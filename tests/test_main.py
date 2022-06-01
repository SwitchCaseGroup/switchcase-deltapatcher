import multiprocessing
import subprocess
import tempfile
import random
import shutil
import pytest
import base64
import time
import json
import stat
import sys
import os

from RangeHTTPServer import RangeRequestHandler
from http.server import HTTPServer
from pathlib import Path

from deltapatcher import DeltaPatcher, DeltaPatcherSettings
from itertools import product

g_timeout_path = None
g_timeout_count = 0


class AuthHTTPRequestHandler(RangeRequestHandler):
    def __init__(self, *args, **kwargs):
        self._auth = base64.b64encode(f"test:pass".encode()).decode()
        super().__init__(*args, **kwargs)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Test"')
        self.send_header("Content-type", "application/octet-stream")
        self.end_headers()

    def do_GET(self):
        global g_timeout_path
        global g_timeout_count
        if self.headers.get("Authorization") == None:
            self.do_AUTHHEAD()
            self.wfile.write(b"no auth header received")
        elif self.headers.get("Authorization") == ("Basic " + self._auth):
            # enable timeout for the first path fetched
            if g_timeout_path is None:
                g_timeout_path = self.path
            # timeout the first two attempts
            if self.path == g_timeout_path and g_timeout_count > 0:
                # @todo wget makes multiple requests even with --tries 1 and it messes up
                # unit tests if we try to track tries count perfectly, for now disabling
                # this strict test
                # g_timeout_count -= 1
                return
            RangeRequestHandler.do_GET(self)
        else:
            self.do_AUTHHEAD()
            self.wfile.write(self.headers.get("Authorization").encode())
            self.wfile.write(b"not authenticated")


def http_server(dir, timeout=False):
    global g_timeout_path
    global g_timeout_count
    g_timeout_path = None
    g_timeout_count = 2 if timeout else 0
    os.chdir(dir)
    address = ("localhost", 8080)
    server = HTTPServer(address, AuthHTTPRequestHandler)
    server.serve_forever()


class DeltaPatcherTests(DeltaPatcher):
    # test configuration
    target_size = 8 * 1024 * 1024
    min_file_size = 1
    max_file_size = 500 * 1024
    min_chunk_size = 1
    max_chunk_size = max_file_size / 1024
    changed_bytes = 0

    # note that modify and split can both be applied to the same source file
    chance_remove = (0, 10)
    chance_modify = (10, 40)
    chance_split = (20, 60)
    chance_add = (60, 70)

    def __init__(self, zip):
        settings = DeltaPatcherSettings()
        settings.zip = zip
        settings.stop_on_error = True
        settings.verbose = True
        settings.http["base"] = "http://localhost:8080/"
        settings.http["user"] = "test"
        settings.http["pass"] = "pass"
        settings.http["comp"] = zip
        settings.http["timeout"] = "60"
        settings.http["tries"] = "5"
        settings.http["dst"] = "dst"
        super().__init__(settings)
        # repeatability
        random.seed(0)
        # prepare temp directory (fail if we can't wipe it clean)
        self.tmpdir = os.path.join(tempfile.gettempdir(), "deltapatcher-test")
        self.rmtree(self.tmpdir)
        os.makedirs(self.tmpdir)
        # work within temp directory
        os.chdir(self.tmpdir)
        # configure test directories
        self.out = os.path.abspath("out")
        # initialize state
        self.sequence_number = 0
        self.http_server = None
        self.cleanup()
        # prepare directories
        self.initialize("src", "dst", "pch")
        self.prepare()
        self.initialize("src", "dst", "pch")
        self.generate()

    def __del__(self):
        self.cleanup()
        super().__del__()

    def cleanup(self):
        self.rmtree(os.path.abspath("src"))
        self.rmtree(os.path.abspath("dst"))
        self.rmtree(os.path.abspath("out"))
        self.rmtree(os.path.abspath("pch"))
        for (inplace, resilience) in [(False, False), (False, True), (True, False), (True, True)]:
            self.rmtree(os.path.abspath(self.get_out_dir(inplace, resilience)))
        self.stop_http()

    def start_http(self, http_dir, timeout):
        self.http_server = multiprocessing.Process(target=http_server, args=(http_dir, timeout))
        self.http_server.start()
        time.sleep(0.5)

    def stop_http(self):
        if self.http_server:
            self.http_server.terminate()
            self.http_server.join()
            self.http_server = None

    def prepare(self):
        # randomize contents of src and pch
        print("Generating test data...")
        self.generate_random(self.src, self.target_size)
        self.generate_random(self.pch, self.target_size)
        self.generate_random(self.out, self.target_size)
        self.initialize("src", "dst", "pch")
        self.permute_dir(self.src, self.dst, self.iterate_files("src"))

    def generate_random(self, path, size):
        while size:
            file_size = random.randint(min(self.min_file_size, size), min(self.max_file_size, size))
            path_elements = random.randint(1, 4)
            filename = path
            os.makedirs(filename, exist_ok=True)
            for _ in range(path_elements - 1):
                filename = os.path.join(filename, self.generate_id())
                os.makedirs(filename, exist_ok=True)
                self.generate_permissions(filename)
            filename = os.path.join(filename, self.generate_id())
            with open(filename, "wb") as outfile:
                outfile.write(os.urandom(file_size))
                outfile.flush()
                os.fsync(outfile.fileno())
            self.generate_permissions(filename)
            size -= file_size

    def generate_permissions(self, path):
        if random.randint(0, 1) == 1:
            os.chmod(path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        else:
            os.chmod(path, stat.S_IRWXU | stat.S_IRWXG)

    def generate_id(self):
        id = self.sequence_number
        self.sequence_number += 1
        return str(id)

    def permute_dir(self, src, dst, src_files):
        # randomly copy/modify/remove
        for src_entry in src_files:
            choice = random.randint(0, 99)
            src_filename = os.path.join(src, src_entry.name)
            dst_filename = os.path.join(dst, src_entry.name)
            # randomly skip ("remove") files
            if choice < self.chance_remove[0] or choice >= self.chance_remove[1]:
                # copy file to destination
                os.makedirs(os.path.dirname(dst_filename), exist_ok=True)
                shutil.copyfile(src_filename, dst_filename)
                # randomly modify the file
                if choice >= self.chance_modify[0] and choice < self.chance_modify[1]:
                    self.permute_file(dst_filename)
                # randomly split the file
                if choice >= self.chance_split[0] and choice < self.chance_split[1]:
                    self.split_file(src_entry.name)
        # randomly add new files
        new_size = int(self.target_size * (self.chance_add[1] - self.chance_add[0]) / 100)
        self.changed_bytes += new_size
        self.generate_random(self.dst, new_size)

    def permute_file(self, filename):
        size = os.path.getsize(filename)
        blocks = []
        # read file in random block sizes
        with open(filename, "rb") as inpfile:
            while size != 0:
                # read the next chunk of data
                chunk_size = random.randint(min(self.min_chunk_size, size), min(self.max_chunk_size, size))
                block = inpfile.read(chunk_size)
                choice = random.randint(0, 99)
                # randomly skip ("remove") the chunk
                if choice < self.chance_remove[0] or choice >= self.chance_remove[1]:
                    # randomly modify the chunk
                    if choice >= self.chance_modify[0] and choice < self.chance_modify[1]:
                        block = os.urandom(len(block))
                        self.changed_bytes += len(block)
                    # randomly add new chunks
                    if choice >= self.chance_add[0] and choice < self.chance_add[1]:
                        blocks.append(os.urandom(len(block)))
                        self.changed_bytes += len(block)
                    # copy block
                    blocks.append(block)
                size -= chunk_size
        # write the blocks back to the file
        with open(filename, "wb") as outfile:
            for block in blocks:
                outfile.write(block)
            outfile.flush()
            os.fsync(outfile.fileno())

    def split_file(self, filename):
        # pull data chunks out of destination file into separate files
        src_filename = os.path.join(self.src, filename)
        dst_filename = os.path.join(self.dst, filename)
        parts = [f"{dst_filename}.uasset", f"{dst_filename}.uexp", f"{dst_filename}.ubulk"]
        # rename source and destination so they are detected by patcher as split files
        os.rename(src_filename, f"{src_filename}.uasset")
        os.rename(dst_filename, f"{dst_filename}.uasset")
        # read the raw data for this file
        size = os.path.getsize(parts[0])
        if size < len(parts):
            return
        blocks = []
        with open(parts[0], "rb") as inpfile:
            chunk_size = int(size / len(parts))
            for _ in parts:
                block = inpfile.read(chunk_size)
                blocks.append(block)
        # write file parts
        for (i, filename) in enumerate(parts):
            with open(filename, "wb") as outfile:
                outfile.write(blocks[i])
                outfile.flush()
                os.fsync(outfile.fileno())

    def get_out_dir(self, inplace, resilience):
        return f'out{"_inplace" if inplace else ""}{"_resilience" if resilience else ""}'

    def rmtree(self, dir):
        retries = 50
        while retries:
            try:
                if os.path.isdir(dir):
                    shutil.rmtree(dir)
                return
            except:
                print(f"shutil.rmtree: {sys.exc_info()[1]}")
                time.sleep(0.10)
                retries -= 1

    def copytree(self, src, dst):
        retries = 50
        while retries:
            try:
                self.rmtree(dst)
                shutil.copytree(src, dst)
                return
            except:
                print(f"shutil.copytree: {sys.exc_info()[1]}")
                time.sleep(0.10)
                retries -= 1


@pytest.fixture(scope="module", params=["none", "bz2", "gz"])
def patch_tool_tests(request):
    patch_tool_tests = DeltaPatcherTests(request.param)
    yield patch_tool_tests
    del patch_tool_tests


def test_analyze(patch_tool_tests):
    patch_tool_tests.initialize("src", "dst", "pch")
    patch_tool_tests.analyze()


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_apply(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    if inplace or resilience:
        patch_tool_tests.copytree("src", out)
    src = out if inplace else "src"
    dst = out
    pch = "pch"
    if resilience:
        missing = []
        patch_tool_tests.initialize(src, dst, pch)
        for src_entry in patch_tool_tests.iterate_files("src"):
            os.rename(src_entry.path, f"{src_entry.path}.missing")
            missing.append(src_entry.path)
        while len(missing):
            try:
                patch_tool_tests.initialize(src, dst, pch)
                patch_tool_tests.apply()
            except:
                pass
            size = len(missing) / 2
            while len(missing) >= size:
                src_filename = missing.pop()
                os.rename(f"{src_filename}.missing", src_filename)

    patch_tool_tests.initialize(src, dst, pch)
    patch_tool_tests.apply()


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_validate(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    patch_tool_tests.initialize("src", out, "pch")
    patch_tool_tests.validate()


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_validate_dst_only(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    patch_tool_tests.initialize(None, out, "pch")
    patch_tool_tests.validate()


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_validate_src_only(patch_tool_tests, inplace, resilience):
    patch_tool_tests.initialize("src", None, "pch")
    patch_tool_tests.validate()


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_validate_patch_sizes(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    patch_tool_tests.initialize("src", out, "pch")
    with open(os.path.join("pch", "manifest.json"), "r") as inpfile:
        local_manifest = json.load(inpfile)
    for (_, src_entry) in patch_tool_tests.iterate_manifest("src"):
        for _, pch_filename in src_entry.get("xdelta3", {}).items():
            if local_manifest["pch"][pch_filename]["size"] > src_entry["size"]:
                raise ValueError("Patch size greater than source file size")


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_diff(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    command = ["diff", "-q", "-r", "dst", out]
    subprocess.check_call(command, universal_newlines=True, stderr=subprocess.DEVNULL, stdout=None)


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_rsync(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    command = ["rsync", "-avzpni", "--del", "dst/", out]
    output = subprocess.check_output(command, universal_newlines=True)
    if len(output.splitlines()) > 5:
        raise ValueError(output)


def corrupt_files(files, dir, type, pch):
    for filename in [file for file in files if file != "manifest.json"]:
        if dir == "manifest":
            with open(os.path.join(pch, "manifest.json"), "r") as inpfile:
                local_manifest = json.load(inpfile)
            if type == "add":
                local_manifest["dst"][f"{filename}/bogus"] = {"sha1": "bad"}
            elif type == "modify":
                local_manifest["dst"][filename]["sha1"] = "bad"
            elif type == "remove":
                del local_manifest["dst"][filename]
            elif type == "permissions":
                current = local_manifest["dst"][filename]["mode"]
                if current & stat.S_IRWXO:
                    local_manifest["dst"][filename]["mode"] = stat.S_IRWXU | stat.S_IRWXG
                else:
                    local_manifest["dst"][filename]["mode"] = stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO
            with open(os.path.join(pch, "manifest.json"), "w") as outfile:
                json.dump(local_manifest, outfile, indent=4)
        else:
            if type == "add":
                with open(os.path.join(dir, "added"), "wt") as outfile:
                    print(dir, file=outfile)
            elif type == "modify":
                with open(os.path.join(dir, filename), "at") as outfile:
                    print(dir, file=outfile)
            elif type == "remove":
                os.remove(os.path.join(dir, filename))
            elif type == "shrink":
                with open(os.path.join(dir, filename), "rb") as inpfile:
                    data = inpfile.read()
                with open(os.path.join(dir, filename), "wb") as outfile:
                    outfile.write(data[0 : -int(len(data) / 2)])
                    outfile.flush()
                    os.fsync(outfile.fileno())
            elif type == "permissions":
                full_path = os.path.join(dir, filename)
                current = stat.S_IMODE(os.stat(full_path).st_mode)
                if current & stat.S_IRWXO:
                    os.chmod(full_path, stat.S_IRWXU | stat.S_IRWXG)
                else:
                    os.chmod(full_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)


def corrupt_dirs(patch_tool_tests, src, dst, pch, dir, type):
    patch_tool_tests.rmtree(src)
    patch_tool_tests.rmtree(dst)
    patch_tool_tests.rmtree(pch)
    patch_tool_tests.copytree("src", src)
    if dir == dst:  # use empty dst directory when testing corrupted src, otherwise dst files would just be skipped :)
        patch_tool_tests.copytree("dst", dst)
    patch_tool_tests.copytree("pch", pch)
    patch_tool_tests.initialize(src, dst, pch)
    if dir == src:
        corrupt_files([file.name for file in patch_tool_tests.iterate_files("src")], dir, type, pch)
    elif dir == pch:
        corrupt_files([file.name for file in patch_tool_tests.iterate_files("pch")], dir, type, pch)
    else:
        corrupt_files([file.name for file in patch_tool_tests.iterate_files("dst")], dir, type, pch)
    patch_tool_tests.initialize(src, dst, pch)


@pytest.mark.parametrize("dir, type", product(["manifest", "src-fail", "dst-fail"], ["add", "modify", "remove", "permissions"]))
def test_validate_failure(patch_tool_tests, dir, type):
    with pytest.raises(ValueError):
        corrupt_dirs(patch_tool_tests, "src-fail", "dst-fail", "pch-fail", dir, type)
        patch_tool_tests.validate()
    # exception could leave zombie workers, re-init to flush the pool
    patch_tool_tests.initialize("src-fail", "dst-fail", "pch-fail")


@pytest.mark.parametrize(
    "http_tool, corrupt_type, http_type",
    product(
        [None, "wget"],  # download method (internal or wget)
        ["pch-modify-pch", "pch-remove-pch", "src-modify-dst", "src-remove-dst", "pch-modify-dst", "pch-remove-dst"],  # localDir-localCorruptType-httpDir
        ["valid", "corrupt-modify", "corrupt-shrink", "corrupt-remove", "timeout"],  # HTTP file corruption/timeout
    ),
)
def test_http_fallback(patch_tool_tests, http_tool, corrupt_type, http_type):
    # parse corrupt_type into component parameters
    (file_type, corrupt_type, http_dir) = corrupt_type.split("-")
    # wipe the http directory
    patch_tool_tests.rmtree(http_type)

    # configure manifest HTTP settings
    patch_tool_tests.http["dst"] = "dst" if http_dir == "dst" else None
    patch_tool_tests.http["pch"] = "pch" if http_dir == "pch" else None

    # copy dst folder into HTTP dst folder
    http_srv_dir = f"{http_type}/{patch_tool_tests.http[http_dir]}"
    patch_tool_tests.copytree(http_dir, http_srv_dir)

    # configure http_tool:wget
    if http_tool == "wget":
        patch_tool_tests.http["tool"] = "wget $HTTP_URL -q -O $HTTP_FILE --user $HTTP_USER --password $HTTP_PASS --timeout $HTTP_TIMEOUT --tries $HTTP_TRIES"
        patch_tool_tests.http["user"] = "test"
        patch_tool_tests.http["pass"] = "pass"

    # corrupt http files
    if "corrupt" in http_type:
        http_corrupt_type = http_type.split("-")[1]
        corrupt_files([os.path.relpath(file, http_type) for file in Path(http_type).glob("**/*") if file.is_file()], http_type, http_corrupt_type, None)

    # corrupt local files
    corrupt_dirs(patch_tool_tests, "src-http", "dst-http", "pch-http", f"{file_type}-http", corrupt_type)

    # compress http files (only for dst files)
    if patch_tool_tests.zip != "none" and http_dir == "dst":
        zip2cmd = {"bz2": "bzip2", "gz": "gzip"}
        find = subprocess.Popen(
            ["find", os.path.abspath(http_srv_dir), "-not", "-name", f"*.{patch_tool_tests.zip}", "-type", "f", "-print0"], stdout=subprocess.PIPE
        )
        subprocess.check_output(["xargs", "-0", zip2cmd[patch_tool_tests.zip]], stdin=find.stdout)
        find.wait()

    # start HTTP server
    patch_tool_tests.start_http(os.path.abspath(http_type), "timeout" in http_type)

    # perform the actual test
    try:
        # expect error if http fallback is corrupted
        if "corrupt" in http_type:
            with pytest.raises(ValueError):
                patch_tool_tests.apply()
        # expect error if http times out
        elif http_type == "timeout":
            patch_tool_tests.http["timeout"] = "5"
            patch_tool_tests.http["tries"] = "1"
            with pytest.raises(ValueError):
                patch_tool_tests.apply()
        # otherwise, expect success
        else:
            patch_tool_tests.http["timeout"] = "5"
            patch_tool_tests.http["tries"] = "5"
            patch_tool_tests.apply()
            patch_tool_tests.initialize("src", "dst-http", "pch-http")
            patch_tool_tests.validation_dirs = "d"
            patch_tool_tests.validate()
    finally:
        # exception could leave zombie workers, re-init to flush the pool
        patch_tool_tests.initialize("src-http", "dst-http", "pch-http")
        patch_tool_tests.stop_http()
