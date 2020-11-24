import pytest
import subprocess
import tempfile
import argparse
import random
import signal
import shutil
import json
import stat
import sys
import re
import os
import io

from patchtool import PatchTool
from itertools import product


class PatchToolTests(PatchTool):
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
        super().__init__(['uasset', 'umap'], zip, stop_on_error=True, base=None, validation_dirs='sdp', verbose=False)
        # repeatability
        random.seed(0)
        # work within temp directory
        os.chdir(tempfile.gettempdir())
        # configure test directories
        self.out = os.path.abspath('out')
        self.cleanup()
        # initialize state
        self.sequence_number = 0

    def __del__(self):
        # remove test data
        self.cleanup()
        super().__del__()

    def prepare(self):
        # randomize contents of src and pch
        print("Generating test data...")
        self.generate_random(self.src, self.target_size)
        self.generate_random(self.pch, self.target_size)
        self.generate_random(self.out, self.target_size)
        self.initialize('src', 'dst', 'pch')
        self.permute_dir(self.src, self.dst, self.iterate_files('src'))

    def generate_random(self, path, size):
        while size:
            file_size = random.randint(
                min(self.min_file_size, size), min(self.max_file_size, size))
            path_elements = random.randint(1, 4)
            filename = path
            os.makedirs(filename, exist_ok=True)
            for _ in range(path_elements - 1):
                filename = os.path.join(filename, self.generate_id())
                os.makedirs(filename, exist_ok=True)
                self.generate_permissions(filename)
            filename = os.path.join(filename, self.generate_id())
            with open(filename, 'wb') as outfile:
                outfile.write(os.urandom(file_size))
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
        with open(filename, 'rb') as inpfile:
            while size != 0:
                # read the next chunk of data
                chunk_size = random.randint(
                    min(self.min_chunk_size, size), min(self.max_chunk_size, size))
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
        with open(filename, 'wb') as outfile:
            for block in blocks:
                outfile.write(block)

    def split_file(self, filename):
        # pull data chunks out of destination file into separate files
        src_filename = os.path.join(self.src, filename)
        dst_filename = os.path.join(self.dst, filename)
        parts = [f'{dst_filename}.uasset', f'{dst_filename}.uexp', f'{dst_filename}.ubulk']
        # rename source and destination so they are detected by patcher as split files
        os.rename(src_filename, f'{src_filename}.uasset')
        os.rename(dst_filename, f'{dst_filename}.uasset')
        # read the raw data for this file
        size = os.path.getsize(parts[0])
        if size < len(parts):
            return
        blocks = []
        with open(parts[0], 'rb') as inpfile:
            chunk_size = int(size / len(parts))
            for _ in parts:
                block = inpfile.read(chunk_size)
                blocks.append(block)
        # write file parts
        for (i, filename) in enumerate(parts):
            with open(filename, 'wb') as outfile:
                outfile.write(blocks[i])

    def get_out_dir(self, inplace, resilience):
        return f'out{"_inplace" if inplace else ""}{"_resilience" if resilience else ""}'

    def copytree(self, src, dst):
        try:
            shutil.copytree(src, dst)
        except:
            pass

    def cleanup(self):
        shutil.rmtree(os.path.abspath('src'), ignore_errors=True)
        shutil.rmtree(os.path.abspath('dst'), ignore_errors=True)
        shutil.rmtree(os.path.abspath('out'), ignore_errors=True)
        shutil.rmtree(os.path.abspath('pch'), ignore_errors=True)
        shutil.rmtree(os.path.abspath('src-fail'), ignore_errors=True)
        shutil.rmtree(os.path.abspath('dst-fail'), ignore_errors=True)
        shutil.rmtree(os.path.abspath('pch-fail'), ignore_errors=True)
        shutil.rmtree(os.path.abspath('src-http'), ignore_errors=True)
        shutil.rmtree(os.path.abspath('dst-http'), ignore_errors=True)
        shutil.rmtree(os.path.abspath('pch-http'), ignore_errors=True)
        for (inplace, resilience) in [(False, False), (False, True), (True, False), (True, True)]:
            shutil.rmtree(os.path.abspath(self.get_out_dir(inplace, resilience)), ignore_errors=True)


@pytest.fixture(scope="module", params=["none", "bz2", "gzip"])
def patch_tool_tests(request):
    return PatchToolTests(request.param)


def test_prepare(patch_tool_tests):
    patch_tool_tests.initialize('src', 'dst', 'pch')
    patch_tool_tests.prepare()


def test_generate(patch_tool_tests):
    patch_tool_tests.initialize('src', 'dst', 'pch')
    patch_tool_tests.generate()


def test_analyze(patch_tool_tests):
    patch_tool_tests.initialize('src', 'dst', 'pch')
    patch_tool_tests.analyze()


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_apply(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    if inplace or resilience:
        patch_tool_tests.copytree('src', out)
    src = out if inplace else 'src'
    dst = out
    pch = 'pch'
    if resilience:
        missing = []
        patch_tool_tests.initialize(src, dst, pch)
        for src_entry in patch_tool_tests.iterate_files('src'):
            os.rename(src_entry.path, f'{src_entry.path}.missing')
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
                os.rename(f'{src_filename}.missing', src_filename)

    patch_tool_tests.initialize(src, dst, pch)
    patch_tool_tests.apply()


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_validate(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    patch_tool_tests.initialize('src', out, 'pch')
    patch_tool_tests.validate()


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_validate_dst_only(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    patch_tool_tests.initialize(None, out, 'pch')
    patch_tool_tests.validate()


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_validate_src_only(patch_tool_tests, inplace, resilience):
    patch_tool_tests.initialize('src', None, 'pch')
    patch_tool_tests.validate()


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_validate_patch_sizes(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    patch_tool_tests.initialize('src', out, 'pch')
    with open(os.path.join('pch', 'manifest.json'), 'r') as inpfile:
        local_manifest = json.load(inpfile)
    for (_, src_entry) in patch_tool_tests.iterate_manifest('src'):
        for _, pch_filename in src_entry.get('xdelta3', {}).items():
            if local_manifest['pch'][pch_filename]['size'] > src_entry['size']:
                raise ValueError("Patch size greater than source file size")


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_diff(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    command = ['diff', '-q', '-r', 'dst', out]
    subprocess.check_call(command, universal_newlines=True, stderr=subprocess.DEVNULL, stdout=None)


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_rsync(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    command = ['rsync', '-avzpni', '--del', 'dst/', out]
    output = subprocess.check_output(command, universal_newlines=True)
    if len(output.splitlines()) > 5:
        raise ValueError(output)


def failure_tests(patch_tool_tests, src, dst, pch, dir, type):
    shutil.rmtree(src, ignore_errors=True)
    shutil.rmtree(dst, ignore_errors=True)
    shutil.rmtree(pch, ignore_errors=True)
    patch_tool_tests.copytree('dst', src)
    patch_tool_tests.copytree('dst', dst)
    patch_tool_tests.initialize(src, dst, pch)
    patch_tool_tests.generate()
    random_file = random.choice(list(patch_tool_tests.iterate_files('dst'))).name
    if dir == "manifest":
        with open(os.path.join(pch, 'manifest.json'), 'r') as inpfile:
            local_manifest = json.load(inpfile)
        if type == "add":
            local_manifest["dst"]["test/bogus"] = {"sha1": "bad"}
        elif type == "modify":
            local_manifest["dst"][random_file]["sha1"] = "bad"
        elif type == "remove":
            del local_manifest["dst"][random_file]
        elif type == "permissions":
            current = local_manifest["dst"][random_file]["mode"]
            if current & stat.S_IRWXO:
                local_manifest["dst"][random_file]["mode"] = stat.S_IRWXU | stat.S_IRWXG
            else:
                local_manifest["dst"][random_file]["mode"] = stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO
        with open(os.path.join(pch, 'manifest.json'), 'w') as outfile:
            json.dump(local_manifest, outfile, indent=4)
    else:
        if type == "add":
            with open(os.path.join(dir, 'added'), "wt") as outfile:
                print("testing", file=outfile)
        elif type == "modify":
            with open(os.path.join(dir, random_file), "wt") as outfile:
                print("modified", file=outfile)
        elif type == "remove":
            os.remove(os.path.join(dir, random_file))
        elif type == "permissions":
            full_path = os.path.join(dir, random_file)
            current = stat.S_IMODE(os.stat(full_path).st_mode)
            if current & stat.S_IRWXO:
                os.chmod(full_path, stat.S_IRWXU | stat.S_IRWXG)
            else:
                os.chmod(full_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
    patch_tool_tests.initialize(src, dst, pch)


@pytest.mark.parametrize("dir, type", product(["manifest", "src-fail", "dst-fail"],
                                              ["add", "modify", "remove", "permissions"]))
def test_validate_failure(patch_tool_tests, dir, type):
    with pytest.raises(ValueError):
        failure_tests(patch_tool_tests, 'src-fail', 'dst-fail', 'pch-fail', dir, type)
        patch_tool_tests.validate()
    # exception could leave zombie workers, re-init to flush the pool
    patch_tool_tests.initialize('src-fail', 'dst-fail', 'pch-fail')


@pytest.mark.parametrize("dir, type", product(["src-http", "dst-http"], ["modify", "remove", "permissions"]))
def test_http_fallback(patch_tool_tests, dir, type):
    # start HTTP server for destination files
    server = subprocess.Popen([sys.executable, '-m', 'http.server', '8080', '--bind', 'localhost'], cwd='dst')
    # run tests with HTTP fallback
    patch_tool_tests.base = "http://localhost:8080/"
    failure_tests(patch_tool_tests, 'src-http', 'dst-http', 'pch-http', dir, type)
    # exception could leave zombie workers, re-init to flush the pool
    patch_tool_tests.initialize('src-http', 'dst-http', 'pch-http')
    patch_tool_tests.apply()
    patch_tool_tests.initialize('dst', 'dst-http', 'pch')
    patch_tool_tests.validation_dirs = 'd'
    patch_tool_tests.validate()
    # stop http server
    server.send_signal(signal.SIGTERM)
