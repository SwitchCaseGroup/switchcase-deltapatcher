import pytest
import subprocess
import argparse
import random
import shutil
import json
import sys
import re
import os
import io

from patchtool import PatchTool
from itertools import product


# for generating filenames
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

    def __init__(self):
        super().__init__(['uasset', 'umap'], verbose=False)
        # repeatability
        random.seed(0)
        # configure test directories
        self.out = os.path.abspath('out')
        self.cleanup()
        # initialize state
        self.sequence_number = 0

    def __del__(self):
        # remove test data
        self.cleanup()

    def prepare(self):
        # randomize contents of src and pch
        print("Generating test data...")
        self.generate_random(self.src, self.target_size)
        self.generate_random(self.pch, self.target_size)
        self.generate_random(self.out, self.target_size)
        self.initialize('src', 'dst', 'pch')
        self.permute_dir(self.src, self.dst, self.src_files)

    def generate_random(self, path, size):
        while size:
            file_size = random.randint(
                min(self.min_file_size, size), min(self.max_file_size, size))
            path_elements = random.randint(1, 4)
            filename = path
            for _ in range(path_elements):
                filename = os.path.join(filename, self.generate_id())
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, 'wb') as outfile:
                outfile.write(os.urandom(file_size))
            size -= file_size

    def generate_id(self):
        id = self.sequence_number
        self.sequence_number += 1
        return str(id)

    def permute_dir(self, src, dst, files):
        # randomly copy/modify/remove
        for filename in files:
            choice = random.randint(0, 99)
            src_filename = os.path.join(src, filename)
            dst_filename = os.path.join(dst, filename)
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
                    self.split_file(filename)
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

    def execute(self, command, verbose=False, silent=False):
        self.trace(command)
        subprocess.check_call(command + ["--verbose"] if verbose else command, universal_newlines=True,
                              stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL if silent else None)

    def cleanup(self):
        shutil.rmtree(os.path.abspath('src'), ignore_errors=True)
        shutil.rmtree(os.path.abspath('dst'), ignore_errors=True)
        shutil.rmtree(os.path.abspath('out'), ignore_errors=True)
        shutil.rmtree(os.path.abspath('pch'), ignore_errors=True)
        shutil.rmtree(os.path.abspath('inv'), ignore_errors=True)
        shutil.rmtree(os.path.abspath('dsv'), ignore_errors=True)
        for (inplace, resilience) in [(False, False), (False, True), (True, False), (True, True)]:
            shutil.rmtree(os.path.abspath(self.get_out_dir(inplace, resilience)), ignore_errors=True)


@pytest.fixture(scope="module")
def patch_tool_tests():
    return PatchToolTests()


def test_prepare(patch_tool_tests):
    patch_tool_tests.initialize('src', 'dst', 'pch')
    patch_tool_tests.prepare()


def test_generate(patch_tool_tests):
    patch_tool_tests.initialize('src', 'dst', 'pch')
    patch_tool_tests.generate()


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_apply(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    if inplace or resilience:
        patch_tool_tests.execute(['cp', '-R', f'src', out])
    src = out if inplace else 'src'
    dst = out
    pch = 'pch'
    if resilience:
        missing = []
        patch_tool_tests.initialize(src, dst, pch)
        for filename in patch_tool_tests.src_files:
            src_filename = os.path.join(patch_tool_tests.src, filename)
            os.rename(src_filename, f'{src_filename}.missing')
            missing.append(src_filename)
        while len(missing):
            try:
                patch_tool_tests.initialize(src, dst, pch)
                patch_tool_tests.apply()
            except:
                size = len(missing) / 2
                while len(missing) >= size:
                    src_filename = missing.pop()
                    os.rename(f'{src_filename}.missing', src_filename)

    patch_tool_tests.initialize(src, dst, pch)
    patch_tool_tests.apply()


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_validate(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    patch_tool_tests.initialize('dst', out, 'pch')
    patch_tool_tests.validate()


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_validate_manifest(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    patch_tool_tests.initialize(None, out, 'pch')
    patch_tool_tests.validate()


@pytest.mark.parametrize("inplace, resilience", [(False, False), (False, True), (True, False), (True, True)])
def test_diff(patch_tool_tests, inplace, resilience):
    out = patch_tool_tests.get_out_dir(inplace, resilience)
    patch_tool_tests.execute(['diff', '-q', '-r', 'dst', out])


def test_compare(patch_tool_tests):
    patch_tool_tests.execute(['tar', 'cf', f'src.tar', 'src'])
    patch_tool_tests.execute(['tar', 'cf', f'dst.tar', 'dst'])
    patch_tool_tests.execute(['xdelta3', '-e', '-9', '-f', '-s', f'src.tar', f'dst.tar', 'tar-patch.xdelta3'])
    patch_tool_tests.execute(['du', 'src', 'dst', 'pch',
                              'tar-patch.xdelta3', '-s'])
    patch_tool_tests.execute(['rm', f'src.tar', f'dst.tar', 'tar-patch.xdelta3'])
    print(str(int(patch_tool_tests.changed_bytes / 1024)).ljust(8) + "modified/added")


@pytest.mark.parametrize("dir, type", product(["dsv", "inv", "manifest"], ["add", "modify", "remove"]))
def test_validate_failure(patch_tool_tests, dir, type):
    patch_tool_tests.execute(['rm', '-rf', 'dsv'])
    patch_tool_tests.execute(['rm', '-rf', 'inv'])
    patch_tool_tests.execute(['cp', '-R', f'dst', 'dsv'])
    patch_tool_tests.execute(['cp', '-R', f'dst', 'inv'])
    patch_tool_tests.initialize('dsv', 'inv', 'pch')
    with pytest.raises(ValueError):
        if dir == "manifest":
            with open(os.path.join('pch', 'manifest.json'), 'r') as inpfile:
                local_manifest = json.load(inpfile)
            if type == "add":
                local_manifest["dst"]["test/bogus"] = {
                    "sha1": "bogus"
                }
            elif type == "modify":
                local_manifest["dst"][patch_tool_tests.dst_files[0]]["sha1"] = "bogus"
            elif type == "remove":
                del local_manifest["dst"][patch_tool_tests.dst_files[0]]
            with open(os.path.join('pch', 'manifest.json'), 'w') as outfile:
                json.dump(local_manifest, outfile, indent=4)
        else:
            if type == "add":
                with open(os.path.join(dir, 'added'), "wt") as outfile:
                    print("testing", file=outfile)
            elif type == "modify":
                with open(os.path.join(dir, patch_tool_tests.dst_files[0]), "wt") as outfile:
                    print("modified", file=outfile)
            elif type == "remove":
                os.remove(os.path.join(dir, patch_tool_tests.dst_files[0]))
        patch_tool_tests.initialize('dsv', 'inv', 'pch')
        patch_tool_tests.validate()
