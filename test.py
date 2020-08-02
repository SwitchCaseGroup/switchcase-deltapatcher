#
# file: test.py
# desc: Tests for binary delta patching tool
#

from patchtool import PatchTool

import subprocess
import argparse
import random
import shutil
import json
import sys
import re
import os
import io


class PatchToolTest(PatchTool):
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

    def __init__(self, verbose):
        super().__init__('src', 'dst', 'pch', [
            'uasset', 'umap'], verbose=verbose)
        # repeatability
        random.seed(0)
        # configure test directories
        self.out = os.path.abspath('out')
        self.cleanup()
        # initialize state
        self.sequence_number = 0
        # randomize contents of src and pch
        print("Generating test data...")
        self.generate_random(self.src, self.target_size)
        self.generate_random(self.pch, self.target_size)
        self.generate_random(self.out, self.target_size)
        self.initialize()
        self.permute_dir(self.src, self.dst, self.src_files)
        # perform generate/apply/validate operations
        try:
            #
            # Patch generate, apply and validate on separate src/dst/out directories
            #

            self.execute([sys.executable, "patchtool.py", 'generate', '-s',
                          self.src, '-d', self.dst, '-p', self.pch], self.verbose)
            self.execute([sys.executable, "patchtool.py", 'apply', '-s',
                          self.src, '-d', self.out, '-p', self.pch], self.verbose)
            self.execute([sys.executable, "patchtool.py", 'validate', '-s',
                          self.dst, '-d', self.out, '-p', self.pch], self.verbose)
            self.execute(['diff', '-q', '-r', self.dst, self.out])
            self.execute(['tar', 'cf', f'{self.src}.tar', os.path.relpath(self.src)])
            self.execute(['tar', 'cf', f'{self.dst}.tar', os.path.relpath(self.dst)])
            self.execute(['xdelta3', '-e', '-9', '-f', '-s', f'{self.src}.tar', f'{self.dst}.tar', 'tar-patch.xdelta3'])
            self.execute(['du', self.src, self.dst, self.pch,
                          'tar-patch.xdelta3', '-s'])
            self.execute(['rm', f'{self.src}.tar', f'{self.dst}.tar', 'tar-patch.xdelta3'])

            print(str(int(self.changed_bytes / 1024)).ljust(8) + "modified/added")

            #
            # Patch apply in-place on src directory
            #

            self.execute([sys.executable, "patchtool.py", 'apply',
                          '-s', self.src, '-d', self.src, '-p', self.pch])
            self.execute([sys.executable, "patchtool.py", 'validate',
                          '-s', self.dst, '-d', self.src, '-p', self.pch])
            self.execute(['diff', '-q', '-r', self.dst, self.src])

            #
            # Simulate patch failure and recovery
            #

            self.initialize()
            shutil.rmtree(self.out, ignore_errors=True)

            missing = []
            for filename in self.src_files:
                src_filename = os.path.join(self.src, filename)
                os.rename(src_filename, f'{src_filename}.missing')
                missing.append(src_filename)

            while len(missing):
                try:
                    self.execute([sys.executable, "patchtool.py", 'apply', '-s',
                                  self.src, '-d', self.out, '-p', self.pch], self.verbose, True)
                except:
                    size = len(missing) / 2
                    while len(missing) >= size:
                        src_filename = missing.pop()
                        os.rename(f'{src_filename}.missing', src_filename)

            self.execute([sys.executable, "patchtool.py", 'validate',
                          '-s', self.dst, '-d', self.src, '-p', self.pch])
            self.execute(['diff', '-q', '-r', self.dst, self.src])
            print("Tests Passed.")

        except Exception as e:
            print("Test Failed:")
            self.error(e)

        # remove test data
        self.cleanup()

    def execute(self, command, verbose=False, silent=False):
        self.trace(command)
        subprocess.check_call(command + ["--verbose"] if verbose else command, universal_newlines=True,
                              stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL if silent else None)

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

    def cleanup(self):
        shutil.rmtree(os.path.abspath(self.src), ignore_errors=True)
        shutil.rmtree(os.path.abspath(self.dst), ignore_errors=True)
        shutil.rmtree(os.path.abspath(self.pch), ignore_errors=True)
        shutil.rmtree(os.path.abspath(self.out), ignore_errors=True)

    def generate_id(self):
        id = self.sequence_number
        self.sequence_number += 1
        return str(id)


if __name__ == "__main__":
    # parse command-line arguments and execute the command
    arg_parser = argparse.ArgumentParser(
        description='Binary delta patching tool.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    arg_parser.add_argument('-v', '--verbose', dest='verbose',
                            action="store_true", help='increase verbosity')
    args = arg_parser.parse_args()
    patch_tool_test = PatchToolTest(args.verbose)
