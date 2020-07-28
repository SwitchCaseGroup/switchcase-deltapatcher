#
# file: delta-patcher.py
# desc: generates and applies binary delta patches
# 

import argparse
import hashlib
import json
import sys
import os
import io

#
# DeltaPatcher
#
# Generates and applies binary delta patches
#

class DeltaPatcher:
    # currently supported CLI commands
    commands = [ "generate", "apply" ]

    def __init__(self):
        # parse command-line arguments and execute the command
        arg_parser = argparse.ArgumentParser(description='Generate and apply binary delta patches', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        arg_parser.add_argument('command', nargs='?', choices=self.commands, default="generate", help='command')
        arg_parser.add_argument('-s', '--src', dest='src', required=True, help='source directory')
        arg_parser.add_argument('-d', '--dst', dest='dst', required=True, help='destination directory')
        arg_parser.add_argument('-o', '--out', dest='out', required=True, help='patch directory')
        arg_parser.add_argument('-p', '--pat', dest='pattern', nargs="*", help='zero or more merge patterns')
        self.args = arg_parser.parse_args()
        self.src = os.path.abspath(self.args.src)
        self.dst = os.path.abspath(self.args.dst)
        self.out = os.path.abspath(self.args.out)
        getattr(globals()['DeltaPatcher'], self.args.command)(self)

    def generate(self):
        os.makedirs(self.out, exist_ok=True)

        print("Processing {self.src}...")
        self.manifest = { 
            entry: { 
                'md5': self.generate_hash(entry),
                'dst': []
            } 
            for entry in self.find_files(self.src) 
        }

        print("Writing manifest...")
        with open(os.path.join(self.out, 'manifest.json'), 'w') as outfile:
            json.dump(self.manifest, outfile, indent=4)

    def find_files(self, path):
        if not os.path.isfile(path):
            for current in os.listdir(path):
                yield from self.find_files(os.path.join(path, current))
        else:
            yield path

    def generate_hash(self, path):
        sha1sum = hashlib.sha1()
        print(f'  {path}: ', end='')
        sys.stdout.flush()
        with open(path, 'rb') as source:
            block = source.read(io.DEFAULT_BUFFER_SIZE)
            while len(block) != 0:
                sha1sum.update(block)
                block = source.read(io.DEFAULT_BUFFER_SIZE)
        print(sha1sum.hexdigest())
        return sha1sum.hexdigest()

    def apply(self):
        print("apply");


if __name__ == "__main__":
    delta_patcher = DeltaPatcher()
