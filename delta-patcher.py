#
# file: delta-patcher.py
# desc: generates and applies binary delta patches
# 

import argparse
import hashlib
import json
import sys
import re
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
        arg_parser.add_argument('-x', '--split', dest='split', default=[ 'uasset' ], nargs="*", help='zero or more split file extensions')
        self.args = arg_parser.parse_args()
        # generate absolute paths
        self.src = os.path.abspath(self.args.src)
        self.dst = os.path.abspath(self.args.dst)
        self.out = os.path.abspath(self.args.out)
        # add default regex pattern and prepare any additional patterns from CLI arguments
        self.pat = [ "(.*):{0}" ]
        for split in self.args.split:
            self.pat += [ "(.*)/(.*)\." + split + ":{0}/{1}\.(.*)" ]
        # collect src/dst filename
        print("Finding files...")
        self.src_files = [ filename for filename in self.find_files(self.src) ]
        self.dst_files = [ filename for filename in self.find_files(self.dst) ]
        getattr(globals()['DeltaPatcher'], self.args.command)(self)

    def generate(self):
        os.makedirs(self.out, exist_ok=True)

        # Add manifest entry for each destination file and hash its file contents
        print(f'Processing {self.dst}...')
        self.manifest = { 
            "dst": {
                os.path.relpath(filename, self.dst): { 
                    'sha256': self.generate_hash(filename),
                    'src': None
                } 
                for filename in self.dst_files
            },
            "src": { }
        }

        # Iterate through our regex patterns, matching against all source files
        print(f'Processing {self.src}...')
        for pattern in self.pat:
            split = pattern.split(':')
            src_regex = re.compile(split[0])
            for src_filename in self.src_files:
                src_match = src_regex.match(src_filename)
                if not src_match:
                    continue;

                rel_src = os.path.relpath(src_match[0], self.src)
                print(f'  {split[0]} => {rel_src}')

                # If the regex pattern matched, find all destination matches
                regex_str = split[1]
                for group in range(src_regex.groups):
                    regex_str = regex_str.replace('{' + str(group) + '}', src_match[group+1])
                dst_regex = re.compile(regex_str)
                for dst_filename in self.dst_files:
                    dst_match = dst_regex.match(dst_filename)
                    if not dst_match:
                        continue

                    rel_dst = os.path.relpath(dst_match[0], self.dst)
                    # Skip if we already have an earlier match
                    if self.manifest['dst'][rel_dst]['src']:
                        continue

                    self.manifest['dst'][rel_dst]['src'] = rel_src
                    print(f'    {rel_src} => {rel_dst}')

                    if rel_src not in self.manifest['src']:
                        self.manifest['src'][rel_src] = {
                            'sha256': self.generate_hash(src_match[0])
                        }

        # convert absolute paths to relative
        print(f'Writing manifest...')
        with open(os.path.join(self.out, 'manifest.json'), 'w') as outfile:
            json.dump(self.manifest, outfile, indent=4)

    def find_files(self, path):
        if not os.path.isfile(path):
            for current in os.listdir(path):
                yield from self.find_files(os.path.join(path, current))
        else:
            yield path

    def generate_hash(self, path):
        hash = hashlib.sha256()
        print(f'  {path}: ', end='')
        sys.stdout.flush()
        with open(path, 'rb') as source:
            block = source.read(io.DEFAULT_BUFFER_SIZE)
            while len(block) != 0:
                hash.update(block)
                block = source.read(io.DEFAULT_BUFFER_SIZE)
        print(hash.hexdigest())
        return hash.hexdigest()

    def apply(self):
        print("apply");


if __name__ == "__main__":
    delta_patcher = DeltaPatcher()
