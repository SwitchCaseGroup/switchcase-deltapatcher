#
# file: delta-patcher.py
# desc: generates and applies binary delta patches
# 

import subprocess, argparse, hashlib, shutil, json, sys, re, os, io

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
        arg_parser.add_argument('-p', '--patch', dest='pch', required=True, help='patch directory')
        arg_parser.add_argument('-x', '--split', dest='split', default=[ 'uasset' ], nargs="*", help='zero or more split file extensions')
        arg_parser.add_argument('-v', '--verbose', dest='verbose', action="store_true", help='increase verbosity')
        self.args = arg_parser.parse_args()
        # generate absolute paths
        self.src = os.path.abspath(self.args.src)
        self.dst = os.path.abspath(self.args.dst)
        self.pch = os.path.abspath(self.args.pch)
        # add default regex pattern and prepare any additional patterns from CLI arguments
        self.pat = [ "(.*):{0}" ]
        for split in self.args.split:
            self.pat += [ "(.*)/(.*)\." + split + ":{0}/{1}\.(.*)" ]
        # collect src/dst filename
        print("Finding files...")
        self.src_files = [ os.path.relpath(filename, self.src) for filename in self.find_files(self.src) ]
        self.dst_files = [ os.path.relpath(filename, self.dst) for filename in self.find_files(self.dst) ]
        getattr(globals()['DeltaPatcher'], self.args.command)(self)

    def generate(self):
        os.makedirs(self.pch, exist_ok=True)

        # Add manifest entry for each destination file and hash its file contents
        print(f'Processing {self.dst}...')
        self.manifest = { 
            "dst": {
                filename: { 
                    'sha256': self.generate_hash(os.path.join(self.dst, filename)),
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

                self.verbose(f'  {split[0]} => {src_match[0]}')

                # If the regex pattern matched, find all destination matches
                regex_str = split[1]
                for group in range(src_regex.groups):
                    regex_str = regex_str.replace('{' + str(group) + '}', src_match[group+1])
                dst_regex = re.compile(regex_str)
                for dst_filename in self.dst_files:
                    dst_match = dst_regex.match(dst_filename)
                    if not dst_match:
                        continue

                    # Skip if we already have an earlier match
                    if self.manifest['dst'][dst_match[0]]['src']:
                        continue

                    self.manifest['dst'][dst_match[0]]['src'] = src_match[0]
                    self.verbose(f'    {src_match[0]} => {dst_match[0]}')

                    if src_match[0] not in self.manifest['src']:
                        self.manifest['src'][src_match[0]] = {
                            'sha256': self.generate_hash(os.path.join(self.src, src_match[0]))
                        }

        # Clean the patch directory
        print(f'Cleaning {self.pch}...')
        for filename in self.find_files(self.pch):
            os.remove(filename)

        # Iterate through destination files, creating patch files
        print(f'Generating {self.pch}...')
        for dst_filename in self.manifest['dst']:
            dst = self.manifest['dst'].get(dst_filename)
            src = self.manifest['src'].get(dst_filename)
            # handle added files by copying over the destination file directly
            if not dst['src']:
                print(f'  Copying {dst_filename}...')
                pch_filename = os.path.join(self.pch, dst_filename)
                dst['delta'] = pch_filename
                shutil.copyfile(os.path.join(self.dst, dst_filename), pch_filename)
            elif src and src['sha256'] != dst['sha256']:
                print(f'  Creating delta for {dst_filename}...')
                pch_filename = os.path.join(self.pch, dst_filename + ".xdelta3")
                os.makedirs(os.path.dirname(pch_filename), exist_ok=True)
                command = [
                    "xdelta3", "-e",
                    "-s", os.path.join(self.src, dst_filename), os.path.join(self.dst, dst_filename), pch_filename
                ]
                subprocess.check_output(command, universal_newlines=True)

        # generate manifest file
        print(f'Writing manifest...')
        with open(os.path.join(self.pch, 'manifest.json'), 'w') as outfile:
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

    def verbose(self, str):
        if self.args.verbose:
            print(str)


if __name__ == "__main__":
    delta_patcher = DeltaPatcher()
