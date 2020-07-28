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
    commands = [ "generate", "apply", "validate" ]

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
        # ensure paths exist
        os.makedirs(self.src, exist_ok=True)
        os.makedirs(self.dst, exist_ok=True)
        os.makedirs(self.pch, exist_ok=True)
        # add default regex pattern and prepare any additional patterns from CLI arguments
        self.pat = [ "(.*):{0}" ]
        for split in self.args.split:
            self.pat += [ "(.*)/(.*)\." + split + ":{0}/{1}\.(.*)" ]
        # collect src/dst filename
        print("Finding files...")
        self.src_files = [ os.path.relpath(filename, self.src) for filename in self.find_files(self.src) ]
        self.dst_files = [ os.path.relpath(filename, self.dst) for filename in self.find_files(self.dst) ]
        self.pch_files = [ os.path.relpath(filename, self.dst) for filename in self.find_files(self.dst) ]
        getattr(globals()['DeltaPatcher'], self.args.command)(self)

    def generate(self):
        # add manifest entry for each destination file and hash its file contents
        print(f'Processing {self.dst}...')
        self.manifest = { 
            "src": { },
            "dst": {
                filename: { 
                    'sha256': self.generate_hash(os.path.join(self.dst, filename)),
                    'src': None
                } 
                for filename in self.dst_files
            },
            "pch": { }
        }

        # iterate through our regex patterns, matching against all source files
        print(f'Processing {self.src}...')
        for pattern in self.pat:
            split = pattern.split(':')
            src_regex = re.compile(split[0])
            for src_filename in self.src_files:
                src_match = src_regex.match(src_filename)
                if not src_match:
                    continue;
                self.verbose(f'Matched source "{split[0]}" => {src_match[0]}')

                # if the regex pattern matched, find all destination matches
                regex_str = split[1]
                for group in range(src_regex.groups):
                    regex_str = regex_str.replace('{' + str(group) + '}', src_match[group+1])
                dst_regex = re.compile(regex_str)
                for dst_filename in self.dst_files:
                    dst_match = dst_regex.match(dst_filename)
                    if not dst_match:
                        continue
                    self.verbose(f'Matched destination {split[1]} => {dst_match[0]}')

                    # skip if we already have an earlier match
                    if self.manifest['dst'][dst_match[0]]['src']:
                        self.verbose(f'Skipping duplicate match {split[1]} => {dst_match[0]}')
                        continue

                    self.manifest['dst'][dst_match[0]]['src'] = src_match[0]

                    if src_match[0] not in self.manifest['src']:
                        self.manifest['src'][src_match[0]] = {
                            'sha256': self.generate_hash(os.path.join(self.src, src_match[0]))
                        }

        # clean the patch directory
        print(f'Cleaning {self.pch}...')
        for filename in self.find_files(self.pch):
            os.remove(filename)

        # iterate through destination files, creating patch files
        print(f'Generating {self.pch}...')
        for dst_filename in self.manifest['dst']:
            dst = self.manifest['dst'].get(dst_filename)
            src = self.manifest['src'].get(dst_filename)
            # handle added files by copying over the destination file directly
            if not dst['src']:
                print(f'Copying {dst_filename}...')
                pch_filename = os.path.join(self.pch, dst_filename)
                shutil.copyfile(os.path.join(self.dst, dst_filename), pch_filename)
                self.manifest['pch'][os.path.relpath(pch_filename, self.pch)] = {
                    'sha256': self.generate_hash(pch_filename)
                }
            # handle modified files by creating xdelta3 file
            elif src and src['sha256'] != dst['sha256']:
                print(f'Creating delta for {dst_filename}...')
                pch_filename = os.path.join(self.pch, dst_filename + ".xdelta3")
                os.makedirs(os.path.dirname(pch_filename), exist_ok=True)
                command = [
                    "xdelta3", "-e", "-9", "-f",
                    "-s", os.path.join(self.src, dst_filename), os.path.join(self.dst, dst_filename), pch_filename
                ]
                self.verbose(' '.join(command))
                subprocess.check_output(command, universal_newlines=True)
                dst['xdelta3'] = os.path.relpath(pch_filename, self.pch)
                self.manifest['pch'][dst['xdelta3']] = {
                    'sha256': self.generate_hash(pch_filename)
                }

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
        self.verbose(f'Hasing {path}...')
        hash = hashlib.sha256()
        try:
            with open(path, 'rb') as source:
                block = source.read(io.DEFAULT_BUFFER_SIZE)
                while len(block) != 0:
                    hash.update(block)
                    block = source.read(io.DEFAULT_BUFFER_SIZE)
        except:
            pass
        return hash.hexdigest()

    def apply(self):
        # read manifest file
        print(f'Reading manifest...')
        with open(os.path.join(self.pch, 'manifest.json'), 'r') as inpfile:
            self.manifest = json.load(inpfile)

        # look for files which needed to be added or patched
        print(f'Adding/patching files...')
        for dst_filename in self.manifest['dst']:
            dst_hash = self.generate_hash(os.path.join(self.dst, dst_filename))
            pch_hash = self.generate_hash(os.path.join(self.pch, dst_filename))
            # check if destination already matches
            if dst_hash == self.manifest['dst'][dst_filename]['sha256']:
                print(f'skipping already matching {dst_filename}')
                continue;
            elif dst_filename in self.manifest['src'] and dst_hash == self.manifest['src'][dst_filename]['sha256']:
                # look for source file matching the expected hash
                if self.generate_hash(os.path.join(self.src, dst_filename)) == self.manifest['src'][dst_filename]['sha256']:
                    # look for xdelta3 filename
                    if 'xdelta3' in self.manifest['dst'][dst_filename]:
                        print(f'patching {dst_filename}...')
                        pch_filename = os.path.join(self.pch, self.manifest['dst'][dst_filename]['xdelta3'])
                        out_filename = os.path.join(self.dst, dst_filename)
                        # apply xdelta3 patch
                        os.makedirs(os.path.dirname(out_filename), exist_ok=True)
                        command = [
                            "xdelta3", "-d", "-f",
                            "-s", os.path.join(self.src, dst_filename), pch_filename, os.path.join(self.dst, dst_filename)
                        ]
                        self.verbose(' '.join(command))
                        subprocess.check_output(command, universal_newlines=True)
                else:
                    self.error(f'Missing {dst_filename} 1')
            elif dst_filename in self.manifest['pch'] and pch_hash == self.manifest['pch'][dst_filename]['sha256']:
                print(f'copying {dst_filename}')
                shutil.copyfile(os.path.join(self.pch, dst_filename), os.path.join(self.dst, dst_filename))
            else:
                self.error(f'Missing {dst_filename} 2')

        # remove any files not in the manifest
        for filename in self.dst_files:
            if filename not in self.manifest['dst']:
                print(f'Removing {filename}...')
                os.remove(os.path.join(self.dst, filename))

    def validate(self):
        print(f'Generating hashes...')
        self.manifest = { 
            "src": {
                filename: { 'sha256': self.generate_hash(os.path.join(self.src, filename)) } 
                for filename in self.src_files
            },
            "dst": {
                filename: { 'sha256': self.generate_hash(os.path.join(self.dst, filename)) } 
                for filename in self.dst_files
            },
            "pch": { 
                filename: { 'sha256': self.generate_hash(os.path.join(self.pch, filename)) } 
                for filename in self.pch_files
            }
        }

        # validate src vs dst directly
        for src_filename in self.manifest['src']:
            if src_filename not in self.manifest['dst']:
                self.error(f'{src_filename}: missing from {self.dst}')
            elif self.manifest['src'][src_filename]['sha256'] != self.manifest['dst'][src_filename]['sha256']:
                print(os.path.join(self.src, src_filename), self.manifest['src'][src_filename]['sha256'])
                print(os.path.join(self.dst, src_filename), self.manifest['dst'][src_filename]['sha256'])
                self.error(f'{src_filename}: sha256 mismatch!')
            print(f'{src_filename}: OK')

    def verbose(self, str):
        if self.args.verbose:
            print(str)

    def error(self, str):
        print(str)
        exit(1)

if __name__ == "__main__":
    delta_patcher = DeltaPatcher()
