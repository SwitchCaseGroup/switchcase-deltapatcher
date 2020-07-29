#
# file: delta-patcher.py
# desc: Binary delta patching tool
# 

import subprocess, argparse, hashlib, shutil, json, sys, re, os, io

class DeltaPatcher:
    # currently supported CLI commands
    commands = [ "generate", "apply", "validate" ]

    def __init__(self):
        # parse command-line arguments and execute the command
        arg_parser = argparse.ArgumentParser(description='Binary delta patching tool.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        arg_parser.add_argument('command', nargs='?', choices=self.commands, default="generate", help='command')
        arg_parser.add_argument('-s', '--src', dest='src', required=True, help='source directory')
        arg_parser.add_argument('-d', '--dst', dest='dst', required=True, help='destination directory')
        arg_parser.add_argument('-p', '--patch', dest='pch', required=True, help='patch directory')
        arg_parser.add_argument('-x', '--split', dest='split', default=[ 'uasset' ], nargs="*", help='zero or more split file extensions')
        arg_parser.add_argument('-v', '--verbose', dest='verbose', action="store_true", help='increase verbosity')
        self.args = arg_parser.parse_args()
        self.initialize()
        getattr(globals()['DeltaPatcher'], self.args.command)(self)

    def initialize(self):
        # initialize directories
        print(f'Recursively gathering filenames...')
        for dir in [ 'src', 'dst', 'pch' ]:
            # convert dirs to absolute paths
            setattr(self, dir, os.path.abspath(getattr(self.args, dir)))
            # ensure directories exist
            os.makedirs(getattr(self, dir), exist_ok=True)
            # find all files in each directory
            setattr(self, f'{dir}_files', [ os.path.relpath(filename, getattr(self, dir)) for filename in self.find_files(getattr(self, dir)) ])

        # add default regex pattern and prepare any additional patterns from CLI arguments
        self.pat = [ "(.*):{0}" ]
        for split in self.args.split:
            self.pat += [ "(.*)\." + split + ":{0}\.(.*)" ]

        # initialize blank manifest
        self.manifest = { "src": { }, "dst": { }, "pch": { } }

    def generate(self):
        # cleanup the patch directory
        print(f'Cleaning {self.pch}...')
        for filename in self.find_files(self.pch):
            os.remove(filename)

        # add manifest entry for each destination file and hash its file contents
        print(f'Generating sha256 hashes for destination files...')
        self.generate_hashes(["src", "dst"])

        # search for modified files and generate xdelta3 patches for them
        print(f'Creating deltas for modified files...')
        for (src_regex, dst_regex) in [ pattern.split(':') for pattern in self.pat ]:
            compiled = re.compile(src_regex)
            for src_match in filter(None, [ compiled.match(src_filename) for src_filename in self.src_files]):
                # if the regex pattern matched, find all destination matches
                print(f'Matched source "{src_regex}" => {src_match[0]}')
                # replace destination pattern {N} variables with results from source regex
                dst_regex_new = dst_regex
                for group in range(compiled.groups):
                    dst_regex_new = dst_regex_new.replace('{' + str(group) + '}', src_match[group+1])
                # handle destination file regex matches
                self.match_dst(src_match[0], dst_regex_new);

        # handle added files by copying over the destination file directly
        print(f'Copying added files...')
        for dst_filename in [dst_filename for dst_filename in self.manifest['dst'] if 'src' not in self.manifest['dst'][dst_filename]]:
            print(f'Copying {dst_filename}...')
            pch_filename = os.path.join(self.pch, dst_filename)
            self.copyfile(os.path.join(self.dst, dst_filename), pch_filename)
            self.manifest['pch'][os.path.relpath(pch_filename, self.pch)] = {
                'sha256': self.generate_hash(pch_filename)
            }

        # write the manifest file
        print(f'Writing manifest...')
        with open(os.path.join(self.pch, 'manifest.json'), 'w') as outfile:
            json.dump(self.manifest, outfile, indent=4)

    def match_dst(self, src_filename, dst_regex):
        compiled = re.compile(dst_regex)
        # iterate through our regex destination pattern, matching against all destination files
        for dst_match in filter(None, [ compiled.match(dst_filename) for dst_filename in self.dst_files]):
            dst_filename = dst_match[0]
            # skip if we already have an earlier match
            if 'src' in self.manifest['dst'][dst_filename]:
                print(f'Skipping duplicate match {dst_regex} => {dst_filename}')
                continue

            # if the regex pattern matched, check if it requires an xdelta3 patch
            print(f'Matched destination {compiled} => {dst_filename}')
            self.manifest['dst'][dst_filename]['src'] = src_filename

            # generate xdelta3 if the files don't already match
            if self.manifest['src'][src_filename]['sha256'] != self.manifest['dst'][dst_filename]['sha256']:
                print(f'Creating delta for {dst_filename}...')
                self.generate_xdelta3(self.manifest['dst'][dst_filename], src_filename, dst_filename)

    def apply(self):
        # read the manifest file
        print(f'Reading manifest...')
        with open(os.path.join(self.pch, 'manifest.json'), 'r') as inpfile:
            self.manifest = json.load(inpfile)

        # look for files which needed to be added or patched
        print(f'Adding/patching files...')
        for dst_filename in self.manifest['dst']:
            dst_hash = self.generate_hash(os.path.join(self.dst, dst_filename))
            pch_hash = self.generate_hash(os.path.join(self.pch, dst_filename))
            pch_delta_filename = dst_filename + ".xdelta3"
            pch_delta_hash = self.generate_hash(os.path.join(self.pch, pch_delta_filename))
            # check if destination already matches
            if dst_hash == self.manifest['dst'][dst_filename]['sha256']:
                print(f'Skipping already matching {dst_filename}')
                continue;
            # check if there's an expected patch source in src directory
            if dst_filename in self.manifest['src'] and dst_hash == self.manifest['src'][dst_filename]['sha256']:
                # validate the source hash matches manifest
                if self.generate_hash(os.path.join(self.src, dst_filename)) != self.manifest['src'][dst_filename]['sha256']:
                    self.error(f'Hash mismatch for {dst_filename}')
                # validate the patch filename is specified
                if 'xdelta3' not in self.manifest['dst'][dst_filename]:
                    self.error(f'Delta file missing for {dst_filename}')
                # apply xdelta3 patch
                print(f'Patching {dst_filename}...')
                self.apply_xdelta3(dst_filename)
                continue
            # check if there's an expected patch source in patch directory
            if pch_delta_filename in self.manifest['pch'] and pch_delta_hash == self.manifest['pch'][pch_delta_filename]['sha256']:
                # validate the source hash matches manifest
                if self.generate_hash(os.path.join(self.pch, pch_delta_filename)) != self.manifest['pch'][pch_delta_filename]['sha256']:
                    self.error(f'Hash mismatch for {dst_filename}')
                # validate the patch filename is specified
                if 'xdelta3' not in self.manifest['dst'][dst_filename]:
                    self.error(f'Delta file missing for {dst_filename}')
                # apply xdelta3 patch
                print(f'Patching {dst_filename}...')
                self.apply_xdelta3(dst_filename)
                continue
            # check if there is an exact file match in patch directory
            if dst_filename in self.manifest['pch'] and pch_hash == self.manifest['pch'][dst_filename]['sha256']:
                print(f'Copying {dst_filename}')
                self.copyfile(os.path.join(self.pch, dst_filename), os.path.join(self.dst, dst_filename))
                continue

            self.error(f'Found no way to patch {dst_filename}')

        # remove any files not in the manifest
        for filename in self.dst_files:
            if filename not in self.manifest['dst']:
                print(f'Removing {filename}...')
                os.remove(os.path.join(self.dst, filename))

    def find_files(self, path):
        if not os.path.isfile(path):
            for current in os.listdir(path):
                yield from self.find_files(os.path.join(path, current))
        else:
            yield path

    def generate_hashes(self, dirs):
        for dir in dirs:
            for filename in getattr(self, f'{dir}_files'):
                self.manifest[dir][filename] = {
                    'sha256': self.generate_hash(os.path.join(getattr(self, dir), filename))
                }

    def generate_hash(self, path):
        self.verbose(f'Hashing {path}...')
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

    def generate_xdelta3(self, dst, src_filename, dst_filename):
        pch_filename = os.path.join(self.pch, dst_filename + ".xdelta3")
        os.makedirs(os.path.dirname(pch_filename), exist_ok=True)
        command = [
            "xdelta3", "-e", "-9", "-f",
            "-s", os.path.join(self.src, src_filename), os.path.join(self.dst, dst_filename), pch_filename
        ]
        self.verbose(' '.join(command))
        subprocess.check_output(command, universal_newlines=True)
        dst['xdelta3'] = os.path.relpath(pch_filename, self.pch)
        self.manifest['pch'][dst['xdelta3']] = {
            'sha256': self.generate_hash(pch_filename)
        }

    def apply_xdelta3(self, dst_filename):
        pch_filename = os.path.join(self.pch, self.manifest['dst'][dst_filename]['xdelta3'])
        src_filename = os.path.join(self.src, self.manifest['dst'][dst_filename]['src'])
        out_filename = os.path.join(self.dst, dst_filename)
        # apply xdelta3 patch
        os.makedirs(os.path.dirname(out_filename), exist_ok=True)
        command = [
            "xdelta3", "-d", "-f",
            "-s", src_filename, pch_filename, os.path.join(self.dst, dst_filename)
        ]
        self.verbose(' '.join(command))
        subprocess.check_output(command, universal_newlines=True)

    def validate(self):
        print(f'Generating hashes...')
        self.generate_hashes(['src', 'dst', 'pch'])

        # validate src vs dst directly
        for src_filename in self.manifest['src']:
            if src_filename not in self.manifest['dst']:
                self.error(f'{src_filename}: missing from {self.dst}')
            elif self.manifest['src'][src_filename]['sha256'] != self.manifest['dst'][src_filename]['sha256']:
                self.error(f'{src_filename}: sha256 mismatch!')
            print(f'{src_filename}: OK')

    def copyfile(self, src, dst):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)

    def verbose(self, str):
        if self.args.verbose:
            print(str)

    def error(self, str):
        print(str)
        exit(1)

if __name__ == "__main__":
    delta_patcher = DeltaPatcher()
