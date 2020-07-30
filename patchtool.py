#
# file: patchtool.py
# desc: Binary delta patching tool
# 

import multiprocessing, subprocess, argparse, hashlib, shutil, json, sys, re, os, io

from functools import partial

usage = f'''

Example to generate patch directory, apply it and then validate:
  python3 patchtool.py generate -s src_dir -d dst_dir -p patch_dir
  python3 patchtool.py apply -s src_dir -d out_dir -p patch_dir
  python3 patchtool.py validate -s dst_dir -d out_dir -p patch_dir

Patching can also be done in-place, over top of the source directory:
  python3 patchtool.py generate -s src_dir -d dst_dir -p patch_dir
  python3 patchtool.py apply -s src_dir -d src_dir -p patch_dir
  python3 patchtool.py validate -s dst_dir -d src_dir -p patch_dir

Patch apply uses atomic file operations. If the process is interrupted,
the apply command can be run again to resume patching.

'''

# generate hash of filename
def perform_hash(verbose, filename):
    if verbose:
        print(f'Hashing {filename}...')
    hash = hashlib.sha256()
    try:
        with open(filename, 'rb') as inpfile:
            block = inpfile.read(io.DEFAULT_BUFFER_SIZE)
            while len(block) != 0:
                hash.update(block)
                block = inpfile.read(io.DEFAULT_BUFFER_SIZE)
    except:
        pass
    return hash.hexdigest()

class PatchTool:

    def __init__(self, src, dst, pch, out, split, verbose):
        self.src = src
        self.dst = dst
        self.pch = pch
        self.out = out
        self.verbose = verbose
        # add default regex pattern and prepare any additional patterns from CLI arguments
        self.pat = [ "(.*):{0}" ]
        for ext in split:
            self.pat += [ "(.*)\." + ext + ":{0}\.(.*)" ]
        # initialize blank manifest
        self.manifest = { "src": { }, "dst": { }, "pch": { } }
        # prepare to process on each of the system's cpus
        self.pool = multiprocessing.Pool(processes = multiprocessing.cpu_count())

    def initialize(self):
        # initialize directories
        self.trace(f'Recursively gathering filenames...')
        for dir in [ 'src', 'dst', 'pch' ]:
            # convert dirs to absolute paths
            setattr(self, dir, os.path.abspath(getattr(self, dir)))
            # ensure directories exist
            os.makedirs(getattr(self, dir), exist_ok=True)
            # find all files in each directory
            setattr(self, f'{dir}_files', [ os.path.relpath(filename, getattr(self, dir)) for filename in self.find_files(getattr(self, dir)) ])

    def generate(self):
        # cleanup the patch directory
        self.trace(f'Cleaning {self.pch}...')
        for filename in self.find_files(self.pch):
            os.remove(filename)
        for dir in os.listdir(self.pch):
            shutil.rmtree(os.path.join(self.pch, dir), ignore_errors=True)

        # add manifest entry for each destination file and hash its file contents
        self.trace(f'Generating sha256 hashes for destination files...')
        self.generate_hashes(self.manifest, ["src", "dst"])

        # search for modified files and generate xdelta3 patches for them
        self.trace(f'Creating deltas for modified files...')
        for (src_regex, dst_regex) in [ pattern.split(':') for pattern in self.pat ]:
            compiled = re.compile(src_regex)
            for src_match in filter(None, [ compiled.fullmatch(src_filename) for src_filename in self.src_files]):
                # if the regex pattern matched, find all destination matches
                self.trace(f'Matched source "{src_regex}" => {src_match[0]}')
                # replace destination pattern {N} variables with results from source regex
                dst_regex_new = dst_regex
                for group in range(compiled.groups):
                    dst_regex_new = dst_regex_new.replace('{' + str(group) + '}', re.escape(src_match[group+1]))
                # handle destination file regex matches
                self.generate_deltas(src_match[0], dst_regex_new);

        # handle added files by copying over the destination file directly
        self.trace(f'Copying added files...')
        for dst_filename in [dst_filename for dst_filename in self.manifest['dst'] if 'src' not in self.manifest['dst'][dst_filename]]:
            self.trace(f'Copying {dst_filename}...')
            pch_filename = os.path.join(self.pch, dst_filename)
            self.atomic_replace(os.path.join(self.dst, dst_filename), pch_filename)

        # generate pch hashes
        self.pch_files = [ os.path.relpath(filename, self.pch) for filename in self.find_files(self.pch) ]
        self.generate_hashes(self.manifest, ['pch'])

        # generate dir list
        self.manifest['dir'] = [ os.path.relpath(filename, self.dst) for filename in self.find_dirs(self.dst) ]

        # write the manifest file
        self.trace(f'Writing manifest...')
        with open(os.path.join(self.pch, 'manifest.json'), 'w') as outfile:
            json.dump(self.manifest, outfile, indent=4)

    def generate_deltas(self, src_filename, dst_regex):
        compiled = re.compile(dst_regex)
        # iterate through our regex destination pattern, matching against all destination files
        for dst_match in filter(None, [ compiled.fullmatch(dst_filename) for dst_filename in self.dst_files]):
            dst_filename = dst_match[0]
            # skip if we already have an earlier match
            if 'src' in self.manifest['dst'][dst_filename]:
                self.trace(f'Skipping duplicate match {dst_regex} => {dst_filename}')
                continue

            # if the regex pattern matched, check if it requires an xdelta3 patch
            self.trace(f'Matched destination {compiled} => {dst_filename}')
            self.manifest['dst'][dst_filename]['src'] = src_filename

            # generate xdelta3 if the files don't already match
            if self.manifest['src'][src_filename]['sha256'] != self.manifest['dst'][dst_filename]['sha256']:
                self.trace(f'Creating delta for {dst_filename}...')
                self.generate_xdelta3(self.manifest['dst'][dst_filename], src_filename, dst_filename)

    def generate_xdelta3(self, dst, src_filename, dst_filename):
        pch_filename = os.path.join(self.pch, dst_filename + ".xdelta3")
        os.makedirs(os.path.dirname(pch_filename), exist_ok=True)
        command = [
            "xdelta3", "-e", "-9", "-f",
            "-s", os.path.join(self.src, src_filename), os.path.join(self.dst, dst_filename), pch_filename
        ]
        self.trace(' '.join(command))
        subprocess.check_output(command, universal_newlines=True)
        dst['xdelta3'] = os.path.relpath(pch_filename, self.pch)

    def apply(self):
        # read the manifest file
        self.trace(f'Reading manifest...')
        with open(os.path.join(self.pch, 'manifest.json'), 'r') as inpfile:
            self.manifest = json.load(inpfile)

        # remove any files not in the manifest
        for filename in self.dst_files:
            if filename not in self.manifest['dst']:
                self.trace(f'Removing {filename}...')
                os.remove(os.path.join(self.dst, filename))

        # look for files which needed to be added or patched
        self.trace(f'Adding/patching files...')
        for source in [ False, True ]:
            for dst_filename in self.manifest['dst']:
                # first pass, don't overwrite source files which other files depend on (to support in-place patching)
                if source != ('src' in self.manifest['dst'][dst_filename] and self.manifest['dst'][dst_filename]['src'] == dst_filename):
                    continue
                # check if destination already matches
                dst_hash = self.generate_hash(os.path.join(self.dst, dst_filename))
                if dst_hash == self.manifest['dst'][dst_filename]['sha256']:
                    self.trace(f'Skipping already matching {dst_filename}')
                    continue;
                # check if there is an exact file match in src directory
                if dst_filename in self.manifest['src']:
                    src_hash = self.generate_hash(os.path.join(self.src, dst_filename))
                    if src_hash == self.manifest['src'][dst_filename]['sha256'] and src_hash == self.manifest['dst'][dst_filename]['sha256']:
                        self.trace(f'Copying {dst_filename}')
                        self.atomic_replace(os.path.join(self.src, dst_filename), os.path.join(self.dst, dst_filename))
                        continue
                # check if there is an exact file match in patch directory
                if dst_filename in self.manifest['pch']:
                    pch_hash = self.generate_hash(os.path.join(self.pch, dst_filename))
                    if pch_hash == self.manifest['pch'][dst_filename]['sha256'] and pch_hash == self.manifest['dst'][dst_filename]['sha256']:
                        self.trace(f'Copying {dst_filename}')
                        self.atomic_replace(os.path.join(self.pch, dst_filename), os.path.join(self.dst, dst_filename))
                        continue
                # check if there's an expected patch source in src directory
                if dst_filename in self.manifest['src'] and dst_hash == self.manifest['src'][dst_filename]['sha256']:
                    # validate the source hash matches manifest
                    if self.generate_hash(os.path.join(self.src, dst_filename)) != self.manifest['src'][dst_filename]['sha256']:
                        self.error(f'Hash mismatch for {dst_filename}')
                    # validate the patch filename is specified
                    if 'xdelta3' not in self.manifest['dst'][dst_filename]:
                        self.error(f'Delta file missing for {dst_filename}')
                    # apply xdelta3 patch
                    self.trace(f'Patching {dst_filename}...')
                    self.apply_xdelta3(dst_filename)
                    continue
                # check if there's an expected patch source in patch directory
                pch_delta_filename = dst_filename + ".xdelta3"
                pch_delta_hash = self.generate_hash(os.path.join(self.pch, pch_delta_filename))
                if pch_delta_filename in self.manifest['pch'] and pch_delta_hash == self.manifest['pch'][pch_delta_filename]['sha256']:
                    # validate the source hash matches manifest
                    if self.generate_hash(os.path.join(self.pch, pch_delta_filename)) != self.manifest['pch'][pch_delta_filename]['sha256']:
                        self.error(f'Hash mismatch for {dst_filename}')
                    # validate the patch filename is specified
                    if 'xdelta3' not in self.manifest['dst'][dst_filename]:
                        self.error(f'Delta file missing for {dst_filename}')
                    # apply xdelta3 patch
                    self.trace(f'Patching {dst_filename}...')
                    self.apply_xdelta3(dst_filename)
                    continue

                self.error(f'Found no way to patch {dst_filename}')

        # remove any dirs not in the manifest
        for dir in [ os.path.relpath(filename, self.dst) for filename in self.find_dirs(self.dst) ]:
            if dir not in self.manifest['dir']:
                self.trace(f'Removing {dir}...')
                shutil.rmtree(os.path.join(self.dst, dir), ignore_errors=True)

    def find_files(self, path):
        if not os.path.isfile(path):
            for current in os.listdir(path):
                yield from self.find_files(os.path.join(path, current))
        else:
            yield path

    def find_dirs(self, path):
        if not os.path.isfile(path):
            yield path
            for current in os.listdir(path):
                yield from self.find_dirs(os.path.join(path, current))

    def generate_hashes(self, manifest, dirs):
        # queue up the hash generators
        queue = []
        for dir in dirs:
            for filename in getattr(self, f'{dir}_files'):
                queue.append(os.path.join(getattr(self, dir), filename))

        # perform the hashes
        tasks = list(self.pool.imap(partial(perform_hash, self.verbose), queue))

        # retrieve the results in the same order as queued
        for dir in dirs:
            if dir not in manifest:
                manifest[dir] = { }
            for filename in getattr(self, f'{dir}_files'):
                manifest[dir][filename] = {
                    'sha256': tasks.pop(0)
                }

    def generate_hash(self, path):
        self.trace(f'Hashing {path}...')
        hash = hashlib.sha256()
        try:
            with open(path, 'rb') as inpfile:
                block = inpfile.read(io.DEFAULT_BUFFER_SIZE)
                while len(block) != 0:
                    hash.update(block)
                    block = inpfile.read(io.DEFAULT_BUFFER_SIZE)
        except:
            pass
        return hash.hexdigest()

    def apply_xdelta3(self, dst_filename):
        pch_filename = os.path.join(self.pch, self.manifest['dst'][dst_filename]['xdelta3'])
        src_filename = os.path.join(self.src, self.manifest['dst'][dst_filename]['src'])
        out_filename = os.path.join(self.dst, dst_filename)
        tmp_filename = f'{out_filename}.patched'
        # apply xdelta3 patch to temporary file
        os.makedirs(os.path.dirname(out_filename), exist_ok=True)
        command = [
            "xdelta3", "-d", "-f",
            "-s", src_filename, pch_filename, tmp_filename
        ]
        self.trace(' '.join(command))
        subprocess.check_output(command, universal_newlines=True)
        # perform atomic file copy/replace
        self.atomic_replace(tmp_filename, out_filename)
        # remove temporary file
        os.remove(tmp_filename)

    def validate(self):
        # read the manifest file
        self.trace(f'Reading manifest...')
        with open(os.path.join(self.pch, 'manifest.json'), 'r') as inpfile:
            self.manifest = json.load(inpfile)

        # generate local hashes
        self.trace(f'Generating hashes...')
        local_manifest = {}
        self.generate_hashes(local_manifest, ['src', 'dst'])

        # validate all src files exist in dst and hashes match
        for src_filename in self.src_files:
            if src_filename not in self.dst_files:
                self.error(f'{src_filename}: missing from {self.dst}')
            elif local_manifest['src'][src_filename]['sha256'] != local_manifest['dst'][src_filename]['sha256']:
                self.error(f'{src_filename}: src/dst sha256 mismatch!')
            elif local_manifest['src'][src_filename]['sha256'] != self.manifest['dst'][src_filename]['sha256']:
                self.error(f'{src_filename}: manifest sha256 mismatch!')

        # validate all dst files exist in src
        for dst_filename in self.dst_files:
            if dst_filename not in self.src_files:
                self.error(f'{dst_filename}: missing from {self.src}')

    def atomic_replace(self, src, dst):
        tmp = f'{dst}.tmp'
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        # perform atomic file copy/replace
        with open(src, 'rb') as inpfile:
            with open(tmp, 'wb') as outfile:
                block = inpfile.read(io.DEFAULT_BUFFER_SIZE)
                while len(block) != 0:
                    outfile.write(block)
                    block = inpfile.read(io.DEFAULT_BUFFER_SIZE)
                outfile.flush()
                os.fsync(outfile.fileno())
        os.replace(tmp, dst)

    def trace(self, str):
        if self.verbose:
            print(str)

    def error(self, str):
        print(str)
        exit(1)

if __name__ == "__main__":
    # currently supported CLI commands
    commands = [ "generate", "apply", "validate" ]
    # parse command-line arguments and execute the command
    arg_parser = argparse.ArgumentParser(description='Binary delta patching tool.', usage=usage, formatter_class=argparse.RawTextHelpFormatter)
    arg_parser.add_argument('command', nargs='?', choices=commands, default="generate", help='command')
    arg_parser.add_argument('-s', '--src', dest='src', required=True, help='source directory')
    arg_parser.add_argument('-d', '--dst', dest='dst', required=True, help='destination directory')
    arg_parser.add_argument('-p', '--patch', dest='pch', required=True, help='patch directory')
    arg_parser.add_argument('-o', '--out', dest='out', default='out', help='output directory (for tests)')
    arg_parser.add_argument('-x', '--split', dest='split', default=[ 'uasset', 'umap' ], nargs="*", help='zero or more split file extensions')
    arg_parser.add_argument('-v', '--verbose', dest='verbose', action="store_true", help='increase verbosity')
    args = arg_parser.parse_args()
    patch_tool = PatchTool(args.src, args.dst, args.pch, args.out, args.split, args.verbose)
    patch_tool.initialize()
    getattr(globals()['PatchTool'], args.command)(patch_tool)
