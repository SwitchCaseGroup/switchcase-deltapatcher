#
# file: patchtool.py
# desc: Binary delta patching tool
# 

import multiprocessing, subprocess, argparse, hashlib, shutil, json, sys, os, io

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

# log message if verbose is enabled
def trace(verbose, text):
    if verbose:
        print(text)

# error resilient makedirs
def makedirs(dir):
    try:
        os.makedirs(dir, exist_ok=True)
    except OSError as e:
        print(dir, e)
        raise

# generate hash of filename
def perform_hash(verbose, filename):
    trace(verbose, f'Hashing {filename}...')
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

# perform atomic file replace
def atomic_replace(src, dst):
    tmp = f'{dst}.tmp'
    # ensure directories exist (can safely fail if another worker collides)
    try:
        makedirs(os.path.dirname(dst))
    except:
        pass
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

class XDelta3Patch:
    def __init__(self, dst_filename, pch_filename):
        self.dst_filename = dst_filename
        self.pch_filename = pch_filename
        self.dst_sha256 = None
        self.pch_sha256 = None

class XDelta3:
    def __init__(self, verbose, src_filename):
        self.verbose = verbose
        self.src_filename = src_filename
        self.src_sha256 = None
        self.patches = []

    def trace(self, text):
        if self.verbose:
            print(text)

    def add_patch(self, dst_filename, pch_filename):
        self.patches.append(XDelta3Patch(dst_filename, pch_filename))

    def perform_xdelta3(self):
        # hash the source file
        if self.src_filename:
            self.src_sha256 = perform_hash(self.verbose, self.src_filename)
        # process all of the potential patches
        for patch in self.patches:
            # hash the destination file
            patch.dst_sha256 = perform_hash(self.verbose, patch.dst_filename)
            # only apply patches when there's a source who's hash doesn't match destination
            if self.src_filename and self.src_sha256 != patch.dst_sha256:
                # create the xdelta3 patch file
                self.trace(f'Creating delta for {patch.dst_filename}...')
                makedirs(os.path.dirname(patch.pch_filename))
                command = [
                    "xdelta3", "-e", "-9", "-f",
                    "-s", self.src_filename, patch.dst_filename, patch.pch_filename
                ]
                self.trace(' '.join(command))
                subprocess.check_output(command, universal_newlines=True)
                # hash the patch file
                patch.pch_sha256 = perform_hash(self.verbose, patch.pch_filename)
            # if there is no source, copy the file itself as the patch
            elif not self.src_filename:
                atomic_replace(patch.dst_filename, patch.pch_filename)
                patch.pch_sha256 = patch.dst_sha256

        return self

class PatchTool:
    def __init__(self, src, dst, pch, out, split, verbose):
        self.src = src
        self.dst = dst
        self.pch = pch
        self.out = out
        self.verbose = verbose
        # add default pattern and prepare any additional patterns from CLI arguments
        self.split = [ ('', '') ] + [ (f'.{ext}', '.') for ext in split]
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
            makedirs(getattr(self, dir))
            # find all files in each directory
            setattr(self, f'{dir}_files', [ os.path.relpath(filename, getattr(self, dir)) for filename in self.find_files(getattr(self, dir)) ])

    def generate(self):
        # cleanup the patch directory
        self.trace(f'Cleaning {self.pch}...')
        for filename in self.find_files(self.pch):
            os.remove(filename)
        for dir in os.listdir(self.pch):
            shutil.rmtree(os.path.join(self.pch, dir), ignore_errors=True)

        # perform patching in parallel and process the results
        for xdelta3 in self.pool.imap_unordered(partial(XDelta3.perform_xdelta3), self.generate_queue()):
            # update manifest with src hash, if the patch(es) had a source
            if xdelta3.src_filename:
                src_filename = os.path.relpath(xdelta3.src_filename, self.src)
                self.manifest['src'][src_filename] = { 'sha256': xdelta3.src_sha256, "xdelta3": [] }
            # process each patch's results
            for patch in xdelta3.patches:
                dst_filename = os.path.relpath(patch.dst_filename, self.dst)
                # update manifest with dst hash
                self.manifest['dst'][dst_filename] = { 'sha256': patch.dst_sha256 }
                # update manifest with patch hash, if there was a patch file
                if patch.pch_sha256:
                    pch_filename = os.path.relpath(patch.pch_filename, self.pch)
                    self.manifest['pch'][pch_filename] = { 'sha256': patch.pch_sha256 }
                    # if this patch is a delta, update manifest with the delta's hash
                    if xdelta3.src_filename:
                        self.manifest['src'][src_filename]['xdelta3'].append({dst_filename: pch_filename})
            # cleanup
            if xdelta3.src_filename and len(self.manifest['src'][src_filename]['xdelta3']) == 0:
                del self.manifest['src'][src_filename]['xdelta3']
                if src_filename not in self.manifest['dst']:
                    del self.manifest['src'][src_filename]
        
        # generate dir list
        self.manifest['dir'] = [ os.path.relpath(filename, self.dst) for filename in self.find_dirs(self.dst) ]

        # write the manifest file
        self.trace(f'Writing manifest...')
        with open(os.path.join(self.pch, 'manifest.json'), 'w') as outfile:
            json.dump(self.manifest, outfile, indent=4)

    def generate_queue(self):
        # search for modified files and queue patches for them
        self.trace(f'Creating deltas for modified files...')
        for (ending, append) in self.split:
            for src_filename in [src_filename for src_filename in self.src_files if src_filename.endswith(ending)]:
                # if the pattern matched, find all destination matches
                self.trace(f'Matched source ("{ending}", "{append}") => {src_filename}')
                # prepare prefix for destination match
                dst_prefix = src_filename[-len(ending):] + append
                # handle destination file matches
                xdelta3 = XDelta3(self.verbose, os.path.join(self.src, src_filename))
                # iterate through our destination prefix, matching against all destination files
                for dst_filename in [dst_filename for dst_filename in self.dst_files if dst_filename.startswith(dst_prefix)]:
                    # skip if we already have an earlier match
                    if dst_filename in self.manifest['dst']:
                        self.trace(f'Skipping duplicate match {dst_filename}')
                        continue
                    self.trace(f'Matched destination {dst_filename}')
                    # generate xdelta3 if the files don't already match
                    pch_filename = f'{dst_filename}.xdelta3'
                    abs_dst_filename = os.path.join(self.dst, dst_filename)
                    abs_pch_filename = os.path.join(self.pch, pch_filename)
                    xdelta3.add_patch(abs_dst_filename, abs_pch_filename)
                yield xdelta3

        # search for files without a source and queue patches for them
        self.trace(f'Copying added files...')
        for dst_filename in [dst_filename for dst_filename in self.dst_files if dst_filename not in self.manifest['dst']]:
            pch_filename = os.path.join(self.pch, dst_filename)
            self.manifest['dst'][dst_filename] = { }
            xdelta3 = XDelta3(self.verbose, None)
            xdelta3.add_patch(os.path.join(self.dst, dst_filename), pch_filename)
            yield xdelta3
        
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

        # look for files which need to be copied or patched from source dir
        self.trace(f'Patching files...')
        for src_filename in self.manifest['src']:
            # validate source hash
            src_hash = self.generate_hash(os.path.join(self.src, src_filename))
            if src_hash != self.manifest['src'][src_filename]['sha256']:
                self.error(f'Hash mismatch for {src_filename}')
            # apply patches from this source file
            for patch in self.manifest['src'][src_filename].get('xdelta3', []):
                for dst_filename in patch:
                    pch_filename = patch[dst_filename]
                    # check if dst already matches
                    dst_hash = self.generate_hash(os.path.join(self.dst, dst_filename))
                    if dst_hash == self.manifest['dst'][dst_filename]['sha256']:
                        self.trace(f'Skipping already matching {dst_filename}')
                    # if not, apply patch
                    else:
                        self.trace(f'Patching {dst_filename}...')
                        self.apply_xdelta3(src_filename, dst_filename, pch_filename)
            # check if there is an exact match in the dst directory
            if src_filename in self.manifest['dst'] and self.manifest['dst'][src_filename]['sha256'] == src_hash:
                # check if dst already matches
                dst_hash = self.generate_hash(os.path.join(self.dst, src_filename))
                if dst_hash == src_hash:
                    self.trace(f'Skipping already matching {src_filename}')
                # if not, copy from source
                else:
                    self.trace(f'Copying {src_filename}...')
                    atomic_replace(os.path.join(self.src, src_filename), os.path.join(self.dst, src_filename))

        # look for files which need to be copied from patch dir
        self.trace(f'Adding files...')
        for pch_filename in self.manifest['pch']:
            # validate patch hash
            pch_hash = self.generate_hash(os.path.join(self.pch, pch_filename))
            if pch_hash != self.manifest['pch'][pch_filename]['sha256']:
                self.error(f'Hash mismatch for {pch_filename}')
            # check if there is an exact match in the dst directory
            if pch_filename in self.manifest['dst'] and self.manifest['dst'][pch_filename]['sha256'] == pch_hash:
                # check if dst already matches
                dst_hash = self.generate_hash(os.path.join(self.dst, pch_filename))
                if dst_hash == src_hash:
                    self.trace(f'Skipping already matching {pch_filename}')
                # if not, copy from source
                else:
                    self.trace(f'Copying {pch_filename}...')
                    atomic_replace(os.path.join(self.pch, pch_filename), os.path.join(self.dst, pch_filename))

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
        # queue the hashes
        queue = [ os.path.join(getattr(self, dir), filename) for dir in dirs for filename in getattr(self, f'{dir}_files') ]
        # perform hashes in parallel
        tasks = list(self.pool.imap(partial(perform_hash, self.verbose), queue))
        # retrieve results in same order as queued
        for dir in dirs:
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

    def apply_xdelta3(self, src_filename, dst_filename, pch_filename):
        src_filename = os.path.join(self.src, src_filename)
        pch_filename = os.path.join(self.pch, pch_filename)
        dst_filename = os.path.join(self.dst, dst_filename)
        tmp_filename = f'{dst_filename}.patched'
        # apply xdelta3 patch to temporary file
        makedirs(os.path.dirname(dst_filename))
        command = [
            "xdelta3", "-d", "-f",
            "-s", src_filename, pch_filename, tmp_filename
        ]
        self.trace(' '.join(command))
        subprocess.check_output(command, universal_newlines=True)
        # perform atomic file copy/replace
        atomic_replace(tmp_filename, dst_filename)
        # remove temporary file
        os.remove(tmp_filename)

    def validate(self):
        # read the manifest file
        self.trace(f'Reading manifest...')
        with open(os.path.join(self.pch, 'manifest.json'), 'r') as inpfile:
            self.manifest = json.load(inpfile)

        # generate local hashes
        self.trace(f'Generating hashes...')
        local_manifest = { "src": { }, "dst": { }, "pch": { } }
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
