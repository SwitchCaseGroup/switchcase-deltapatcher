#
# file: patchtool.py
# desc: Binary delta patching tool
#

import multiprocessing
import subprocess
import argparse
import hashlib
import signal
import shutil
import gzip
import stat
import json
import sys
import bz2
import os
import io

from datetime import datetime
from functools import partial
from collections import defaultdict

description = f'''

Example to generate patch directory, apply it and then validate:
  python3 patchtool.py generate -s src_dir -d dst_dir -p patch_dir
  python3 patchtool.py apply -s src_dir -d out_dir -p patch_dir
  python3 patchtool.py validate -s dst_dir -d out_dir -p patch_dir

Patching can also be done in-place, over top of the source directory:
  python3 patchtool.py generate -s src_dir -d dst_dir -p patch_dir
  python3 patchtool.py apply -s src_dir -d src_dir -p patch_dir
  python3 patchtool.py validate -d src_dir -p patch_dir

Patch apply uses atomic file operations. If the process is interrupted,
the apply command can be run again to resume patching.

Validation can be done on either one or both of src/dst directories:
  python3 patchtool.py validate -s dst_dir -d out_dir -p patch_dir
  python3 patchtool.py validate -s src_dir -p patch_dir
  python3 patchtool.py validate -d dst_dir -p patch_dir

This allows a patch to be validated before and/or after in-place patching.

'''


class PatchTool:
    def __init__(self, split, zip, stop_on_error, verbose):
        self.split = split
        self.verbose = verbose
        self.manifest = defaultdict(dict)
        self.pool = None
        self.zip = zip
        self.stop_on_error = stop_on_error
        self.create_pool()

    def __del__(self):
        self.pool.terminate()
        self.pool.close()
        self.pool.join()

    def initialize(self, src, dst, pch):
        self.src = src
        self.dst = dst
        self.pch = pch
        self.src_files = {}
        self.dst_files = {}
        self.pch_files = {}
        self.has_error = False
        self.create_pool()
        # initialize directories
        self.trace(f'Preparing file information...')
        for dir in ['src', 'dst', 'pch']:
            directory = getattr(self, dir)
            if directory:
                # convert dirs to absolute paths
                setattr(self, dir, os.path.abspath(directory))
                # ensure directories exist
                makedirs(directory)
                # find all files in each directory
                self.scan_files(dir, directory)

    def scan_files(self, dir, directory):
        setattr(self, f'{dir}_files', {entry.name: entry for entry in self.scantree(directory, directory)})

    def create_pool(self):
        # flush the old pool which could have lingering subprocesses
        if self.pool:
            self.pool.close()
            self.pool.join()
        # create pool, disabling SIGINT so parent process can handle it
        handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        self.pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
        signal.signal(signal.SIGINT, handler)

    def generate(self):
        # cleanup the patch directory
        self.trace(f'Cleaning {self.pch}...')
        shutil.rmtree(self.pch, ignore_errors=True)
        makedirs(self.pch)

        # populate src/dst manifest with files/dirs metadata
        for dir in ['src', 'dst']:
            for entry in getattr(self, f'{dir}_files').values():
                self.manifest[dir][entry.name] = {
                    attr: getattr(entry, attr) for attr in ['uid', 'gid', 'mode', 'size', 'mtime']
                }

        # create patch directory structure
        for entry in self.iterate_dirs('dst'):
            makedirs(os.path.join(self.pch, entry.name))

        # perform patch generation in parallel and process the results as they arrive
        for xdelta3 in self.pool.imap_unordered(XDelta3.generate_patches, self.generate_queue()):
            # update manifest with src hash, if the patch(es) had a source
            if xdelta3.src_filename:
                src_filename = os.path.relpath(xdelta3.src_filename, self.src)
                self.manifest['src'][src_filename]['sha1'] = xdelta3.src_sha1
                self.manifest['src'][src_filename]["xdelta3"] = {}
            # process each patch's results
            for patch in xdelta3.patches:
                # update manifest with dst hash
                dst_filename = os.path.relpath(patch.dst_filename, self.dst)
                self.manifest['dst'][dst_filename]['sha1'] = patch.dst_sha1
                # process patch file result if there was one
                if patch.pch_sha1:
                    # update manifest with patch hash
                    pch_filename = os.path.relpath(patch.pch_filename, self.pch)
                    self.manifest['pch'][pch_filename] = {'sha1': patch.pch_sha1, 'zip': self.zip}
                    # if this patch is a delta, update src in manifest with the delta's filename
                    if xdelta3.src_filename:
                        self.manifest['src'][src_filename]['xdelta3'][dst_filename] = pch_filename
                    # otherwise, reference the destination filename
                    else:
                        self.manifest['pch'][pch_filename]['dst'] = dst_filename
            # cleanup empty manifest entries
            if xdelta3.src_filename and len(self.manifest['src'][src_filename]['xdelta3']) == 0:
                del self.manifest['src'][src_filename]['xdelta3']

        # generate metadata for manifest file
        self.generate_metadata()

        # write the manifest file
        self.trace(f'Writing manifest...')
        with open(os.path.join(self.pch, 'manifest.json'), 'w') as outfile:
            json.dump(self.manifest, outfile, indent=4)

    def generate_queue(self):
        # search for modified files and queue patches for them
        self.trace(f'Creating deltas for modified files...')
        for (src, dsts) in self.generate_merged():
            # create deltas relative to this source file
            xdelta3 = XDelta3(self.verbose, src.path)
            xdelta3.src_size = src.size
            # iterate through our destination files, looking for matches
            for dst in dsts:
                self.trace(f'Matched destination {dst.name}')
                # mark this dst as having been queued for processing
                self.manifest['dst'][dst.name]['sha1'] = ''
                # generate xdelta3 if the files don't already match
                abs_dst_filename = os.path.join(self.dst, dst.name)
                abs_pch_filename = os.path.join(self.pch, dst.name)
                xdelta3.add_patch(XDelta3Patch(abs_dst_filename, abs_pch_filename, self.zip))
            yield xdelta3

        # search for destination files without a source and create full-copy patches for them
        self.trace(f'Copying added files...')
        for dst in [dst for dst in self.iterate_files('dst') if 'sha1' not in self.manifest['dst'][dst.name]]:
            pch_filename = os.path.join(self.pch, dst.name)
            xdelta3 = XDelta3(self.verbose, None)
            xdelta3.add_patch(XDelta3Patch(dst.path, pch_filename, self.zip))
            yield xdelta3

    def generate_merged(self):
        map = defaultdict(list)
        # prepare list of destination files for each "prefix" (filename prior to final '.' character)
        for dst_entry in self.iterate_files('dst'):
            extension = dst_entry.name.rfind('.')
            if extension != -1:
                map[dst_entry.name[:extension]].append(dst_entry)
                continue
            map[dst_entry.name].append(dst_entry)
        # use the prefix lists from above to return source files mapped to their split destination file(s)
        for src_entry in self.iterate_files('src'):
            extension = src_entry.name.rfind('.')
            if extension != -1 and src_entry.name[extension + 1:] in self.split:
                dsts = map[src_entry.name[:extension]]
                if len(dsts):
                    yield (src_entry, dsts)
            elif src_entry.name in self.dst_files:
                yield (src_entry, [src_entry])
        return map

    def generate_metadata(self):
        # write manifest metadata
        self.manifest["metadata"] = {
            "manifest": {
                "created": str(datetime.now()),
                "version": 1.0,
                "src": self.src,
                "dst": self.dst,
                "pch": self.pch
            },
            "src_size": 0,
            "dst_size": 0,
            "pch_size": 0
        }

        # refresh pch file information
        self.scan_files('pch', self.pch)

        # update pch manifest entries with file sizes
        for pch_entry in self.iterate_files('pch'):
            self.manifest['pch'][pch_entry.name]['size'] = pch_entry.size

        # determine src/dst size
        for dir in ['src', 'dst', 'pch']:
            for entry in self.iterate_files(dir):
                self.manifest["metadata"][f'{dir}_size'] += entry.size

    def apply(self):
        # read the manifest file
        self.trace(f'Reading manifest...')
        with open(os.path.join(self.pch, 'manifest.json'), 'r') as inpfile:
            self.manifest = json.load(inpfile)

        # create destination directories, in tree order, applying manifest permissions
        for (name, entry) in sorted(self.iterate_manifest('dst', True), key=lambda tuple: tuple[0]):
            mkdir(os.path.join(self.dst, name), mode=entry['mode'])

        # perform patching in parallel (dependent files)
        for xdelta3 in self.pool.imap_unordered(XDelta3.apply_patches, self.apply_queue(False)):
            self.has_error = self.has_error or xdelta3.has_error
            if self.has_error and self.stop_on_error:
                raise ValueError("Stopping on error.")

        # perform patching in parallel (dependencies)
        for xdelta3 in self.pool.imap_unordered(XDelta3.apply_patches, self.apply_queue(True)):
            self.has_error = self.has_error or xdelta3.has_error
            if self.has_error and self.stop_on_error:
                raise ValueError("Stopping on error.")

        # apply file properties
        self.trace(f'Applying file properties...')
        for (name, entry) in self.manifest['dst'].items():
            dst_filename = os.path.join(self.dst, name)
            timestamp = datetime.strptime(entry['mtime'], '%Y-%m-%dT%H:%M:%S.%f').timestamp()
            os.chmod(dst_filename, entry['mode'])
            os.chown(dst_filename, entry['uid'], entry['gid'])
            os.utime(dst_filename, times=(timestamp, timestamp))

        # remove any files not in the manifest
        for entry in [entry for entry in self.iterate_files('dst') if entry.name not in self.manifest['dst']]:
            self.trace(f'Removing {entry.name}...')
            remove(os.path.join(self.dst, entry.name))

        # remove any directories not in the manifest
        for entry in [entry for entry in self.iterate_dirs('dst') if entry.name not in self.manifest['dst']]:
            self.trace(f'Removing {entry.name}...')
            shutil.rmtree(os.path.join(self.dst, entry.name), ignore_errors=True)

    def apply_queue(self, sources):
        # search for files which need to be copied or patched from source dir
        self.trace(f'Patching files ({"sources" if sources else "dependents"})...')
        for (src_filename, src_entry) in self.iterate_manifest('src'):
            xdelta3 = XDelta3(self.verbose, os.path.join(self.src, src_filename))
            xdelta3.src_sha1 = src_entry['sha1']
            xdelta3.src_size = src_entry['size']
            # queue up patches for destination files which are deltas from a source file
            for dst_filename, pch_filename in src_entry.get('xdelta3', {}).items():
                abs_dst_filename = os.path.join(self.dst, dst_filename)
                # defer patching when destination == source, for in-place patching it would break other deltas
                if sources == (src_filename == dst_filename):
                    abs_pch_filename = os.path.join(self.pch, pch_filename)
                    patch = XDelta3Patch(abs_dst_filename, abs_pch_filename, self.manifest['pch'][pch_filename]['zip'])
                    patch.dst_sha1 = self.manifest['dst'][dst_filename]['sha1']
                    patch.pch_sha1 = self.manifest['pch'][pch_filename]['sha1']
                    xdelta3.add_patch(patch)
            # queue up patches for destination files to be directly copied from source directory
            if sources and src_filename in self.manifest['dst']:
                if src_entry['sha1'] == self.manifest['dst'][src_filename]['sha1']:
                    abs_dst_filename = os.path.join(self.dst, src_filename)
                    xdelta3.add_patch(XDelta3Patch(abs_dst_filename, None, False))
            yield xdelta3

        # queue up patches for destination files to be directly copied from patch directory
        for (pch_filename, pch_entry) in self.iterate_manifest('pch'):
            if 'dst' in pch_entry:
                abs_dst_filename = os.path.join(self.dst, pch_entry['dst'])
                abs_pch_filename = os.path.join(self.pch, pch_filename)
                xdelta3 = XDelta3(self.verbose, abs_pch_filename)
                xdelta3.src_sha1 = self.manifest['pch'][pch_filename]['sha1']
                xdelta3.add_patch(XDelta3Patch(abs_dst_filename, None, self.manifest['pch'][pch_filename]['zip']))
                yield xdelta3

    def iterate_manifest(self, dir, dirs=False):
        for (name, entry) in self.manifest[dir].items():
            if ('sha1' not in entry) == dirs:
                yield (name, entry)

    def iterate_files(self, dir):
        for entry in getattr(self, f'{dir}_files').values():
            if entry.is_file:
                yield entry

    def iterate_dirs(self, dir):
        for entry in getattr(self, f'{dir}_files').values():
            if entry.is_dir:
                yield entry

    def iterate_all(self, dir):
        for entry in getattr(self, f'{dir}_files').values():
            yield entry

    def scantree(self, basedir, path):
        try:
            for entry in os.scandir(path):
                yield ManifestEntry(basedir, entry)
                if entry.is_dir(follow_symlinks=False):
                    yield from self.scantree(basedir, entry.path)
        except FileNotFoundError:
            pass

    def generate_hashes(self, manifest, dirs):
        # prepare the queue of files to hash
        queue = [entry.path for dir in dirs for entry in self.iterate_files(dir)]
        # perform hashes in parallel
        tasks = list(self.pool.imap(partial(perform_hash, self.verbose), queue))
        # retrieve results in the same order as queued
        for dir in dirs:
            for entry in self.iterate_files(dir):
                manifest[dir][entry.name] = {
                    'sha1': tasks.pop(0)
                }

    def validate(self):
        # read the manifest file
        self.trace(f'Reading manifest...')
        with open(os.path.join(self.pch, 'manifest.json'), 'r') as inpfile:
            self.manifest = json.load(inpfile)

        # generate local hashes
        self.trace(f'Generating hashes...')
        local_manifest = defaultdict(dict)
        self.generate_hashes(local_manifest, ['src', 'dst', 'pch'])

        # validate manifest vs local files
        for dir in [dir for dir in ['src', 'dst', 'pch'] if getattr(self, dir)]:
            # check each entry in the manifest against each local file
            for (filename, entry) in self.iterate_manifest(dir):
                dir_files = getattr(self, f'{dir}_files')
                abs_filename = os.path.join(getattr(self, dir), filename)
                # make sure file in manifest exists locally
                if filename not in dir_files:
                    self.error(f'{abs_filename}: missing in {dir}')
                # make sure hash in manifest matches the local hash
                if local_manifest[dir][filename]['sha1'] != self.manifest[dir][filename]['sha1']:
                    self.error(f'{abs_filename}: manifest sha1 mismatch in {dir}')
                # make sure each file attribute in the manifest matches the local file attribute
                for attr in [attr for attr in ['uid', 'gid', 'mode', 'size', 'mtime'] if attr in entry]:
                    if getattr(dir_files[filename], attr) != entry[attr]:
                        print(f'{abs_filename}: {attr} mismatch in {dir}')
            for entry in (self.iterate_files(dir) if dir == 'pch' else self.iterate_all(dir)):
                if entry.name != 'manifest.json' and entry.name not in self.manifest[dir]:
                    self.error(f'{entry.path}: missing from manifest!')

    def analyze(self):
        # populate src/dst manifest with files/dirs metadata
        for dir in ['src', 'dst']:
            for entry in getattr(self, f'{dir}_files').values():
                self.manifest[dir][entry.name] = {
                    attr: getattr(entry, attr) for attr in ['uid', 'gid', 'mode', 'size', 'mtime']
                }

        # determine what savings there would be with case-insensitive src/dst keying
        self.trace(f'Searching for case insensitive src/dst matches...')
        case_insensitive_size = 0
        upper = {src_entry.upper(): src_entry for src_entry in self.manifest['src']}
        for dst_entry in self.manifest['dst']:
            if dst_entry.upper() in upper and dst_entry not in self.manifest['src']:
                file_size = self.manifest["dst"][dst_entry]["size"]
                self.trace(f'{dst_entry} => {upper[dst_entry.upper()]}: {file_size:,} bytes')
                case_insensitive_size += file_size

        # determine what savings there would be with filename matching
        self.trace(f'Searching for potentially moved files...')
        src_filenames = {os.path.basename(entry.path): entry for entry in self.iterate_files('dst')}
        dst_filenames = {os.path.basename(entry.path): entry for entry in self.iterate_files('src')}
        moved_file_size = 0
        for (src_filename, src_entry) in src_filenames.items():
            if src_filename in dst_filenames:
                dst_entry = dst_filenames[src_filename]
                if src_entry.name != dst_entry.name:
                    self.trace(f'{src_entry.name} => {dst_entry.name}: {dst_entry.size:,} bytes')
                    moved_file_size += src_entry.size

        print(f'Case insensitive savings could be at most {case_insensitive_size:,} bytes')
        print(f'Moved file savings could be at most {moved_file_size:,} bytes')

    def trace(self, str):
        trace(self.verbose, str)

    def error(self, str):
        raise ValueError(str)


class ManifestEntry:
    def __init__(self, basedir, entry):
        self.name = os.path.relpath(entry.path, basedir)
        self.path = entry.path
        self.is_dir = entry.is_dir(follow_symlinks=False)
        self.is_file = not self.is_dir
        self.parse_stat(entry.stat(follow_symlinks=False))

    def parse_stat(self, stat_ret):
        self.mode = stat.S_IMODE(stat_ret.st_mode)
        self.uid = stat_ret.st_uid
        self.gid = stat_ret.st_gid
        self.size = stat_ret.st_size
        self.mtime = datetime.fromtimestamp(stat_ret.st_mtime).isoformat()


class XDelta3Patch:
    def __init__(self, dst_filename, pch_filename, zip):
        self.dst_filename = dst_filename
        self.pch_filename = pch_filename
        self.dst_sha1 = None
        self.pch_sha1 = None
        self.zip = zip


class XDelta3:
    def __init__(self, verbose, src_filename):
        self.verbose = verbose
        self.src_filename = src_filename
        self.src_sha1 = None
        self.src_size = None
        self.patches = []
        self.has_error = False

    def add_patch(self, patch):
        self.patches.append(patch)

    def generate_patches(self):
        # hash the source file, if there is one
        if self.src_filename:
            self.src_sha1 = perform_hash(self.verbose, self.src_filename)
        # generate all of the specified patches
        for patch in self.patches:
            # hash the destination file
            patch.dst_sha1 = perform_hash(self.verbose, patch.dst_filename)
            # if there is no source, copy the destination file directly
            if not self.src_filename:
                self.trace(f'Copying direct patch for {patch.dst_filename}...')
                self.update_pch_filename(patch, delta=False)
                with open(patch.dst_filename, "rb") as inpfile:
                    patch.pch_sha1 = self.atomic_replace_pipe(patch.pch_filename, inpfile.read(), zip=patch.zip)
            # otherwise, if the destination hash don't already match, create a patch
            elif self.src_sha1 != patch.dst_sha1:
                self.trace(f'Creating delta for {patch.dst_filename}...')
                self.update_pch_filename(patch, delta=True)
                command = [
                    "xdelta3", "-e", "-0", "-B", str(max(self.src_size, 1 * 1024 * 1024)), "-f", "-c",
                    "-s", self.src_filename, patch.dst_filename
                ]
                self.trace(' '.join(command))
                process = execute_pipe(command)
                patch.pch_sha1 = self.atomic_replace_pipe(patch.pch_filename, process.stdout.read(), zip=patch.zip)
        return self

    def update_pch_filename(self, patch, delta):
        # determine whether or not to apply zip
        if patch.zip == "bz2" and patch.pch_filename.endswith(".bz2"):
            patch.zip = None
        elif patch.zip == "gzip" and patch.pch_filename.endswith(".gz"):
            patch.zip = None
        patch.pch_filename = f'{patch.pch_filename}.xdelta3' if delta else patch.pch_filename
        patch.pch_filename = f'{patch.pch_filename}.gz' if patch.zip == "gzip" else patch.pch_filename
        patch.pch_filename = f'{patch.pch_filename}.bz2' if patch.zip == "bz2" else patch.pch_filename

    def apply_patches(self):
        # lazily hash source only once and only if/when necessary
        src_hash = None
        # process all of the patches
        for patch in self.patches:
            try:
                # check if dst already matches the manifest
                dst_hash = perform_hash(self.verbose, patch.dst_filename)
                if patch.dst_sha1 == dst_hash:
                    self.trace(f'Skipping already matching {patch.dst_filename}')
                    continue
                # validate source hash matches the manifest
                if not src_hash:
                    src_hash = perform_hash(self.verbose, self.src_filename)
                if self.src_sha1 != src_hash:
                    self.error(f'Hash mismatch for {self.src_filename}')
                # validate patch hash matches the manifest
                if patch.pch_filename:
                    pch_hash = perform_hash(self.verbose, patch.pch_filename)
                    if patch.pch_sha1 != pch_hash:
                        self.error(f'Hash mismatch for {patch.pch_filename}')
                    # patch the source file into the destination
                    self.trace(f'Patching {patch.pch_filename}...')
                    self.apply_xdelta3(patch)
                # copy patch file directly to destination
                else:
                    self.trace(f'Copying {self.src_filename}...')
                    with open(self.src_filename, "rb") as inpfile:
                        self.atomic_replace_pipe(patch.dst_filename, inpfile.read(), unzip=patch.zip)
            except:
                print(f'WARNING: Failed to apply patch: {sys.exc_info()[1]}')
                self.has_error = True
        return self

    def apply_xdelta3(self, patch):
        command = [
            "xdelta3", "-d", "-B", str(max(self.src_size, 1 * 1024 * 1024)), "-f", "-c",
            "-s", self.src_filename
        ]
        self.trace(' '.join(command))
        process = execute_pipe(command)
        if patch.zip == "bz2":
            inpfile = bz2.open(patch.pch_filename, "rb")
        elif patch.zip == "gzip":
            inpfile = gzip.open(patch.pch_filename, "rb")
        else:
            inpfile = open(patch.pch_filename, "rb")
        data = process.communicate(inpfile.read())[0]
        inpfile.close()
        self.atomic_replace_pipe(patch.dst_filename, data, sha1=patch.dst_sha1)

    def atomic_replace_pipe(self, dst, data, zip=False, unzip=False, sha1=None):
        tmp = f'{dst}.tmp'
        # copy pipe to temporary file while hashing its contents
        hash = hashlib.sha1()
        with open(tmp, 'wb') as outfile:
            data = bz2.compress(data) if zip == "bz2" else data
            data = gzip.compress(data) if zip == "gzip" else data
            data = bz2.decompress(data) if unzip == "bz2" else data
            data = gzip.decompress(data) if unzip == "gzip" else data
            hash.update(data)
            outfile.write(data)
            outfile.flush()
            os.fsync(outfile.fileno())
            outfile.close()
        # validate the digest
        digest = hash.hexdigest()
        if sha1 and sha1 != digest:
            self.error(f'Hash mismatch for {dst}!')
        # perform atomic replace of temporary file
        self.replace(tmp, dst)
        return digest

    def replace(self, src, dst):
        try:
            os.replace(src, dst)
        except PermissionError:
            os.chmod(dst, stat.S_IWRITE)
            os.replace(src, dst)

    def trace(self, text):
        if self.verbose:
            print(text)

    def error(self, str):
        raise ValueError(str)


def trace(verbose, text):
    if verbose:
        print(text)


def remove(filename):
    try:
        os.remove(filename)
    except FileNotFoundError:
        pass


def mkdir(dir, mode):
    try:
        os.mkdir(dir, mode=mode)
    except FileExistsError:
        pass


def makedirs(dir):
    os.makedirs(os.path.abspath(dir), exist_ok=True)


def execute_pipe(command):
    try:
        return subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f'{command}')
        print(f'{e.stdout}')
        raise


def perform_hash(verbose, filename):
    trace(verbose, f'Hashing {filename}...')
    hash = hashlib.sha1()
    try:
        with open(filename, 'rb') as inpfile:
            block = inpfile.read(io.DEFAULT_BUFFER_SIZE)
            while len(block) != 0:
                hash.update(block)
                block = inpfile.read(io.DEFAULT_BUFFER_SIZE)
        return hash.hexdigest()
    except:
        pass
    return ""


if __name__ == "__main__":
    # currently supported CLI commands
    commands = ["generate", "apply", "validate", "analyze"]
    # parse command-line arguments and execute the command
    arg_parser = argparse.ArgumentParser(
        description=description, formatter_class=argparse.RawTextHelpFormatter)
    arg_parser.add_argument(
        'command', nargs='?', choices=commands, default="generate", help='command')
    arg_parser.add_argument('-s', '--src', dest='src',
                            required=False, help='source directory')
    arg_parser.add_argument('-d', '--dst', dest='dst',
                            required=False, help='destination directory')
    arg_parser.add_argument('-p', '--patch', dest='pch',
                            required=True, help='patch directory')
    arg_parser.add_argument('-x', '--split', dest='split', default=[
                            'uasset', 'umap'], nargs="*", help='zero or more split file extensions')
    arg_parser.add_argument('-c', '--zip', dest='zip',
                            choices=["bz2", "gzip", "none"], default="bz2", help='patch file zip')
    arg_parser.add_argument('-e', '--stop-on-error', dest='stop_on_error',
                            action="store_true", help='stop patching files immediately after the first error')
    arg_parser.add_argument('-v', '--verbose', dest='verbose',
                            action="store_true", help='increase verbosity')
    args = arg_parser.parse_args()

    try:
        patch_tool = PatchTool(args.split, args.zip, args.stop_on_error, args.verbose)
        patch_tool.initialize(args.src, args.dst, args.pch)
        getattr(globals()['PatchTool'], args.command)(patch_tool)
        sys.exit(1 if patch_tool.has_error else 0)
    except KeyboardInterrupt:
        sys.exit(1)
