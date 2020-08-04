#
# file: patchtool.py
# desc: Binary delta patching tool
#

import multiprocessing
import subprocess
import argparse
import hashlib
import shutil
import json
import sys
import os
import io

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

'''


class PatchTool:
    def __init__(self, split, verbose):
        self.split = split
        self.verbose = verbose
        self.manifest = defaultdict(dict)
        self.pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())

    def initialize(self, src, dst, pch):
        self.src = src
        self.dst = dst
        self.pch = pch
        self.src_files = {}
        self.dst_files = {}
        self.pch_files = {}
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
                setattr(self, f'{dir}_files', {entry.name: entry for entry in self.scantree(directory, directory)})

    def generate(self):
        # cleanup the patch directory
        self.trace(f'Cleaning {self.pch}...')
        shutil.rmtree(self.pch, ignore_errors=True)
        makedirs(self.pch)

        # populate manifest and create patch subdirectories
        for entry in self.src_files.values():
            self.manifest['src'][entry.name] = {
                'uid': entry.uid,
                'gid': entry.gid,
                'mode': entry.mode
            }
        for entry in self.dst_files.values():
            self.manifest['dst'][entry.name] = {
                'uid': entry.uid,
                'gid': entry.gid,
                'mode': entry.mode
            }
            if entry.is_dir:
                makedirs(os.path.join(self.pch, entry.name))

        # perform patch generation in parallel and process the results as they arrive
        for xdelta3 in self.pool.imap_unordered(XDelta3.generate_patches, self.generate_queue()):
            # handle caught exception in subprocess
            if xdelta3.exception:
                self.error(xdelta3.exception)
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
                    # update manifest with patch manifest
                    pch_filename = os.path.relpath(
                        patch.pch_filename, self.pch)
                    self.manifest['pch'][pch_filename] = {
                        'sha1': patch.pch_sha1}
                    # if this patch is a delta, update manifest with the delta's hash
                    if xdelta3.src_filename:
                        self.manifest['src'][src_filename]['xdelta3'][dst_filename] = pch_filename
            # cleanup empty manifest entries
            if xdelta3.src_filename and len(self.manifest['src'][src_filename]['xdelta3']) == 0:
                del self.manifest['src'][src_filename]['xdelta3']
                if src_filename not in self.manifest['dst']:
                    del self.manifest['src'][src_filename]

        # write the manifest file
        self.trace(f'Writing manifest...')
        with open(os.path.join(self.pch, 'manifest.json'), 'w') as outfile:
            json.dump(self.manifest, outfile, indent=4)

    def generate_queue(self):
        # search for modified files and queue patches for them
        self.trace(f'Creating deltas for modified files...')
        for (src, dsts) in self.generate_map():
            # create deltas relative to this source file
            xdelta3 = XDelta3(self.verbose, src.path)
            # iterate through our destination files, looking for matches
            for dst in dsts:
                self.trace(f'Matched destination {dst.name}')
                # mark this dst as having been queued for processing already
                self.manifest['dst'][dst.name]['sha1'] = ''
                # generate xdelta3 if the files don't already match
                pch_name = f'{dst.name}.xdelta3'
                abs_dst_filename = os.path.join(self.dst, dst.name)
                abs_pch_filename = os.path.join(self.pch, pch_name)
                xdelta3.add_patch(XDelta3Patch(
                    abs_dst_filename, abs_pch_filename))
            yield xdelta3

        # search for files without a source and queue patches for them
        self.trace(f'Copying added files...')
        for dst in [dst for dst in self.iterate_files('dst') if 'sha1' not in self.manifest['dst'][dst.name]]:
            pch_filename = os.path.join(self.pch, dst.name)
            xdelta3 = XDelta3(self.verbose, None)
            xdelta3.add_patch(XDelta3Patch(dst.path, pch_filename))
            yield xdelta3

    def generate_map(self):
        map = defaultdict(list)
        for dst_entry in self.iterate_files('dst'):
            extension = dst_entry.name.rfind('.')
            if extension != -1:
                map[dst_entry.name[:extension]].append(dst_entry)
                continue
            map[dst_entry.name].append(dst_entry)
        for src_entry in self.iterate_files('src'):
            extension = src_entry.name.rfind('.')
            if extension != -1 and src_entry.name[extension + 1:] in self.split:
                dsts = map[src_entry.name[:extension]]
                if len(dsts):
                    yield (src_entry, dsts)
            elif src_entry.name in self.dst_files:
                yield (src_entry, [src_entry])
        return map

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
            # handle caught exception in subprocess
            if xdelta3.exception:
                self.error(xdelta3.exception)

        # perform patching in parallel (dependencies)
        for xdelta3 in self.pool.imap_unordered(XDelta3.apply_patches, self.apply_queue(True)):
            # handle caught exception in subprocess
            if xdelta3.exception:
                self.error(xdelta3.exception)

        # apply file properties
        self.trace(f'Applying file properties...')
        for (name, entry) in self.iterate_manifest('dst'):
            dst_filename = os.path.join(self.dst, name)
            os.chmod(dst_filename, entry['mode'])
            os.chown(dst_filename, entry['uid'], entry['gid'])

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
            xdelta3 = XDelta3(
                self.verbose, os.path.join(self.src, src_filename))
            xdelta3.src_sha1 = src_entry['sha1']
            for dst_filename, pch_filename in src_entry.get('xdelta3', {}).items():
                abs_dst_filename = os.path.join(self.dst, dst_filename)
                if sources == (src_filename == dst_filename):
                    abs_pch_filename = os.path.join(self.pch, pch_filename)
                    patch = XDelta3Patch(abs_dst_filename, abs_pch_filename)
                    patch.dst_sha1 = self.manifest['dst'][dst_filename]['sha1']
                    patch.pch_sha1 = self.manifest['pch'][pch_filename]['sha1']
                    xdelta3.add_patch(patch)
            if src_filename in self.manifest['dst'] and src_entry['sha1'] == self.manifest['dst'][src_filename]['sha1']:
                if sources:
                    abs_dst_filename = os.path.join(self.dst, src_filename)
                    xdelta3.add_patch(XDelta3Patch(abs_dst_filename, None))
            yield xdelta3

        # search for files which need to be copied from patch dir
        for (pch_filename, _) in self.iterate_manifest('pch'):
            if pch_filename in self.manifest['dst']:
                abs_dst_filename = os.path.join(self.dst, pch_filename)
                abs_pch_filename = os.path.join(self.pch, pch_filename)
                xdelta3 = XDelta3(self.verbose, abs_pch_filename)
                xdelta3.src_sha1 = self.manifest['pch'][pch_filename]['sha1']
                xdelta3.add_patch(XDelta3Patch(abs_dst_filename, None))
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

    def scantree(self, basedir, path):
        try:
            for entry in os.scandir(path):
                yield ManifestEntry(basedir, entry)
                if entry.is_dir(follow_symlinks=False):
                    yield from self.scantree(basedir, entry.path)
        except FileNotFoundError:
            pass

    def find_dirs(self, path):
        try:
            if os.path.exists(path):
                if not os.path.isfile(path):
                    yield path
                    for current in os.listdir(path):
                        yield from self.find_dirs(os.path.join(path, current))
        except FileNotFoundError:
            pass

    def generate_hashes(self, manifest, dirs):
        # queue the hashes
        queue = [entry.path for dir in dirs for entry in self.iterate_files(dir)]
        # perform hashes in parallel
        tasks = list(self.pool.imap(
            partial(perform_hash, self.verbose), queue))
        # retrieve results in same order as queued
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
        self.generate_hashes(local_manifest, ['src', 'dst'])

        # validate against manifest and local src files
        self.validate_manifest(local_manifest)
        self.validate_src(local_manifest)

    def validate_manifest(self, local_manifest):
        # validate all manifest src files exist in dst and hashes match
        for (src_filename, _) in self.iterate_manifest('dst'):
            if src_filename not in self.dst_files:
                self.error(f'{src_filename}: missing from {self.dst}')
            if local_manifest['dst'][src_filename]['sha1'] != self.manifest['dst'][src_filename]['sha1']:
                self.error(f'{src_filename}: manifest sha1 mismatch!')

        # validate all dst files exist in manifest src
        for dst_entry in self.dst_files.values():
            if dst_entry.name not in self.manifest['dst']:
                self.error(f'{dst_entry.name}: missing from manifest!')

    def validate_src(self, local_manifest):
        # skip if local src is not available
        if not self.src:
            return

        # validate all src files exist in dst and hashes match
        for src_entry in self.src_files.values():
            if src_entry.name not in self.dst_files:
                self.error(f'{src_entry.name}: missing from {self.dst}')
            dst_entry = self.dst_files[src_entry.name]
            for attr in ['is_dir', 'uid', 'gid', 'mode']:
                src_attr = getattr(src_entry, attr)
                dst_attr = getattr(dst_entry, attr)
                if src_attr != dst_attr:
                    self.error(f'{src_entry.name}: {attr}={src_attr}, {self.dst}: {attr}={dst_attr}')
            if src_entry.is_file and local_manifest['src'][src_entry.name]['sha1'] != local_manifest['dst'][src_entry.name]['sha1']:
                self.error(f'{src_entry.name}: src/dst sha1 mismatch!')

        # validate all dst files exist in src
        for dst_entry in self.dst_files.values():
            if dst_entry.name not in self.src_files:
                self.error(f'{dst_entry.name}: missing from {self.src}')

    def trace(self, str):
        trace(self.verbose, str)

    def error(self, str):
        # flush the old pool which could have lingering subprocesses
        self.pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
        raise ValueError(str)


class ManifestEntry:
    def __init__(self, basedir, entry):
        self.name = os.path.relpath(entry.path, basedir)
        self.path = entry.path
        self.is_dir = entry.is_dir(follow_symlinks=False)
        self.is_file = not self.is_dir
        self.parse_stat(entry.stat(follow_symlinks=False))

    def parse_stat(self, stat):
        self.mode = stat.st_mode
        self.uid = stat.st_uid
        self.gid = stat.st_gid


class XDelta3Patch:
    def __init__(self, dst_filename, pch_filename):
        self.dst_filename = dst_filename
        self.pch_filename = pch_filename
        self.dst_sha1 = None
        self.pch_sha1 = None


class XDelta3:
    def __init__(self, verbose, src_filename):
        self.verbose = verbose
        self.src_filename = src_filename
        self.src_sha1 = None
        self.patches = []
        self.exception = None

    def trace(self, text):
        if self.verbose:
            print(text)

    def error(self, str):
        raise ValueError(str)

    def add_patch(self, patch):
        self.patches.append(patch)

    def generate_patches(self):
        try:
            # hash the source file
            if self.src_filename:
                self.src_sha1 = perform_hash(self.verbose, self.src_filename)
            # process all of the potential patches
            for patch in self.patches:
                # hash the destination file
                patch.dst_sha1 = perform_hash(self.verbose, patch.dst_filename)
                # only apply patches when there's a source who's hash doesn't match destination
                if self.src_filename and self.src_sha1 != patch.dst_sha1:
                    # create the xdelta3 patch file
                    self.trace(f'Creating delta for {patch.dst_filename}...')
                    command = [
                        "xdelta3", "-e", "-9", "-f",
                        "-s", self.src_filename, patch.dst_filename, patch.pch_filename
                    ]
                    self.trace(' '.join(command))
                    execute(command)
                    # hash the patch file
                    patch.pch_sha1 = perform_hash(
                        self.verbose, patch.pch_filename)
                # if there is no source, copy the file itself as the patch
                elif not self.src_filename:
                    atomic_replace(patch.dst_filename, patch.pch_filename)
                    patch.pch_sha1 = patch.dst_sha1
        except:
            self.exception = str(sys.exc_info())
        return self

    def apply_xdelta3(self, src_filename, dst_filename, pch_filename):
        tmp_filename = f'{dst_filename}.patched'
        # apply xdelta3 patch to temporary file
        command = [
            "xdelta3", "-d", "-f",
            "-s", src_filename, pch_filename, tmp_filename
        ]
        self.trace(' '.join(command))
        execute(command)
        # perform atomic file copy/replace
        atomic_replace(tmp_filename, dst_filename)
        # remove temporary file
        remove(tmp_filename)

    def apply_patches(self):
        try:
            # lazily hash source only once and only if/when necessary
            src_hash = None
            # process all of the patches
            for patch in self.patches:
                # check if dst already matches
                dst_hash = perform_hash(self.verbose, patch.dst_filename)
                if patch.dst_sha1 == dst_hash:
                    self.trace(f'Skipping already matching {patch.dst_filename}')
                    continue
                # validate source hash
                if not src_hash:
                    src_hash = perform_hash(self.verbose, self.src_filename)
                if self.src_sha1 != src_hash:
                    self.error(f'Hash mismatch for {self.src_filename} {patch.dst_sha1} {dst_hash}, {self.src_sha1}, {src_hash}')
                # validate patch hash
                if patch.pch_filename:
                    pch_hash = perform_hash(self.verbose, patch.pch_filename)
                    if patch.pch_sha1 != pch_hash:
                        self.error(f'Hash mismatch for {patch.pch_filename}')
                    # apply the patch
                    self.apply_xdelta3(self.src_filename,
                                       patch.dst_filename, patch.pch_filename)
                # copy file directly
                else:
                    self.trace(f'Copying {self.src_filename}...')
                    atomic_replace(self.src_filename, patch.dst_filename)
        except:
            self.exception = str(sys.exc_info())

        return self


def trace(verbose, text):
    if verbose:
        print(text)


def remove(filename):
    try:
        if os.path.exists(filename):
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


def execute(command):
    try:
        subprocess.check_output(command, universal_newlines=True)
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


def atomic_replace(src, dst):
    tmp = f'{dst}.tmp'
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


if __name__ == "__main__":
    # currently supported CLI commands
    commands = ["generate", "apply", "validate"]
    # parse command-line arguments and execute the command
    arg_parser = argparse.ArgumentParser(
        description=description, formatter_class=argparse.RawTextHelpFormatter)
    arg_parser.add_argument(
        'command', nargs='?', choices=commands, default="generate", help='command')
    arg_parser.add_argument('-s', '--src', dest='src',
                            required=False, help='source directory')
    arg_parser.add_argument('-d', '--dst', dest='dst',
                            required=True, help='destination directory')
    arg_parser.add_argument('-p', '--patch', dest='pch',
                            required=True, help='patch directory')
    arg_parser.add_argument('-x', '--split', dest='split', default=[
                            'uasset', 'umap'], nargs="*", help='zero or more split file extensions')
    arg_parser.add_argument('-v', '--verbose', dest='verbose',
                            action="store_true", help='increase verbosity')
    args = arg_parser.parse_args()
    patch_tool = PatchTool(args.split, args.verbose)
    patch_tool.initialize(args.src, args.dst, args.pch)
    getattr(globals()['PatchTool'], args.command)(patch_tool)
