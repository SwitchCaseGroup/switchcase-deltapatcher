#
# file: delta-patcher.py
# desc: generates and applies binary delta patches
# 

import argparse
import os

class DeltaPatcher:
    # currently supported CLI commands
    commands = [ "generate", "apply" ]

    def __init__(self):
        # parse command-line arguments and execute the command
        arg_parser = argparse.ArgumentParser(description='Generate and apply binary delta patches', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        arg_parser.add_argument('command', nargs='?', choices=self.commands, default="generate", help='command')
        arg_parser.add_argument('-s', '--src', dest='src', required=True, help='input source directory')
        arg_parser.add_argument('-d', '--dst', dest='dst', required=True, help='input destination directory')
        arg_parser.add_argument('-o', '--out', dest='out', required=True, help='output patch directory')
        arg_parser.add_argument('-p', '--pat', dest='pattern', nargs="*", help='zero or more merge patterns')
        self.args = arg_parser.parse_args()
        self.src = os.path.abspath(self.args.src)
        self.dst = os.path.abspath(self.args.dst)
        self.out = os.path.abspath(self.args.out)
        getattr(globals()['DeltaPatcher'], self.args.command)(self)

    def generate(self):
        self.manifest = { entry for entry in self.find_files(self.src) }
        for entry in self.manifest:
            print(entry)

    def find_files(self, path):
        if not os.path.isfile(path):
            for current in os.listdir(path):
                yield from self.find_files(os.path.join(path, current))
        else:
            yield path

    def apply(self):
        print("apply");


if __name__ == "__main__":
    delta_patcher = DeltaPatcher()
