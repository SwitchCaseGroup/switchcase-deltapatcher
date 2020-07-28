#
# file: delta-patcher.py
# desc: generates and applies binary delta patches
# 

import argparse

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
        getattr(globals()['DeltaPatcher'], self.args.command)(self)

    def generate(self):
        print(f'src: {self.args.src}');
        print(f'dst: {self.args.dst}');
        print(f'out: {self.args.out}');
        print(f'pattern: {self.args.pattern}');

    def appl(self):
        print("apply");


if __name__ == "__main__":
    delta_patcher = DeltaPatcher()
