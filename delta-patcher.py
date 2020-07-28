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
        arg_parser.add_argument('-s', '--src', dest='src_dir', required=True, help='input source directory')
        arg_parser.add_argument('-d', '--dst', dest='dst_dir', required=True, help='input destination directory')
        arg_parser.add_argument('-p', '--patch', dest='patch_dir', required=True, help='output patch directory')
        self.args = arg_parser.parse_args()
        getattr(globals()['DeltaPatcher'], self.args.command)(self)

    def generate(self):
        print("generate");

    def appl(self):
        print("apply");


if __name__ == "__main__":
    delta_patcher = DeltaPatcher()
