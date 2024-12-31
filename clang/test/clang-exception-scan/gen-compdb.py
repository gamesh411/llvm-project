#!/usr/bin/env python3

import argparse
import json
import os
import sys

def main():
    parser = argparse.ArgumentParser(description='Generate compilation database')
    parser.add_argument('files', nargs='+', help='Source files')
    parser.add_argument('-I', dest='includes', action='append', default=[],
                       help='Include paths')
    args = parser.parse_args()

    db = []
    for src in args.files:
        abs_path = os.path.abspath(src)
        entry = {
            'directory': os.path.dirname(abs_path),
            'file': abs_path,
            'arguments': ['clang++', '-c', src] + ['-I' + i for i in args.includes],
            'output': os.path.splitext(src)[0] + '.o'
        }
        db.append(entry)

    json.dump(db, sys.stdout, indent=2)

if __name__ == '__main__':
    main() 