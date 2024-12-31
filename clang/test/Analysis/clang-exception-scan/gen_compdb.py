#!/usr/bin/env python3
import sys
import json
import os


def main():
    if len(sys.argv) < 2:
        print("Usage: gen_compdb.py <source_file>")
        sys.exit(1)

    source_file = sys.argv[1]

    # Create a compilation database entry
    entry = {
        "directory": os.path.dirname(os.path.abspath(source_file)),
        "file": source_file,
        "command": f"clang++ -c {source_file}",
    }

    # Output the compilation database as JSON
    print(json.dumps([entry], indent=2))


if __name__ == "__main__":
    main()
