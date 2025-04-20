#!/usr/bin/env python3
import sys
import json
import os


def main():
    if len(sys.argv) < 2:
        print("Usage: gen_compdb.py <source_file> [<source_file2> ...]")
        sys.exit(1)

    source_files = sys.argv[1:]
    entries = []

    # Create compilation database entries for all source files
    for source_file in source_files:
        entry = {
            "directory": os.path.dirname(os.path.abspath(source_file)),
            "file": source_file,
            "command": f"clang++ -c {source_file}",
        }
        entries.append(entry)

    # Output the compilation database as JSON
    print(json.dumps(entries, indent=2))


if __name__ == "__main__":
    main()
