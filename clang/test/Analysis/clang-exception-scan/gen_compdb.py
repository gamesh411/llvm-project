#!/usr/bin/env python3
import sys
import json
import os
import argparse


def main():
    parser = argparse.ArgumentParser(description="Generate a JSON compilation database.")
    parser.add_argument(
        "source_files",
        metavar="SOURCE_FILE",
        nargs='+',
        help="Source file(s) to include in the database.",
    )

    args = parser.parse_args()

    entries = []

    # Create compilation database entries for all source files
    for source_file in args.source_files:
        # Ensure the source file path is absolute for consistency
        abs_source_file = os.path.abspath(source_file)
        directory = os.path.dirname(abs_source_file)

        # Base command
        command = f"clang++ -c {abs_source_file}"

        # Add include path for the directory containing the source file
        # This allows includes relative to the source file, like "Inputs/...".
        command += f" -I{directory}"

        entry = {
            "directory": directory,
            "file": abs_source_file,
            "command": command,
        }
        entries.append(entry)

    # Output the compilation database as JSON
    print(json.dumps(entries, indent=2))


if __name__ == "__main__":
    main()
