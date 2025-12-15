#!/usr/bin/env python3
"""
Quick script to check which JSON files still have missing AI reports.
"""

import os
import json
import sys


def check_json_file(filepath):
    """Check a single JSON file for missing reports."""
    try:
        with open(filepath, "r") as f:
            data = json.load(f)

        if not isinstance(data, list):
            return None, "Not a list"

        missing_paths = []
        for item in data:
            if "path_id" in item and (
                "ai_report" not in item or item["ai_report"] is None
            ):
                missing_paths.append(item["path_id"])

        return missing_paths, None
    except Exception as e:
        return None, str(e)


def main():
    if len(sys.argv) < 2:
        print("Usage: python check_missing_reports.py <directory_containing_jsons>")
        print("   or: python check_missing_reports.py <file1.json> <file2.json> ...")
        sys.exit(1)

    files_to_check = []

    # Check if first arg is a directory
    if len(sys.argv) == 2 and os.path.isdir(sys.argv[1]):
        directory = sys.argv[1]
        files_to_check = [
            os.path.join(directory, f)
            for f in os.listdir(directory)
            if f.endswith(".json")
        ]
    else:
        # Individual files
        files_to_check = sys.argv[1:]

    print(f"Checking {len(files_to_check)} JSON files...\n")

    files_with_missing = []

    for filepath in sorted(files_to_check):
        if not os.path.exists(filepath):
            print(f"❌ {os.path.basename(filepath)}: File not found")
            continue

        missing_paths, error = check_json_file(filepath)

        if error:
            print(f"⚠️  {os.path.basename(filepath)}: Error - {error}")
        elif missing_paths:
            print(
                f"🔴 {os.path.basename(filepath)}: {len(missing_paths)} missing report(s) - Path IDs: {missing_paths}"
            )
            files_with_missing.append((os.path.basename(filepath), missing_paths))
        else:
            print(f"✅ {os.path.basename(filepath)}: All reports present")

    print(f"\n{'=' * 60}")
    print(f"Summary: {len(files_with_missing)} file(s) still have missing reports")

    if files_with_missing:
        print("\nFiles with missing reports:")
        for filename, path_ids in files_with_missing:
            print(f"  - {filename}: {path_ids}")


if __name__ == "__main__":
    main()
