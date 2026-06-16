#!/usr/bin/env python3
"""
coverage_check.py
Parses hook_table.inc to count how many hooks have been implemented
(detour != nullptr). Also lists unhooked functions.

Usage:
    py -3 coverage_check.py --hook-table hook_table.inc
"""

import re
import sys
from pathlib import Path

def parse_hook_table(file_path: Path):
    """Parse hook_table.inc and return list of (address, detour_expr, comment) for each entry."""
    content = file_path.read_text(encoding='utf-8')
    # Pattern matches lines like: { 0x00401000, nullptr },  // raw: sub_401000
    # Or: { 0x00401000, &Game::Function }, // ...
    pattern = r'\{\s*(0x[0-9A-Fa-f]+)\s*,\s*([^}]+?)\s*\},?\s*//\s*(.*)'
    matches = re.findall(pattern, content)
    entries = []
    for addr, detour, comment in matches:
        detour = detour.strip()
        # Remove trailing comma if any (safe)
        if detour.endswith(','):
            detour = detour[:-1]
        entries.append({
            'address': addr,
            'detour': detour,
            'comment': comment.strip(),
            'hooked': detour != 'nullptr'
        })
    return entries

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Check hook coverage from hook_table.inc")
    parser.add_argument("--hook-table", default="hook_table.inc", help="Path to hook_table.inc")
    parser.add_argument("--verbose", "-v", action="store_true", help="List all unhooked functions")
    args = parser.parse_args()

    hook_table_path = Path(args.hook_table)
    if not hook_table_path.exists():
        print(f"[-] File not found: {hook_table_path}", file=sys.stderr)
        sys.exit(1)

    entries = parse_hook_table(hook_table_path)
    if not entries:
        print("[-] No hook entries found in file.", file=sys.stderr)
        sys.exit(1)

    total = len(entries)
    hooked = sum(1 for e in entries if e['hooked'])
    coverage = (hooked / total) * 100 if total else 0

    print(f"Total functions: {total}")
    print(f"Hooked: {hooked}")
    print(f"Coverage: {coverage:.2f}%")

    if args.verbose and hooked < total:
        print("\nUnhooked functions (detour = nullptr):")
        for e in entries:
            if not e['hooked']:
                # Show address and comment (contains raw name / demangled info)
                print(f"  {e['address']} -> {e['comment']}")

if __name__ == "__main__":
    main()