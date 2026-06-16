#!/usr/bin/env python3
"""
generate_hook_code.py
Reads functions.csv and globals.csv, uses Jinja2 templates to produce:
- hook_table.inc
- globals.h
- (optional) functions.h

Usage:
    py -3 generate_hook_code.py --functions-csv functions.csv --globals-csv globals.csv
"""

import csv
import sys
from pathlib import Path

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    print("[-] Jinja2 not installed. Run: pip install jinja2", file=sys.stderr)
    sys.exit(1)

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def default_global_type(name: str) -> str:
    name_lower = name.lower()
    if name_lower.startswith("byte"):
        return "unsigned char"
    if name_lower.startswith("word"):
        return "uint16_t"
    if name_lower.startswith("dword"):
        return "uint32_t"
    if name_lower.startswith("qword"):
        return "uint64_t"
    if name_lower.startswith("flt"):
        return "float"
    if name_lower.startswith("dbl"):
        return "double"
    if name_lower.startswith("off") or name_lower.startswith("unk"):
        return "uintptr_t"
    return "uintptr_t"

def address_to_identifier(addr: str) -> str:
    clean = addr.replace('0x', '').replace('0X', '')
    return f"sub_{clean}"

def read_functions_csv(csv_path: Path) -> list:
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            addr = row['address'].strip()
            rows.append({
                'address': addr,
                'raw_name': row.get('raw_name', '').strip(),
                'demangled': row.get('demangled_name', '').strip(),
                'identifier': address_to_identifier(addr)
            })
        return rows

def read_globals_csv(csv_path: Path) -> list:
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            rows.append({
                'address': row['address'].strip(),
                'name': row['name'].strip(),
                'default_type': default_global_type(row['name'].strip())
            })
        return rows

def render_templates(template_dir: Path, output_dir: Path,
                     functions_csv: Path, globals_csv: Path,
                     generate_functions_h: bool = False) -> None:
    """Render all templates using Jinja2."""
    env = Environment(loader=FileSystemLoader(template_dir),
                      trim_blocks=True, lstrip_blocks=True)

    # Load functions data if available
    functions = []
    if functions_csv.exists():
        functions = read_functions_csv(functions_csv)

    # Load globals data
    globals_data = []
    if globals_csv.exists():
        globals_data = read_globals_csv(globals_csv)

    # Render hook_table.inc (requires functions)
    if functions:
        template = env.get_template("hook_table.inc.jinja")
        output = template.render(functions=functions)
        (output_dir / "hook_table.inc").write_text(output, encoding='utf-8')
        print(f"[✓] Generated hook_table.inc with {len(functions)} functions")
    else:
        print("[!] No functions.csv found, skipping hook_table.inc")

    # Render globals.h
    if globals_data:
        template = env.get_template("globals.h.jinja")
        output = template.render(globals=globals_data)
        (output_dir / "globals.h").write_text(output, encoding='utf-8')
        print(f"[✓] Generated globals.h with {len(globals_data)} globals")
    else:
        print("[!] No globals.csv found, skipping globals.h")

    # Optionally render functions.h
    if generate_functions_h and functions:
        template = env.get_template("functions.h.jinja")
        output = template.render(functions=functions)
        (output_dir / "functions.h").write_text(output, encoding='utf-8')
        print(f"[✓] Generated functions.h with {len(functions)} placeholders")

# ----------------------------------------------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate decompilation helper files from IDA CSVs")
    parser.add_argument("--functions-csv", default="functions.csv", help="Path to functions.csv")
    parser.add_argument("--globals-csv", default="globals.csv", help="Path to globals.csv")
    parser.add_argument("--template-dir", default="templates", help="Directory containing .jinja templates")
    parser.add_argument("--output-dir", default="generated", help="Output directory for generated files")
    parser.add_argument("--generate-functions-h", action="store_true", help="Also generate functions.h")
    args = parser.parse_args()

    template_dir = Path(args.template_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not template_dir.exists():
        print(f"[-] Template directory '{template_dir}' not found.", file=sys.stderr)
        sys.exit(1)

    render_templates(template_dir, output_dir,
                     Path(args.functions_csv), Path(args.globals_csv),
                     args.generate_functions_h)

if __name__ == "__main__":
    main()