"""
export_globals.py
Exports all global data items from non‑code segments to globals.csv.
Uses IDA's data item iteration to capture default labels.

Usage:
    IDA PRO -> File -> Script file...
"""

import idautils
import idc
import ida_bytes
import ida_segment
import csv

def is_code_segment(ea: int) -> bool:
    seg = ida_segment.getseg(ea)
    if not seg:
        return False
    seg_name = ida_segment.get_segm_name(seg)
    code_sections = {".text", ".code", ".plt", ".init", ".fini", "CODE"}
    return seg_name in code_sections

def main():
    data_items = []
    for ea in idautils.Heads():
        if is_code_segment(ea):
            continue
        flags = ida_bytes.get_flags(ea)
        if not ida_bytes.is_data(flags):
            continue
        name = idc.get_name(ea)
        if not name:
            # generate fallback name based on size
            size = ida_bytes.get_item_size(ea)
            if size == 1:
                name = f"byte_{ea:X}"
            elif size == 2:
                name = f"word_{ea:X}"
            elif size == 4:
                name = f"dword_{ea:X}"
            elif size == 8:
                name = f"qword_{ea:X}"
            elif ida_bytes.is_float(flags):
                name = f"flt_{ea:X}"
            elif ida_bytes.is_double(flags):
                name = f"dbl_{ea:X}"
            else:
                name = f"unk_{ea:X}"
        data_items.append((ea, name))

    with open("globals.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["address", "name"])
        for ea, name in data_items:
            writer.writerow([f"0x{ea:X}", name])

    print(f"[+] Exported {len(data_items)} global data items to globals.csv")

if __name__ == "__main__":
    main()