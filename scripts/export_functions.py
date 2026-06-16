import idautils
import idc
import ida_name  # <-- CHANGE: Use ida_name instead of idaapi
import csv

def demangle_name(ea):
    """Get demangled name using get_ea_name, which is widely supported."""
    # flags: GN_DEMANGLED | GN_SHORT | GN_VISIBLE
    flags = ida_name.GN_DEMANGLED | ida_name.GN_SHORT | ida_name.GN_VISIBLE
    demangled = ida_name.get_ea_name(ea, flags)
    return demangled if demangled else idc.get_func_name(ea)

def main():
    functions = []
    for ea in idautils.Functions():
        raw_name = idc.get_func_name(ea)
        if not raw_name:
            raw_name = f"sub_{ea:X}"
        demangled = demangle_name(ea)
        functions.append((ea, raw_name, demangled))

    with open("functions.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["address", "raw_name", "demangled_name"])
        for ea, raw, demangled in functions:
            writer.writerow([f"0x{ea:X}", raw, demangled])

    print(f"[+] Exported {len(functions)} functions to functions.csv")

if __name__ == "__main__":
    main()