"""
progress_tracker.py - IDA Pro plugin to track reverse engineering progress.
Exports functions.csv, globals.csv, types.csv at each snapshot and diffs them.
"""

import os
import json
import time
import csv
from datetime import datetime
from pathlib import Path
import idaapi
import idc
import idautils
import ida_name
import ida_bytes
import ida_segment
import ida_funcs
import ida_ida
import ida_typeinf

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
DEBUG = True

# Get IDB directory
try:
    idb_path = idc.get_idb_path()
    if not idb_path:
        idb_path = os.path.join(idaapi.get_user_idadir(), "untitled")
except:
    idb_path = os.path.join(idaapi.get_user_idadir(), "untitled")
SNAPSHOT_DIR = os.path.join(os.path.dirname(idb_path), "progress_snapshots")
DATA_FILE = os.path.join(os.path.dirname(idb_path), "out/progress_data.json")


# ----------------------------------------------------------------------
# CSV Export Functions
# ----------------------------------------------------------------------
def export_functions_csv(output_path):
    """Export all functions: address, name, demangled_name (for reference)."""
    functions = []
    try:
        demangle_flags = ida_ida.get_inf_attr(ida_ida.INF_SHORT_DN)
    except:
        demangle_flags = 0

    for ea in idautils.Functions():
        raw_name = idc.get_func_name(ea)
        if not raw_name:
            raw_name = f"sub_{ea:X}"
        try:
            demangled = ida_name.demangle_name(raw_name, demangle_flags)
        except:
            demangled = raw_name
        functions.append((ea, raw_name, demangled or raw_name))

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["address", "name", "demangled"])
        for ea, name, demangled in functions:
            writer.writerow([f"0x{ea:X}", name, demangled])
    return len(functions)

# def export_types_csv(output_path):
#     """
#     Export all user-defined types (structs, unions, enums, typedefs) that have a name.
#     Uses type ID as the stable key. Output: type_id, name
#     """
#     types = []
#     til = ida_typeinf.get_idati()  # current type library
#     # Iterate through all types
#     for idx in range(ida_typeinf.get_number_types(til)):
#         typ = ida_typeinf.get_numbered_type(til, idx)
#         if typ is None:
#             continue
#         type_name = ida_typeinf.get_type_name(til, idx)
#         if not type_name:
#             continue
#         # Get the numeric type ID
#         type_id = idx  # the index is the ID
#         types.append((type_id, type_name))
#     with open(output_path, 'w', newline='', encoding='utf-8') as f:
#         writer = csv.writer(f)
#         writer.writerow(["type_id", "name"])
#         for tid, name in types:
#             writer.writerow([tid, name])
#     return len(types)

def export_globals_csv(output_path):
    """Export all global data items: address, name."""
    globals_data = []
    for ea in idautils.Heads():
        seg = ida_segment.getseg(ea)
        if seg:
            seg_name = ida_segment.get_segm_name(seg)
            if seg_name in {".text", ".code", ".plt", ".init", ".fini", "CODE"}:
                continue
        flags = ida_bytes.get_flags(ea)
        if not ida_bytes.is_data(flags):
            continue
        name = idc.get_name(ea)
        if not name:
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
        globals_data.append((ea, name))
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["address", "name"])
        for ea, name in globals_data:
            writer.writerow([f"0x{ea:X}", name])
    return len(globals_data)

def export_types_csv(output_path):
    """
    Export all local types to CSV using til.numbered_types() generator (IDA 9+).
    Output: type_id, name, declaration
    """
    types = []
    til = ida_typeinf.get_idati()
    if not til:
        print("[progress_tracker] No type library found.")
        return 0

    # numbered_types() returns a generator of tinfo_t objects
    for type_id, tif in enumerate(til.numbered_types(), start=1):
        if not tif:
            continue
        type_name = tif.get_type_name()
        if not type_name:
            continue
        type_decl = str(tif)
        types.append((type_id, type_name, type_decl))

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["type_id", "name", "declaration"])
        for tid, name, decl in types:
            writer.writerow([tid, name, decl])

    print(f"[progress_tracker] Exported {len(types)} types to {output_path}")
    return len(types)

# ----------------------------------------------------------------------
# Diff logic – pure CSV comparison
# ----------------------------------------------------------------------
def load_csv_dict(csv_path, key_col='address', name_col='name'):
    """Return dict {key: name}."""
    result = {}
    if not os.path.exists(csv_path):
        return result
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = row[key_col].strip()
            name = row[name_col].strip()
            result[key] = name
    return result

def compute_diff(old_dict, new_dict):
    """
    Compare two dicts (key -> name).
    Returns (renamed_count, new_count).
    renamed: key exists in both, names differ.
    new: key exists only in new_dict.
    """
    old_keys = set(old_dict.keys())
    new_keys = set(new_dict.keys())
    renamed = 0
    for key in old_keys & new_keys:
        if old_dict[key] != new_dict[key]:
            renamed += 1
            if DEBUG:
                print(f"[DEBUG] Renamed {key}: {old_dict[key]} -> {new_dict[key]}")
    new_items = len(new_keys - old_keys)
    return renamed, new_items

def take_snapshot(force_new_baseline=False):
    ensure_snapshot_dir()
    prev_ts = get_latest_snapshot_timestamp()
    
    now_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    func_path, global_path, type_path = get_snapshot_paths(now_ts)
    export_functions_csv(func_path)
    export_globals_csv(global_path)
    export_types_csv(type_path)
    
    if prev_ts is None or force_new_baseline:
        func_dict = load_csv_dict(func_path, 'address', 'name')
        global_dict = load_csv_dict(global_path, 'address', 'name')
        type_dict = load_csv_dict(type_path, 'type_id', 'name')
        entry = {
            "date": datetime.now().isoformat(),
            "timestamp": time.time(),
            "total_functions": len(func_dict),
            "total_globals": len(global_dict),
            "total_types": len(type_dict),
            "renamed_functions": 0,
            "renamed_globals": 0,
            "renamed_types": 0,
            "new_functions": 0,
            "new_globals": 0,
            "new_types": 0,
            "cumulative_renamed_functions": 0,
            "cumulative_renamed_globals": 0,
            "cumulative_renamed_types": 0,
            "snapshot": now_ts,
        }
        data = load_progress_data()
        data.append(entry)
        save_progress_data(data)
        print(f"[progress_tracker] Initial snapshot: funcs={len(func_dict)}, globals={len(global_dict)}, types={len(type_dict)}")
        return
    
    old_func, old_glob, old_type = load_snapshot(prev_ts)
    new_func = load_csv_dict(func_path, 'address', 'name')
    new_glob = load_csv_dict(global_path, 'address', 'name')
    new_type = load_csv_dict(type_path, 'type_id', 'name')
    
    func_ren, func_new = compute_diff(old_func, new_func)
    glob_ren, glob_new = compute_diff(old_glob, new_glob)
    type_ren, type_new = compute_diff(old_type, new_type)
    
    data = load_progress_data()
    last = data[-1] if data else None
    prev_cum_func = last["cumulative_renamed_functions"] if last else 0
    prev_cum_glob = last["cumulative_renamed_globals"] if last else 0
    prev_cum_type = last["cumulative_renamed_types"] if last else 0
    
    entry = {
        "date": datetime.now().isoformat(),
        "timestamp": time.time(),
        "total_functions": len(new_func),
        "total_globals": len(new_glob),
        "total_types": len(new_type),
        "renamed_functions": func_ren,
        "renamed_globals": glob_ren,
        "renamed_types": type_ren,
        "new_functions": func_new,
        "new_globals": glob_new,
        "new_types": type_new,
        "cumulative_renamed_functions": prev_cum_func + func_ren + func_new,
        "cumulative_renamed_globals": prev_cum_glob + glob_ren + glob_new,
        "cumulative_renamed_types": prev_cum_type + type_ren + type_new,
        "snapshot": now_ts,
    }
    data.append(entry)
    save_progress_data(data)
    print(f"[progress_tracker] Snapshot: renamed funcs={func_ren}, new funcs={func_new} (cum {entry['cumulative_renamed_functions']}), "
          f"globals: ren={glob_ren}, new={glob_new} (cum {entry['cumulative_renamed_globals']}), "
          f"types: ren={type_ren}, new={type_new} (cum {entry['cumulative_renamed_types']})")

# ----------------------------------------------------------------------
# Helper functions for snapshot paths and data management
# ----------------------------------------------------------------------
def ensure_snapshot_dir():
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)

def get_snapshot_paths(timestamp):
    base = os.path.join(SNAPSHOT_DIR, timestamp)
    return f"{base}_functions.csv", f"{base}_globals.csv", f"{base}_types.csv"

def load_snapshot(timestamp):
    func_path, global_path, type_path = get_snapshot_paths(timestamp)
    return (load_csv_dict(func_path, 'address', 'name'),
            load_csv_dict(global_path, 'address', 'name'),
            load_csv_dict(type_path, 'type_id', 'name'))

def get_latest_snapshot_timestamp():
    ensure_snapshot_dir()
    files = os.listdir(SNAPSHOT_DIR)
    timestamps = set()
    for f in files:
        if f.endswith("_functions.csv"):
            ts = f[:-len("_functions.csv")]
            timestamps.add(ts)
    if not timestamps:
        return None
    return max(timestamps)

def load_progress_data():
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)
    # Migration for old format (if needed)
    for entry in data:
        for key in ['cumulative_renamed_functions', 'cumulative_renamed_globals', 'cumulative_renamed_types']:
            if key not in entry:
                entry[key] = 0
    return data

def save_progress_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def init_snapshot():
    take_snapshot(force_new_baseline=True)

# ----------------------------------------------------------------------
# Plotting (matplotlib required)
# ----------------------------------------------------------------------
def plot_progress():
    try:
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
    except ImportError:
        print("[progress_tracker] matplotlib not installed. Cannot plot.")
        return

    data = load_progress_data()
    if len(data) < 2:
        print("[progress_tracker] Not enough snapshots to plot (need at least 2).")
        return

    dates = [datetime.fromisoformat(entry["date"]) for entry in data]
    renamed_funcs = [entry.get("cumulative_renamed_functions", 0) for entry in data]
    renamed_globals = [entry.get("cumulative_renamed_globals", 0) for entry in data]
    renamed_types = [entry.get("cumulative_renamed_types", 0) for entry in data]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(dates, renamed_funcs, marker='o', label='Functions Renamed')
    ax.plot(dates, renamed_globals, marker='s', label='Globals Renamed')
    ax.plot(dates, renamed_types, marker='^', label='Types Renamed')
    ax.set_ylabel('Cumulative Count')
    ax.set_xlabel('Date')
    ax.set_title('Reverse Engineering Progress – GOF2.exe')
    ax.legend()
    ax.grid(True, linestyle=':', alpha=0.6)
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
    fig.autofmt_xdate()
    plt.tight_layout()
    plot_path = os.path.join(idaapi.get_user_idadir(), "progress_graph.png")
    plt.savefig(plot_path, dpi=150)
    print(f"[progress_tracker] Graph saved to {plot_path}")
    plt.close()

# ----------------------------------------------------------------------
# IDA Actions & Plugin
# ----------------------------------------------------------------------
class InitSnapshotHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        init_snapshot()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_IDB

class TakeSnapshotHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        take_snapshot()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_IDB

class ShowGraphHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        plot_progress()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_IDB

class progress_tracker_plugin_t(idaapi.plugin_t):
    flags = 0
    comment = "Tracks RE progress via CSV diffs"
    help = "Edit -> Progress Tracker -> Init Snapshot / Take Snapshot / Show Graph"
    wanted_name = "Progress Tracker"
    wanted_hotkey = "Ctrl+Shift+P"

    def init(self):
        init_action = idaapi.action_desc_t("progress:init", "Init Snapshot (Baseline)", InitSnapshotHandler(), "Ctrl+Shift+I", "", 199)
        take_action = idaapi.action_desc_t("progress:take", "Take Snapshot", TakeSnapshotHandler(), "Ctrl+Shift+S", "", 199)
        graph_action = idaapi.action_desc_t("progress:graph", "Show Progress Graph", ShowGraphHandler(), "Ctrl+Shift+G", "", 199)
        idaapi.register_action(init_action)
        idaapi.register_action(take_action)
        idaapi.register_action(graph_action)

        idaapi.attach_action_to_menu("Edit/Progress Tracker/", "progress:init", idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu("Edit/Progress Tracker/", "progress:take", idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu("Edit/Progress Tracker/", "progress:graph", idaapi.SETMENU_APP)

        print("[progress_tracker] Plugin loaded. Use Edit -> Progress Tracker")
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.unregister_action("progress:init")
        idaapi.unregister_action("progress:take")
        idaapi.unregister_action("progress:graph")

    def run(self, arg):
        take_snapshot()

def PLUGIN_ENTRY():
    return progress_tracker_plugin_t()