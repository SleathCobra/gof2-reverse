#!/usr/bin/env python3
"""
generate_progress_graphs.py
Reads progress_data.json and creates three separate hand‑drawn graphs:
- functions.png (renamed/added functions over time)
- globals.png   (renamed/added globals over time)
- types.png     (renamed/added types over time)
"""

import json
import os
import argparse
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

# Font fallback to avoid warnings
plt.rcParams['font.family'] = ['Comic Neue', 'Comic Sans MS', 'Arial']

def load_progress_data(data_file):
    if not os.path.exists(data_file):
        raise FileNotFoundError(f"Progress data file not found: {data_file}")
    with open(data_file, 'r') as f:
        return json.load(f)

def format_date(date_str):
    return datetime.fromisoformat(date_str)

def generate_single_graph(dates, values, title, ylabel, output_path, color, marker):
    """Generate one xkcd‑style graph with explicit x‑axis ticks at each snapshot."""
    if len(dates) < 2:
        print(f"Skipping {title}: need at least 2 snapshots.")
        return

    with plt.xkcd():
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(dates, values, marker=marker, linestyle='-', linewidth=2,
                color=color, markersize=6)

        # Y‑axis: integer ticks only
        ax.yaxis.set_major_locator(MaxNLocator(integer=True))
        ax.set_ylabel(ylabel)

        # X‑axis: set ticks exactly at each snapshot's datetime
        ax.set_xticks(dates)
        # Determine label format based on time span
        span_seconds = (max(dates) - min(dates)).total_seconds()
        if span_seconds < 86400:  # less than 1 day → show time as well
            fmt = '%b %d %H:%M'
        else:
            fmt = '%b %d'
        labels = [dt.strftime(fmt) for dt in dates]
        ax.set_xticklabels(labels, rotation=45, ha='right')

        ax.set_title(title, fontsize=12, fontweight='bold')
        ax.grid(True, linestyle=':', alpha=0.5)

        plt.tight_layout()
        plt.savefig(output_path, dpi=150)
        plt.close()
        print(f"Saved: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Generate three progress graphs.")
    parser.add_argument("--data-file", default=None,
                        help="Path to progress_data.json (default: IDA user dir)")
    parser.add_argument("--output-dir", default=".",
                        help="Directory to save PNG files (default: current dir)")
    args = parser.parse_args()

    if args.data_file is None:
        ida_user_dir = os.path.expanduser("~/AppData/Roaming/Hex-Rays/IDA Pro")
        data_file = os.path.join(ida_user_dir, "progress_data.json")
    else:
        data_file = args.data_file

    try:
        data = load_progress_data(data_file)
    except Exception as e:
        print(f"Error loading data: {e}")
        return

    if len(data) < 2:
        print("Need at least 2 snapshots to plot.")
        return

    data.sort(key=lambda x: x['timestamp'])
    dates = [format_date(entry["date"]) for entry in data]
    funcs = [entry.get("cumulative_renamed_functions", 0) for entry in data]
    globs = [entry.get("cumulative_renamed_globals", 0) for entry in data]
    types = [entry.get("cumulative_renamed_types", 0) for entry in data]

    os.makedirs(args.output_dir, exist_ok=True)

    generate_single_graph(dates, funcs, "Analyzed   Functions",
                          "",
                          os.path.join(args.output_dir, "functions.png"),
                          "#1f77b4", 'o')
    generate_single_graph(dates, globs, "Analyzed   Globals",
                          "",
                          os.path.join(args.output_dir, "globals.png"),
                          "#ff7f0e", 's')
    generate_single_graph(dates, types, "Reversed    Structures",
                          "",
                          os.path.join(args.output_dir, "types.png"),
                          "#2ca02c", '^')

if __name__ == "__main__":
    main()