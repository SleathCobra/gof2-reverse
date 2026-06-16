=> Initial snapshot with 0 changes : (used to compare for progress against baseline)

`functions.csv` -> functions: address, name, demangled_name 
`globals.csv` -> globals: address, name, demangled_name

=> IDA Pro progress on reverse engineering:

`progress_data.json` -> list of snapshots with: date, timestamp, total_functions, total_globals, total_types, renamed_functions, renamed_globals, renamed_types, new_functions, new_globals, new_types, cumulative_renamed_functions, cumulative_renamed_globals, cumulative_renamed_types

`progress_snapshots` (not included because too heavy) -> snapshots with: functions.csv, globals.csv, types.csv

=> Progress tracking:

`progress_tracker.py` -> IDA Pro plugin to track reverse engineering progress.