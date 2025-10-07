import os  # Standard library: filesystem ops like listdir, path join, mkdir
import json  # Standard library: write results to JSON files

from binaryninja import BinaryViewType, PluginCommand
# Binary Ninja API
# BinaryViewType opens a binary and gives you a BinaryView handle
# PluginCommand lets you add a menu entry in BN’s Plugins menu

from mole.controllers.path import run_analysis_with_ai
# Mole entrypoint inside your plugin that runs path discovery and then the AI analysis per path

# --- Your paths ---
BINARIES_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/CASTLE_repo/CASTLE-Benchmark/datasets/CASTLE-C250_binaries"
# Absolute folder where your compiled CASTLE binaries live

OUTPUT_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/results_CASTLE"
# Absolute folder where per binary JSON reports will be written

dataset = "CASTLE"

os.makedirs(OUTPUT_DIR, exist_ok=True)
# Ensure the output directory exists. If it already exists, do nothing


def run_batch_mole(bv=None):
    """
    Batch-process all binaries in BINARIES_DIR using Mole+AI
    and save JSON reports to OUTPUT_DIR.
    """
    # Binary Ninja passes a BinaryView when a command is run from the UI
    # We do not use that view since we open each file ourselves

    for fname in os.listdir(BINARIES_DIR):
        # Iterate every directory entry in your binaries folder

        fpath = os.path.join(BINARIES_DIR, fname)
        # Build the absolute path to the current entry

        if not os.path.isfile(fpath):
            continue
        # Skip subfolders and non files

        print(f"[+] Analyzing {fname} ...")
        # Simple progress message in BN’s log console

        try:
            bv = BinaryViewType.get_view_of_file(fpath)
            # Open the file in Binary Ninja and create a BinaryView
            # BN will auto analyze lazily. If you ever need to block until ready, you can call:
            # bv.update_analysis_and_wait()

            results = run_analysis_with_ai(bv)
            # Hand the BinaryView to Mole’s analyzer that
            # 1 finds source to sink paths
            # 2 runs the LLM on each path
            # Returns a Python object suitable for JSON, usually a dict with per path AI reports

            outpath = os.path.join(OUTPUT_DIR, f"{fname}.json")
            # Decide where to save this binary’s report

            with open(outpath, "w") as f:
                json.dump(results, f, indent=2)
            # Persist the Mole plus AI result to a JSON file

            print(f"    -> Saved report to {outpath}")
            # Confirmation

        except Exception as e:
            print(f"[!] Error analyzing {fname}: {e}")
            # Any failure on a single file is logged. The loop continues to the next file


# Register command inside BN Plugins menu
PluginCommand.register(
    "Mole\\Batch Run {dataset}",
    # This is exactly how it will appear in Plugins → Mole → Batch Run CASTLE
    "Run Mole+AI on all {dataset}) binaries and save reports",
    # One line help text in the menu
    run_batch_mole,
    # The function that runs when you click the menu item
)
