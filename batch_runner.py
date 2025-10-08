import os
import json
import time
from binaryninja import PluginCommand, BinaryViewType
from mole.common.log import log
from mole.common.task import BackgroundTask


def init(path_ctr):
    """
    Initialize the batch runner with the shared path_ctr from the plugin.
    Registers a BN plugin command to run batch analysis.
    """

    class BatchRunnerTask(BackgroundTask):
        """
        Background task for running batch analysis to avoid freezing the UI.
        """

        def __init__(self, path_ctr):
            super().__init__("Running batch analysis...", True)
            self.path_ctr = path_ctr

        def run(self):
            """
            Run the batch processing in the background.
            """
            # Hardcoded paths for now
            BINARIES_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/CASTLE_repo/CASTLE-Benchmark/datasets/CASTLE-C250_binaries"
            OUTPUT_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/results_CASTLE"

            os.makedirs(OUTPUT_DIR, exist_ok=True)

            binary_files = [
                f
                for f in os.listdir(BINARIES_DIR)
                if os.path.isfile(os.path.join(BINARIES_DIR, f))
            ]
            total_files = len(binary_files)

            for i, fname in enumerate(binary_files):
                if self.cancelled:
                    log.info("BatchRunner", "Batch processing cancelled by user")
                    break

                self.progress = f"Processing {fname} ({i + 1}/{total_files})"
                fpath = os.path.join(BINARIES_DIR, fname)

                log.info("BatchRunner", f"Processing {fname} ({i + 1}/{total_files})")

                # Load binary in BN
                try:
                    bv = BinaryViewType["ELF"].open(fpath)
                    if not bv:
                        log.warn("BatchRunner", f"Could not open {fname}")
                        continue
                    bv.update_analysis_and_wait()
                except Exception as e:
                    log.error("BatchRunner", f"Failed to load {fname}: {e}")
                    continue

                try:
                    # Attach the BinaryView so path_ctr works
                    self.path_ctr._bv = bv

                    # Clear old paths before processing this binary
                    if self.path_ctr.path_tree_view:
                        cleared_count = self.path_ctr.path_tree_view.clear_all_paths()
                        log.info(
                            "BatchRunner", f"Cleared {cleared_count} existing path(s)"
                        )
                    else:
                        log.warn(
                            "BatchRunner", f"No PathTreeView available for {fname}"
                        )
                        continue

                    # Run Mole path finding
                    log.info("BatchRunner", f"Starting path finding for {fname}")
                    self.path_ctr.find_paths()

                    # Wait until path finding is finished
                    while not self.path_ctr.thread_finished:
                        if self.cancelled:
                            log.info(
                                "BatchRunner",
                                "Batch processing cancelled during path finding",
                            )
                            return
                        time.sleep(0.5)

                    log.info("BatchRunner", f"Path finding completed for {fname}")

                    # Verify path_tree_view is available
                    if not self.path_ctr.path_tree_view:
                        log.warn(
                            "BatchRunner",
                            f"No PathTreeView available after path finding for {fname}",
                        )
                        continue

                    # Get all path IDs from the model
                    path_ids = list(self.path_ctr.path_tree_view.model.path_ids)
                    if not path_ids:
                        log.info("BatchRunner", f"No paths found in {fname}")
                        # Still save an empty result file
                        out_file = os.path.join(OUTPUT_DIR, f"{fname}.json")
                        with open(out_file, "w") as fp:
                            json.dump([], fp, indent=2)
                        log.info("BatchRunner", f"Saved empty result to {out_file}")
                        continue

                    log.info("BatchRunner", f"Found {len(path_ids)} path(s) in {fname}")

                    # Run AI analysis on all paths
                    log.info(
                        "BatchRunner",
                        f"Starting AI analysis for {len(path_ids)} path(s)",
                    )
                    self.path_ctr.analyze_paths(path_ids)

                    # Wait until AI analysis finishes
                    while not self.path_ctr.thread_finished:
                        if self.cancelled:
                            log.info(
                                "BatchRunner",
                                "Batch processing cancelled during AI analysis",
                            )
                            return
                        time.sleep(0.5)

                    log.info("BatchRunner", f"AI analysis completed for {fname}")

                    # Collect results
                    results = []
                    for pid in path_ids:
                        try:
                            path = self.path_ctr.path_tree_view.get_path(pid)
                            if not path:
                                log.warn(
                                    "BatchRunner", f"Could not retrieve path {pid}"
                                )
                                continue

                            # Export path data using to_dict()
                            data = path.to_dict()

                            # Note: ai_report is already included in to_dict() output
                            # but we can also check and attach it explicitly if needed
                            if hasattr(path, "ai_report") and path.ai_report:
                                # to_dict() already includes ai_report, but this ensures it's there
                                if "ai_report" not in data or data["ai_report"] is None:
                                    data["ai_report"] = path.ai_report.to_dict()

                            results.append(data)
                        except Exception as e:
                            log.error(
                                "BatchRunner", f"Failed to export path {pid}: {e}"
                            )
                            continue

                    # Save JSON report
                    out_file = os.path.join(OUTPUT_DIR, f"{fname}.json")
                    with open(out_file, "w") as fp:
                        json.dump(results, fp, indent=2)

                    log.info(
                        "BatchRunner", f"Saved {len(results)} path(s) to {out_file}"
                    )

                except Exception as e:
                    log.error("BatchRunner", f"Error processing {fname}: {e}")
                finally:
                    # Explicit cleanup
                    try:
                        if bv:
                            bv.file.close()
                            del bv
                    except Exception as e:
                        log.error("BatchRunner", f"Error closing {fname}: {e}")

            if not self.cancelled:
                log.info("BatchRunner", "Batch processing completed!")

    def run_batch(bv=None):
        """
        Start the batch runner as a background task.
        """
        log.info("BatchRunner", "Starting batch processing in background...")
        task = BatchRunnerTask(path_ctr)
        task.start()

    # Register command in BN
    PluginCommand.register(
        "Mole\\Batch Run CASTLE",
        "Run Find Paths + AI Analysis + Save JSON reports (Background)",
        run_batch,
    )
