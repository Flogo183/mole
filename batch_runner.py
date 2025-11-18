import os
import json
import time
from datetime import datetime
from binaryninja import PluginCommand, BinaryViewType
from mole.common.log import log
from mole.common.task import BackgroundTask


class LogCapture:
    """Simple log capture for debugging no-paths cases"""

    def __init__(self):
        self.logs = []
        self.original_log_methods = {}

    def start_capture(self):
        """Start capturing log messages"""
        self.logs = []

        # Store original methods
        self.original_log_methods = {
            "debug": log.debug,
            "info": log.info,
            "warn": log.warn,
            "error": log.error,
        }

        # Replace with capturing methods
        log.debug = lambda module, message: self._capture_and_forward(
            "DEBUG", module, message
        )
        log.info = lambda module, message: self._capture_and_forward(
            "INFO", module, message
        )
        log.warn = lambda module, message: self._capture_and_forward(
            "WARNING", module, message
        )
        log.error = lambda module, message: self._capture_and_forward(
            "ERROR", module, message
        )

    def stop_capture(self):
        """Stop capturing and restore original methods"""
        if not self.original_log_methods:
            return

        try:
            for level, original_method in self.original_log_methods.items():
                setattr(log, level, original_method)
        except Exception as e:
            print(f"Warning: Could not restore log methods: {e}")

    def _capture_and_forward(self, level, module, message):
        """Capture and forward log message"""
        # Store the log
        self.logs.append(
            {
                "timestamp": datetime.now().isoformat(),
                "level": level,
                "module": module,
                "message": message,
            }
        )

        # Forward to original
        original_method = self.original_log_methods.get(level.lower())
        if original_method:
            try:
                original_method(module, message)
            except Exception:
                print(f"[{level}] [{module}] {message}")

    def get_logs(self):
        """Get all captured logs"""
        return self.logs.copy()

    def get_debug_summary(self):
        """Get all captured logs as formatted strings, filtering noisy entries"""
        filtered = []
        seen = set()
        for entry in self.logs:
            msg = entry.get("message", "")
            # Drop noisy cross-reference scans
            if "finding code cross-references" in msg.lower():
                continue
            line = f"[{entry.get('level')}] [{entry.get('module')}] {msg}"
            # Avoid exact duplicates to keep logs compact
            if line in seen:
                continue
            seen.add(line)
            filtered.append(line)
        return filtered


def load_source_sink_mapping(json_path):
    """
    Load the JSON mapping file that defines which sources/sinks to use for each binary.

    Args:
        json_path: Path to the JSON mapping file

    Returns:
        dict: Mapping of binary names (without extension) to sources/sinks

    Expected JSON format:
    {
      "binary_name_01": {
        "sources": ["recv"],
        "sinks": ["memcpy"]
      },
      "binary_name_02": {
        "sources": ["fgets"],
        "sinks": ["system"]
      }
    }
    """
    try:
        with open(json_path, "r") as f:
            mapping = json.load(f)
        log.info(
            "BatchRunner",
            f"Loaded source/sink mapping for {len(mapping)} binaries from {json_path}",
        )
        return mapping
    except FileNotFoundError:
        log.error("BatchRunner", f"Mapping file not found: {json_path}")
        return None
    except json.JSONDecodeError as e:
        log.error("BatchRunner", f"Invalid JSON in mapping file: {e}")
        return None
    except Exception as e:
        log.error("BatchRunner", f"Error loading mapping file: {e}")
        return None


def apply_source_sink_filter(config_model, source_functions=None, sink_functions=None):
    """
    Disable all sources/sinks in the config, then enable only the specified ones.
    This modifies the config_model in-place, just like Binary Ninja's UI does.

    Args:
        config_model: The ConfigModel to modify
        source_functions: List of source function names to enable (e.g., ['recv', 'fread'])
        sink_functions: List of sink function names to enable (e.g., ['memcpy', 'strcpy'])

    Example:
        apply_source_sink_filter(config_model, ['recv'], ['memcpy'])
    """
    # Get all functions using the same API that Binary Ninja UI uses
    all_sources = config_model.get_functions(fun_type="Sources")
    all_sinks = config_model.get_functions(fun_type="Sinks")

    # Disable ALL sources
    for func in all_sources:
        func.enabled = False

    # Disable ALL sinks
    for func in all_sinks:
        func.enabled = False

    # Enable only the specified sources
    if source_functions:
        for func in all_sources:
            if func.name in source_functions:
                func.enabled = True
                log.info("BatchRunner", f"Enabled source: {func.name}")

    # Enable only the specified sinks
    if sink_functions:
        for func in all_sinks:
            if func.name in sink_functions:
                func.enabled = True
                log.info("BatchRunner", f"Enabled sink: {func.name}")


def init(path_ctr):
    """
    Initialize the batch runner with the shared path_ctr from the plugin.
    Registers a BN plugin command to run batch analysis.
    """

    class BatchRunnerTask(BackgroundTask):
        """
        Background task for running batch analysis to avoid freezing the UI.
        """

        def __init__(self, path_ctr, source_sink_mapping):
            super().__init__("Running batch analysis...", True)
            self.path_ctr = path_ctr
            self.log_capture = LogCapture()  # Initialize log capture
            self.source_sink_mapping = source_sink_mapping

        def run(self):
            """
            Run the batch processing in the background.
            """
            # Hardcoded paths for now
            BINARIES_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/CASTLE_repo/CASTLE-Benchmark/datasets/CASTLE-C250_binariesV2"
            OUTPUT_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/results_CASTLE/results_CASTLE_model_o4-mini_run2"

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
                    # Initialize log capture variable
                    captured_logs = []

                    # === CUSTOM CONFIG: Enable only specific sources/sinks for this binary ===
                    # Look up source/sink mapping in JSON by filename (without extension)
                    base_fname = os.path.splitext(fname)[0]  # Remove extension

                    # Save the current enabled state of all functions (always save)
                    config_model = self.path_ctr.config_ctr.config_model
                    saved_states = {}

                    # Save current state of all sources
                    for func in config_model.get_functions(fun_type="Sources"):
                        saved_states[("source", func.name)] = func.enabled

                    # Save current state of all sinks
                    for func in config_model.get_functions(fun_type="Sinks"):
                        saved_states[("sink", func.name)] = func.enabled

                    if base_fname in self.source_sink_mapping:
                        # Found in JSON - use specific sources/sinks
                        mapping = self.source_sink_mapping[base_fname]
                        sources = mapping.get("sources", [])
                        sinks = mapping.get("sinks", [])

                        log.info(
                            "BatchRunner",
                            f"Found mapping for {base_fname} - Sources: {sources}, Sinks: {sinks}",
                        )

                        # Apply the filter (disable all, enable only specified)
                        apply_source_sink_filter(config_model, sources, sinks)
                        log.info(
                            "BatchRunner", f"Applied source/sink filter for {fname}"
                        )
                    else:
                        # Not found in JSON - enable ALL sources and ALL sinks
                        log.info(
                            "BatchRunner",
                            f"No mapping found for {base_fname} in JSON - enabling ALL sources and sinks",
                        )

                        all_sources = config_model.get_functions(fun_type="Sources")
                        all_sinks = config_model.get_functions(fun_type="Sinks")

                        # Enable ALL sources
                        for func in all_sources:
                            func.enabled = True

                        # Enable ALL sinks
                        for func in all_sinks:
                            func.enabled = True

                        log.info(
                            "BatchRunner",
                            f"Enabled {len(all_sources)} sources and {len(all_sinks)} sinks for {fname}",
                        )

                    # Attach the BinaryView so path_ctr works
                    self.path_ctr._bv = bv

                    # Clear old paths before processing this binary (CRITICAL: prevents path merging)
                    if self.path_ctr.path_tree_view:
                        cleared_count = self.path_ctr.path_tree_view.clear_all_paths()
                        log.info(
                            "BatchRunner",
                            f"Cleared {cleared_count} existing path(s) before processing {fname}",
                        )
                        # Force a small delay to ensure clearing is complete
                        time.sleep(0.1)
                    else:
                        log.warn(
                            "BatchRunner", f"No PathTreeView available for {fname}"
                        )
                        continue

                    # Run Mole path finding with log capture
                    log.info("BatchRunner", f"Starting path finding for {fname}")

                    # Start capturing logs for debugging no-paths cases
                    self.log_capture.start_capture()

                    self.path_ctr.find_paths()

                    # Wait until path finding is finished
                    while not self.path_ctr.thread_finished:
                        if self.cancelled:
                            log.info(
                                "BatchRunner",
                                "Batch processing cancelled during path finding",
                            )
                            self.log_capture.stop_capture()
                            return
                        time.sleep(0.5)

                    # Stop log capture and get captured logs
                    self.log_capture.stop_capture()
                    captured_logs = self.log_capture.get_logs()

                    # Debug: Log how many entries we captured
                    log.info(
                        "BatchRunner",
                        f"Captured {len(captured_logs)} log entries during path finding",
                    )

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

                        # Collect information about sources and sinks actually detected in this binary
                        detected_sources = []
                        detected_sinks = []

                        try:
                            from mole.common.helper.symbol import SymbolHelper

                            # Get configured source functions and check which are in the binary
                            src_funs = (
                                self.path_ctr.config_ctr.config_model.get_functions(
                                    fun_type="Sources", fun_enabled=True
                                )
                            )
                            for src_fun in src_funs:
                                code_refs = SymbolHelper.get_code_refs(
                                    bv, src_fun.symbols
                                )
                                for symbol_name, refs in code_refs.items():
                                    if refs:  # If there are actual code references to this symbol
                                        detected_sources.append(symbol_name)

                            # Get configured sink functions and check which are in the binary
                            snk_funs = (
                                self.path_ctr.config_ctr.config_model.get_functions(
                                    fun_type="Sinks", fun_enabled=True
                                )
                            )
                            for snk_fun in snk_funs:
                                code_refs = SymbolHelper.get_code_refs(
                                    bv, snk_fun.symbols
                                )
                                for symbol_name, refs in code_refs.items():
                                    if refs:  # If there are actual code references to this symbol
                                        detected_sinks.append(symbol_name)

                        except Exception as e:
                            log.warn(
                                "BatchRunner",
                                f"Could not retrieve detected source/sink info: {e}",
                            )

                        # Remove duplicates and sort for consistency
                        detected_sources = sorted(list(set(detected_sources)))
                        detected_sinks = sorted(list(set(detected_sinks)))

                        # Create informative result even when no paths found
                        no_paths_result = {
                            "binary_file": fname,  # Binary name first for better organization
                            "status": "no_paths_detected",
                            "detected_sources": detected_sources
                            if detected_sources
                            else ["none_detected"],
                            "detected_sinks": detected_sinks
                            if detected_sinks
                            else ["none_detected"],
                            "message": f"No vulnerability paths detected between sources and sinks in {fname}",
                        }

                        # Still save the informative result
                        out_file = os.path.join(OUTPUT_DIR, f"{fname}.json")
                        with open(out_file, "w") as fp:
                            json.dump([no_paths_result], fp, indent=2)
                        log.info("BatchRunner", f"Saved no-paths info to {out_file}")

                        # Save debug logs for no-paths case
                        if captured_logs:
                            debug_log_data = {
                                "binary_file": fname,
                                "status": "debug_logs_no_paths",
                                "analysis_timestamp": time.strftime(
                                    "%Y-%m-%d %H:%M:%S"
                                ),
                                "detected_sources": detected_sources,
                                "detected_sinks": detected_sinks,
                                "debug_logs": self.log_capture.get_debug_summary(),
                                "log_statistics": {
                                    "total_log_entries": len(captured_logs),
                                    "log_levels": {
                                        level: sum(
                                            1
                                            for log_entry in captured_logs
                                            if log_entry.get("level") == level
                                        )
                                        for level in [
                                            "DEBUG",
                                            "INFO",
                                            "WARNING",
                                            "ERROR",
                                        ]
                                    },
                                    "capture_status": "enabled"
                                    if len(captured_logs) > 0
                                    else "no_logs_captured",
                                },
                            }

                            debug_log_file = os.path.join(
                                OUTPUT_DIR, f"{fname}_debug_logs.json"
                            )
                            with open(debug_log_file, "w") as fp:
                                json.dump(debug_log_data, fp, indent=2)
                            log.info(
                                "BatchRunner", f"Saved debug logs to {debug_log_file}"
                            )

                        # Clear any potential leftover paths even in no-paths case
                        if self.path_ctr.path_tree_view:
                            cleared_count = (
                                self.path_ctr.path_tree_view.clear_all_paths()
                            )
                            if cleared_count > 0:
                                log.info(
                                    "BatchRunner",
                                    f"No-paths cleanup: cleared {cleared_count} unexpected path(s) for {fname}",
                                )
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

                    # Check captured logs for AI analysis errors
                    ai_errors = {}
                    for log_entry in captured_logs:
                        msg = log_entry.get("message", "")
                        module = log_entry.get("module", "")

                        # Check for AI analysis failures
                        if module == "Mole.AI" and (
                            "Failed to send messages" in msg
                            or "No response received" in msg
                        ):
                            # Extract path ID from message like "[Path:1]"
                            import re

                            path_match = re.search(r"\[Path:(\d+)\]", msg)
                            if path_match:
                                path_id = int(path_match.group(1))
                                if path_id not in ai_errors:
                                    ai_errors[path_id] = []
                                ai_errors[path_id].append(
                                    {
                                        "level": log_entry.get("level"),
                                        "message": msg,
                                        "timestamp": log_entry.get("timestamp"),
                                    }
                                )

                    # Collect results with simplified output
                    results = []
                    for pid in path_ids:
                        try:
                            path = self.path_ctr.path_tree_view.get_path(pid)
                            if not path:
                                log.warn(
                                    "BatchRunner", f"Could not retrieve path {pid}"
                                )
                                continue

                            # Create simplified path data with AI report
                            simplified_data = {
                                "binary_file": fname,  # Binary name first for better organization and safety
                                "path_id": pid,
                                "source": {
                                    "function": path.src_sym_name,
                                    "address": hex(path.src_sym_addr),
                                    "parameter_index": path.src_par_idx,
                                },
                                "sink": {
                                    "function": path.snk_sym_name,
                                    "address": hex(path.snk_sym_addr),
                                    "parameter_index": path.snk_par_idx,
                                },
                                "comment": path.comment if path.comment else None,
                            }

                            # Calculate path structural complexity metrics
                            import math

                            num_instructions = (
                                len(path.insts) if hasattr(path, "insts") else 0
                            )
                            num_phi_calls = (
                                len(path.phiis) if hasattr(path, "phiis") else 0
                            )
                            num_branches = (
                                len(path.bdeps) if hasattr(path, "bdeps") else 0
                            )

                            # Composite metric: D = 0.6*log(1+B) + 0.3*log(1+Φ) + 0.1*log(1+I)
                            # B = branches, Φ = phi calls, I = instructions
                            complexity_score = (
                                0.5 * math.log(1 + num_branches)
                                + 0.3 * math.log(1 + num_phi_calls)
                                + 0.2 * math.log(1 + num_instructions)
                            )

                            simplified_data["path_complexity"] = {
                                "instructions": num_instructions,
                                "phi_calls": num_phi_calls,
                                "branches": num_branches,
                                "structural_complexity_score": round(
                                    complexity_score, 4
                                ),
                            }

                            # Include AI report if available
                            if hasattr(path, "ai_report") and path.ai_report:
                                ai_data = {
                                    "truePositive": path.ai_report.truePositive,
                                    "vulnerabilityClass": str(
                                        path.ai_report.vulnerabilityClass
                                    )
                                    if hasattr(path.ai_report, "vulnerabilityClass")
                                    else None,
                                    "shortExplanation": path.ai_report.shortExplanation,
                                    "severityLevel": str(path.ai_report.severityLevel)
                                    if hasattr(path.ai_report, "severityLevel")
                                    else None,
                                    "inputExample": path.ai_report.inputExample,
                                    "path_id": path.ai_report.path_id,
                                    "model": path.ai_report.model,
                                    "Convesation turns": path.ai_report.turns,
                                    "tool_calls": path.ai_report.tool_calls,
                                    "tools_used": path.ai_report.tools_used
                                    if hasattr(path.ai_report, "tools_used")
                                    else [],  # Add specific tools
                                    "prompt_tokens": path.ai_report.prompt_tokens,
                                    "completion_tokens": path.ai_report.completion_tokens,
                                    "total_tokens": path.ai_report.total_tokens,
                                    "temperature": path.ai_report.temperature,
                                    "timestamp": path.ai_report.timestamp.isoformat()
                                    if hasattr(path.ai_report.timestamp, "isoformat")
                                    else str(path.ai_report.timestamp),
                                }
                                simplified_data["ai_report"] = ai_data
                            else:
                                simplified_data["ai_report"] = None

                            # Include AI analysis errors if any occurred for this path
                            if pid in ai_errors:
                                simplified_data["ai_analysis_errors"] = ai_errors[pid]
                            else:
                                simplified_data["ai_analysis_errors"] = None

                            results.append(simplified_data)
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

                    # Clear paths after saving to prevent merging with next binary
                    if self.path_ctr.path_tree_view:
                        cleared_count = self.path_ctr.path_tree_view.clear_all_paths()
                        log.info(
                            "BatchRunner",
                            f"Post-processing cleanup: cleared {cleared_count} path(s) for {fname}",
                        )

                except Exception as e:
                    log.error("BatchRunner", f"Error processing {fname}: {e}")

                    # Ensure log capture is stopped even on error
                    try:
                        self.log_capture.stop_capture()
                    except Exception:
                        pass

                finally:
                    # Restore original enabled/disabled states (always restore)
                    try:
                        if "saved_states" in locals() and saved_states:
                            config_model = self.path_ctr.config_ctr.config_model

                            # Restore sources
                            for func in config_model.get_functions(fun_type="Sources"):
                                key = ("source", func.name)
                                if key in saved_states:
                                    func.enabled = saved_states[key]

                            # Restore sinks
                            for func in config_model.get_functions(fun_type="Sinks"):
                                key = ("sink", func.name)
                                if key in saved_states:
                                    func.enabled = saved_states[key]

                            log.info(
                                "BatchRunner", "Restored original source/sink states"
                            )
                    except Exception as e:
                        log.warn(
                            "BatchRunner", f"Could not restore original states: {e}"
                        )

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
        # Path to JSON mapping file
        JSON_MAPPING_PATH = "/Users/flaviogottschalk/dev/BachelorArbeit/Source_Sink_mappings/castle_source_sink_mapping.json"

        # Check if JSON file exists
        if not os.path.exists(JSON_MAPPING_PATH):
            log.error(
                "BatchRunner", f"JSON mapping file not found: {JSON_MAPPING_PATH}"
            )
            log.error("BatchRunner", "Cannot proceed without source/sink mapping file")
            from binaryninja import interaction

            interaction.show_message_box(
                "Missing Mapping File",
                f"JSON mapping file not found:\n{JSON_MAPPING_PATH}\n\nPlease create the mapping file before running batch analysis.",
                buttons=interaction.MessageBoxButtonSet.OKButtonSet,
            )
            return

        # Load the source/sink mapping from JSON
        source_sink_mapping = load_source_sink_mapping(JSON_MAPPING_PATH)
        if not source_sink_mapping:
            log.error("BatchRunner", "Failed to load source/sink mapping - aborting")
            return

        log.info("BatchRunner", "Starting batch processing in background...")
        task = BatchRunnerTask(path_ctr, source_sink_mapping)
        task.start()

    # Register command in BN
    PluginCommand.register(
        "Mole\\Batch Run CASTLE",
        "Run Find Paths + AI Analysis + Save JSON reports (Background)",
        run_batch,
    )
