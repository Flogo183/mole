import os
import json
import time
from datetime import datetime
from binaryninja import PluginCommand, load, interaction
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
      "CWE121_test_01": {
        "sources": ["gets"],
        "sinks": ["memcpy"]
      },
      "CWE78_test_02": {
        "sources": ["recv"],
        "sinks": ["system"]
      }
    }
    """
    try:
        with open(json_path, "r") as f:
            mapping = json.load(f)
        log.info(
            "JulietBatchRunner",
            f"Loaded source/sink mapping for {len(mapping)} binaries from {json_path}",
        )
        return mapping
    except FileNotFoundError:
        log.error("JulietBatchRunner", f"Mapping file not found: {json_path}")
        return None
    except json.JSONDecodeError as e:
        log.error("JulietBatchRunner", f"Invalid JSON in mapping file: {e}")
        return None
    except Exception as e:
        log.error("JulietBatchRunner", f"Error loading mapping file: {e}")
        return None


def apply_source_sink_filter(config_model, source_functions=None, sink_functions=None):
    """
    Disable all sources/sinks in the config, then enable only the specified ones.
    This modifies the config_model in-place, just like Binary Ninja's UI does.

    Args:
        config_model: The ConfigModel to modify
        source_functions: List of source function names to enable (e.g., ['gets', 'fread'])
        sink_functions: List of sink function names to enable (e.g., ['memcpy', 'strcpy'])

    Example:
        apply_source_sink_filter(config_model, ['gets'], ['memcpy'])
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
        available_sources = {func.name for func in all_sources}
        for source_name in source_functions:
            if source_name in available_sources:
                for func in all_sources:
                    if func.name == source_name:
                        func.enabled = True
                        log.info("JulietBatchRunner", f"Enabled source: {func.name}")
                        break
            else:
                log.warn(
                    "JulietBatchRunner",
                    f"Source '{source_name}' not found in YAML configs",
                )

    # Enable only the specified sinks
    if sink_functions:
        available_sinks = {func.name for func in all_sinks}
        for sink_name in sink_functions:
            if sink_name in available_sinks:
                for func in all_sinks:
                    if func.name == sink_name:
                        func.enabled = True
                        log.info("JulietBatchRunner", f"Enabled sink: {func.name}")
                        break
            else:
                log.warn(
                    "JulietBatchRunner", f"Sink '{sink_name}' not found in YAML configs"
                )


def init(path_ctr):
    """
    Initialize the Juliet batch runner with the shared path_ctr from the plugin.
    Registers a BN plugin command to run batch analysis on Juliet test suite.
    """

    class JulietBatchRunnerTask(BackgroundTask):
        """
        Background task for running batch analysis on Juliet test suite.
        Expected structure:
        extracted_binaries/
            Top50/
                CWE121/
                    good/
                        binary1
                        binary2
                    bad/
                        binary3
                        binary4
                CWE122/
                    good/
                    bad/
            Top100/
                CWE121/
                ...
            Top150/
                ...
        """

        def __init__(self, path_ctr, target_cwe, source_sink_mapping):
            super().__init__(f"Running Juliet batch analysis for {target_cwe}...", True)
            self.path_ctr = path_ctr
            self.log_capture = LogCapture()
            self.target_cwe = target_cwe
            self.source_sink_mapping = source_sink_mapping

            # Save the ORIGINAL config state once at initialization
            # This prevents state pollution between binaries
            config_model = self.path_ctr.config_ctr.config_model
            self.original_states = {}

            # Save original state of all sources
            for func in config_model.get_functions(fun_type="Sources"):
                self.original_states[("source", func.name)] = func.enabled

            # Save original state of all sinks
            for func in config_model.get_functions(fun_type="Sinks"):
                self.original_states[("sink", func.name)] = func.enabled

            log.info(
                "JulietBatchRunner",
                f"Saved original state: {len([k for k in self.original_states.keys() if k[0] == 'source'])} sources, "
                f"{len([k for k in self.original_states.keys() if k[0] == 'sink'])} sinks",
            )

        def process_binary(self, fpath, fname, output_dir):
            """
            Process a single binary file.
            Returns True if successful, False otherwise.
            """
            log.info("JulietBatchRunner", f"Processing {fname}")

            # Load binary in BN - auto-detect format (ELF or PE)
            try:
                # Use load() function which auto-detects the binary format
                bv = load(fpath)
                if not bv:
                    log.warn("JulietBatchRunner", f"Could not open {fname}")
                    return False
                bv.update_analysis_and_wait()
                log.info("JulietBatchRunner", f"Loaded {fname} as {bv.view_type}")
            except Exception as e:
                log.error("JulietBatchRunner", f"Failed to load {fname}: {e}")
                return False

            try:
                # Initialize log capture variable
                captured_logs = []

                # === CUSTOM CONFIG: Enable only specific sources/sinks for this binary ===
                # Look up source/sink mapping in JSON by filename (keeping extension)
                # Use fname directly (e.g., "CWE78_...bad.out")

                # Get config model
                config_model = self.path_ctr.config_ctr.config_model

                # Check if we're using JSON mapping mode (dict with entries) or enable-all mode (empty dict)
                if (
                    len(self.source_sink_mapping) > 0
                    and fname in self.source_sink_mapping
                ):
                    # JSON mapping mode: Found specific mapping for this binary
                    mapping = self.source_sink_mapping[fname]
                    sources = mapping.get("sources", [])
                    sinks = mapping.get("sinks", [])

                    log.info(
                        "JulietBatchRunner",
                        f"Found mapping for {fname} - Sources: {sources}, Sinks: {sinks}",
                    )

                    # Apply the filter (disable all, enable only specified)
                    apply_source_sink_filter(config_model, sources, sinks)
                    log.info(
                        "JulietBatchRunner", f"Applied source/sink filter for {fname}"
                    )

                    # DEBUG: Log what's actually enabled after filter
                    enabled_sources = [
                        f.name
                        for f in config_model.get_functions(fun_type="Sources")
                        if f.enabled
                    ]
                    enabled_sinks = [
                        f.name
                        for f in config_model.get_functions(fun_type="Sinks")
                        if f.enabled
                    ]
                    log.info(
                        "JulietBatchRunner",
                        f"DEBUG - Actually enabled sources: {enabled_sources}",
                    )
                    log.info(
                        "JulietBatchRunner",
                        f"DEBUG - Actually enabled sinks: {enabled_sinks}",
                    )
                else:
                    # Enable-all mode OR binary not found in JSON - enable ALL sources and ALL sinks
                    if len(self.source_sink_mapping) == 0:
                        log.info(
                            "JulietBatchRunner",
                            f"Enable-all mode: activating ALL sources and sinks for {fname}",
                        )
                    else:
                        log.info(
                            "JulietBatchRunner",
                            f"No mapping found for {fname} in JSON - enabling ALL sources and sinks",
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
                        "JulietBatchRunner",
                        f"Enabled {len(all_sources)} sources and {len(all_sinks)} sinks for {fname}",
                    )

                # Attach the BinaryView so path_ctr works
                self.path_ctr._bv = bv

                # Clear old paths before processing this binary
                if self.path_ctr.path_tree_view:
                    cleared_count = self.path_ctr.path_tree_view.clear_all_paths()
                    log.info(
                        "JulietBatchRunner",
                        f"Cleared {cleared_count} existing path(s) before processing {fname}",
                    )
                    time.sleep(0.1)
                else:
                    log.warn(
                        "JulietBatchRunner", f"No PathTreeView available for {fname}"
                    )
                    return False

                # Run Mole path finding with log capture
                log.info("JulietBatchRunner", f"Starting path finding for {fname}")

                # Start capturing logs for debugging no-paths cases
                self.log_capture.start_capture()

                self.path_ctr.find_paths()

                # Wait until path finding is finished
                while not self.path_ctr.thread_finished:
                    if self.cancelled:
                        log.info(
                            "JulietBatchRunner",
                            "Batch processing cancelled during path finding",
                        )
                        self.log_capture.stop_capture()
                        return False
                    time.sleep(0.5)

                # Stop log capture and get captured logs
                self.log_capture.stop_capture()
                captured_logs = self.log_capture.get_logs()

                log.info(
                    "JulietBatchRunner",
                    f"Captured {len(captured_logs)} log entries during path finding",
                )

                log.info("JulietBatchRunner", f"Path finding completed for {fname}")

                # Verify path_tree_view is available
                if not self.path_ctr.path_tree_view:
                    log.warn(
                        "JulietBatchRunner",
                        f"No PathTreeView available after path finding for {fname}",
                    )
                    return False

                # Get all path IDs from the model
                path_ids = list(self.path_ctr.path_tree_view.model.path_ids)
                if not path_ids:
                    log.info("JulietBatchRunner", f"No paths found in {fname}")

                    # Collect information about sources and sinks actually detected
                    detected_sources = []
                    detected_sinks = []

                    try:
                        from mole.common.helper.symbol import SymbolHelper

                        # Get configured source functions and check which are in the binary
                        src_funs = self.path_ctr.config_ctr.config_model.get_functions(
                            fun_type="Sources", fun_enabled=True
                        )
                        for src_fun in src_funs:
                            code_refs = SymbolHelper.get_code_refs(bv, src_fun.symbols)
                            for symbol_name, refs in code_refs.items():
                                if refs:
                                    detected_sources.append(symbol_name)

                        # Get configured sink functions and check which are in the binary
                        snk_funs = self.path_ctr.config_ctr.config_model.get_functions(
                            fun_type="Sinks", fun_enabled=True
                        )
                        for snk_fun in snk_funs:
                            code_refs = SymbolHelper.get_code_refs(bv, snk_fun.symbols)
                            for symbol_name, refs in code_refs.items():
                                if refs:
                                    detected_sinks.append(symbol_name)

                    except Exception as e:
                        log.warn(
                            "JulietBatchRunner",
                            f"Could not retrieve detected source/sink info: {e}",
                        )

                    # Remove duplicates and sort for consistency
                    detected_sources = sorted(list(set(detected_sources)))
                    detected_sinks = sorted(list(set(detected_sinks)))

                    # Create informative result even when no paths found
                    no_paths_result = {
                        "binary_file": fname,
                        "status": "no_paths_detected",
                        "detected_sources": detected_sources
                        if detected_sources
                        else ["none_detected"],
                        "detected_sinks": detected_sinks
                        if detected_sinks
                        else ["none_detected"],
                        "message": f"No vulnerability paths detected between sources and sinks in {fname}",
                    }

                    # Save the informative result
                    out_file = os.path.join(output_dir, f"{fname}.json")
                    with open(out_file, "w") as fp:
                        json.dump([no_paths_result], fp, indent=2)
                    log.info("JulietBatchRunner", f"Saved no-paths info to {out_file}")

                    # Save debug logs for no-paths case
                    if captured_logs:
                        debug_log_data = {
                            "binary_file": fname,
                            "status": "debug_logs_no_paths",
                            "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
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
                                    for level in ["DEBUG", "INFO", "WARNING", "ERROR"]
                                },
                                "capture_status": "enabled"
                                if len(captured_logs) > 0
                                else "no_logs_captured",
                            },
                        }

                        debug_log_file = os.path.join(
                            output_dir, f"{fname}_debug_logs.json"
                        )
                        with open(debug_log_file, "w") as fp:
                            json.dump(debug_log_data, fp, indent=2)
                        log.info(
                            "JulietBatchRunner",
                            f"Saved debug logs to {debug_log_file}",
                        )

                    # Clear any potential leftover paths
                    if self.path_ctr.path_tree_view:
                        cleared_count = self.path_ctr.path_tree_view.clear_all_paths()
                        if cleared_count > 0:
                            log.info(
                                "JulietBatchRunner",
                                f"No-paths cleanup: cleared {cleared_count} unexpected path(s) for {fname}",
                            )
                    return True

                log.info(
                    "JulietBatchRunner", f"Found {len(path_ids)} path(s) in {fname}"
                )

                # Run AI analysis on all paths
                log.info(
                    "JulietBatchRunner",
                    f"Starting AI analysis for {len(path_ids)} path(s)",
                )
                self.path_ctr.analyze_paths(path_ids)

                # Wait until AI analysis finishes
                while not self.path_ctr.thread_finished:
                    if self.cancelled:
                        log.info(
                            "JulietBatchRunner",
                            "Batch processing cancelled during AI analysis",
                        )
                        return False
                    time.sleep(0.5)

                log.info("JulietBatchRunner", f"AI analysis completed for {fname}")

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
                                "JulietBatchRunner", f"Could not retrieve path {pid}"
                            )
                            continue

                        # Create simplified path data with AI report
                        simplified_data = {
                            "binary_file": fname,
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
                        num_phi_calls = len(path.phiis) if hasattr(path, "phiis") else 0
                        num_branches = len(path.bdeps) if hasattr(path, "bdeps") else 0

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
                            "structural_complexity_score": round(complexity_score, 4),
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
                                else [],
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
                            "JulietBatchRunner", f"Failed to export path {pid}: {e}"
                        )
                        continue

                # Save JSON report
                out_file = os.path.join(output_dir, f"{fname}.json")
                with open(out_file, "w") as fp:
                    json.dump(results, fp, indent=2)

                log.info(
                    "JulietBatchRunner", f"Saved {len(results)} path(s) to {out_file}"
                )

                # Clear paths after saving to prevent merging with next binary
                if self.path_ctr.path_tree_view:
                    cleared_count = self.path_ctr.path_tree_view.clear_all_paths()
                    log.info(
                        "JulietBatchRunner",
                        f"Post-processing cleanup: cleared {cleared_count} path(s) for {fname}",
                    )

                return True

            except Exception as e:
                log.error("JulietBatchRunner", f"Error processing {fname}: {e}")

                # Ensure log capture is stopped even on error
                try:
                    self.log_capture.stop_capture()
                except Exception:
                    pass

                return False

            finally:
                # Restore ORIGINAL enabled/disabled states (always restore to original)
                try:
                    if hasattr(self, "original_states") and self.original_states:
                        config_model = self.path_ctr.config_ctr.config_model

                        # Restore sources to original state
                        for func in config_model.get_functions(fun_type="Sources"):
                            key = ("source", func.name)
                            if key in self.original_states:
                                func.enabled = self.original_states[key]

                        # Restore sinks to original state
                        for func in config_model.get_functions(fun_type="Sinks"):
                            key = ("sink", func.name)
                            if key in self.original_states:
                                func.enabled = self.original_states[key]

                        log.info(
                            "JulietBatchRunner",
                            "Restored to original source/sink states for next binary",
                        )
                except Exception as e:
                    log.warn(
                        "JulietBatchRunner", f"Could not restore original states: {e}"
                    )

                # Explicit cleanup
                try:
                    if bv:
                        bv.file.close()
                        del bv
                except Exception as e:
                    log.error("JulietBatchRunner", f"Error closing {fname}: {e}")

        def run(self):
            """
            Run the Juliet batch processing in the background.
            Supports two directory structures:
            1. With Top folders: BASE_DIR/Top50/CWE121/good_versions/*.bin
            2. Direct CWE folders: BASE_DIR/CWE121/good_versions/*.bin

            Only processes the CWE specified in self.target_cwe
            """
            # FLAVIO: Track execution time and statistics for performance analysis
            batch_start_time = time.time()
            binary_timings = []  # Store (binary_name, elapsed_seconds, num_paths) for each binary
            total_paths_found = 0

            # Hardcoded paths - adjust as needed
            BASE_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/Binaries_Diff_Opt_Levels/compiled_Juliet_O3-s"
            OUTPUT_BASE_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/results_compiled_Juliet_O3-s"

            TARGET_CWE = self.target_cwe

            if not os.path.exists(BASE_DIR):
                log.error("JulietBatchRunner", f"Base directory not found: {BASE_DIR}")
                return

            # Create output base directory
            os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)

            log.info("JulietBatchRunner", f"*** Processing only {TARGET_CWE} ***")

            # Detect directory structure
            # Check if we have Top50/Top100/Top150 folders or direct CWE folders
            has_top_folders = False
            top_folders = ["Top50", "Top100", "Top150"]

            for top_folder in top_folders:
                if os.path.exists(os.path.join(BASE_DIR, top_folder)):
                    has_top_folders = True
                    break

            # Check if target CWE exists directly in BASE_DIR
            direct_cwe_path = os.path.join(BASE_DIR, TARGET_CWE)
            has_direct_cwe = os.path.exists(direct_cwe_path)

            if has_top_folders:
                log.info(
                    "JulietBatchRunner", "Detected Top50/Top100/Top150 folder structure"
                )
            elif has_direct_cwe:
                log.info("JulietBatchRunner", "Detected direct CWE folder structure")
            else:
                log.error(
                    "JulietBatchRunner",
                    f"Could not find {TARGET_CWE} in either folder structure",
                )
                return

            total_binaries = 0
            processed_binaries = 0

            # Build list of paths to process: [(top_folder_name, cwe_path)]
            # top_folder_name can be None for direct structure
            paths_to_process = []

            if has_top_folders:
                # Structure: Top50/CWE121/good_versions
                for top_folder in top_folders:
                    top_path = os.path.join(BASE_DIR, top_folder)
                    if not os.path.exists(top_path):
                        continue

                    target_cwe_path = os.path.join(top_path, TARGET_CWE)
                    if os.path.exists(target_cwe_path):
                        paths_to_process.append((top_folder, target_cwe_path))
                        log.info(
                            "JulietBatchRunner", f"Found CWE path: {target_cwe_path}"
                        )

            if has_direct_cwe:
                # Structure: CWE121/good_versions (no Top folder)
                paths_to_process.append((None, direct_cwe_path))
                log.info(
                    "JulietBatchRunner", f"Found direct CWE path: {direct_cwe_path}"
                )

            # First pass: count total binaries for progress tracking
            for top_folder, cwe_path in paths_to_process:
                # Check for good_versions and bad_versions subfolders
                for category in ["good_versions", "bad_versions"]:
                    category_path = os.path.join(cwe_path, category)
                    if os.path.exists(category_path):
                        binaries = [
                            f
                            for f in os.listdir(category_path)
                            if os.path.isfile(os.path.join(category_path, f))
                        ]
                        total_binaries += len(binaries)

            log.info(
                "JulietBatchRunner",
                f"Found {total_binaries} binaries to process in {TARGET_CWE}",
            )

            # Second pass: process all binaries
            for top_folder, cwe_path in paths_to_process:
                if self.cancelled:
                    log.info("JulietBatchRunner", "Batch processing cancelled by user")
                    break

                # Create corresponding output folder structure
                if top_folder:
                    # With Top folder: OUTPUT_BASE_DIR/Top50/CWE121/
                    output_cwe_dir = os.path.join(
                        OUTPUT_BASE_DIR, top_folder, TARGET_CWE
                    )
                    log.info(
                        "JulietBatchRunner", f"Processing {top_folder}/{TARGET_CWE}"
                    )
                else:
                    # Direct: OUTPUT_BASE_DIR/CWE121/
                    output_cwe_dir = os.path.join(OUTPUT_BASE_DIR, TARGET_CWE)
                    log.info("JulietBatchRunner", f"Processing {TARGET_CWE}")

                os.makedirs(output_cwe_dir, exist_ok=True)

                # Process both good_versions and bad_versions binaries
                for category in ["good_versions", "bad_versions"]:
                    if self.cancelled:
                        break

                    category_path = os.path.join(cwe_path, category)
                    if not os.path.exists(category_path):
                        log.warn(
                            "JulietBatchRunner",
                            f"Skipping missing {category} folder in {TARGET_CWE}",
                        )
                        continue

                    # Create corresponding output folder
                    output_category_dir = os.path.join(output_cwe_dir, category)
                    os.makedirs(output_category_dir, exist_ok=True)

                    # Get all binary files directly from category folder
                    binaries = sorted(
                        [
                            f
                            for f in os.listdir(category_path)
                            if os.path.isfile(os.path.join(category_path, f))
                        ]
                    )

                    log.info(
                        "JulietBatchRunner",
                        f"Found {len(binaries)} {category} binaries in {TARGET_CWE}",
                    )

                    for fname in binaries:
                        if self.cancelled:
                            break

                        processed_binaries += 1

                        if top_folder:
                            self.progress = f"Processing {fname} ({processed_binaries}/{total_binaries}) - {top_folder}/{TARGET_CWE}/{category}"
                        else:
                            self.progress = f"Processing {fname} ({processed_binaries}/{total_binaries}) - {TARGET_CWE}/{category}"

                        fpath = os.path.join(category_path, fname)

                        # FLAVIO: Track per-binary timing
                        binary_start_time = time.time()

                        # Process the binary
                        success = self.process_binary(fpath, fname, output_category_dir)

                        # FLAVIO: Record timing and path count for this binary
                        binary_elapsed = time.time() - binary_start_time

                        # Count paths by reading the JSON output file
                        num_paths = 0
                        try:
                            json_file = os.path.join(
                                output_category_dir, f"{fname}.json"
                            )
                            if os.path.exists(json_file):
                                with open(json_file, "r") as f:
                                    paths_data = json.load(f)
                                    num_paths = (
                                        len(paths_data)
                                        if isinstance(paths_data, list)
                                        else 0
                                    )
                                    total_paths_found += num_paths
                        except Exception:
                            pass

                        binary_timings.append((fname, binary_elapsed, num_paths))

                        if success:
                            log.info(
                                "JulietBatchRunner",
                                f"Successfully processed {fname} ({processed_binaries}/{total_binaries})",
                            )
                        else:
                            log.warn(
                                "JulietBatchRunner",
                                f"Failed to process {fname} ({processed_binaries}/{total_binaries})",
                            )

            # FLAVIO: Calculate and save execution statistics
            batch_end_time = time.time()
            elapsed_seconds = batch_end_time - batch_start_time
            elapsed_minutes = elapsed_seconds / 60
            elapsed_hours = elapsed_minutes / 60

            # Calculate statistics
            avg_time_per_binary = (
                elapsed_seconds / processed_binaries if processed_binaries > 0 else 0
            )
            longest_binary = (
                max(binary_timings, key=lambda x: x[1])
                if binary_timings
                else (None, 0, 0)
            )
            avg_paths_per_binary = (
                total_paths_found / processed_binaries if processed_binaries > 0 else 0
            )

            time_str = f"{elapsed_seconds:.2f}s"
            if elapsed_seconds >= 60:
                time_str = f"{elapsed_minutes:.2f}m ({elapsed_seconds:.2f}s)"
            if elapsed_minutes >= 60:
                time_str = f"{elapsed_hours:.2f}h ({elapsed_minutes:.2f}m)"

            # FLAVIO: Create summary statistics JSON
            summary = {
                "cwe": TARGET_CWE,
                "total_binaries_processed": processed_binaries,
                "total_binaries_found": total_binaries,
                "total_paths_found": total_paths_found,
                "total_execution_time_seconds": round(elapsed_seconds, 2),
                "total_execution_time_formatted": time_str,
                "average_time_per_binary_seconds": round(avg_time_per_binary, 2),
                "average_paths_per_binary": round(avg_paths_per_binary, 2),
                "longest_binary": {
                    "name": longest_binary[0],
                    "time_seconds": round(longest_binary[1], 2),
                    "num_paths": longest_binary[2],
                }
                if longest_binary[0]
                else None,
                "cancelled": self.cancelled,
                "timestamp": datetime.now().isoformat(),
            }

            # Save summary to output directory
            summary_file = os.path.join(
                OUTPUT_BASE_DIR, f"{TARGET_CWE}_batch_summary.json"
            )
            try:
                with open(summary_file, "w") as f:
                    json.dump(summary, f, indent=2)
                log.info("JulietBatchRunner", f"Saved batch summary to {summary_file}")
            except Exception as e:
                log.error("JulietBatchRunner", f"Failed to save summary: {e}")

            if not self.cancelled:
                log.info(
                    "JulietBatchRunner",
                    f"{TARGET_CWE} batch processing completed! Processed {processed_binaries}/{total_binaries} binaries, found {total_paths_found} paths in {time_str}",
                )
            else:
                log.info(
                    "JulietBatchRunner",
                    f"{TARGET_CWE} batch processing cancelled. Processed {processed_binaries}/{total_binaries} binaries, found {total_paths_found} paths in {time_str}",
                )

    def run_juliet_batch(bv=None):
        """
        Start the Juliet batch runner as a background task.
        Shows a UI dialog to select which CWE to process.
        """
        # Hardcoded paths - adjust as needed
        BASE_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/Binaries_Diff_Opt_Levels_Juliet/compiled_Juliet_O0"
        JSON_MAPPING_BASE_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/Source_Sink_mappings/Source_Sink_Mappings_CUT"

        # Ask user to choose mode: JSON mapping, enable all, or auto-all CWEs
        mode_choice = interaction.get_choice_input(
            "Select Source/Sink Mode",
            "choices",
            [
                "Use JSON mapping (per-binary filtering)",
                "Enable ALL sources/sinks (comprehensive scan)",
                "Auto-run ALL CWEs with JSON mappings",
            ],
        )

        if mode_choice is None:
            log.info("JulietBatchRunner", "User cancelled mode selection")
            return

        use_json_mapping = mode_choice == 0
        auto_all_cwes = mode_choice == 2

        # Scan for available CWEs in both directory structures:
        # 1. Top50/Top100/Top150 folders containing CWEs
        # 2. Direct CWE folders in BASE_DIR
        available_cwes = set()
        top_folders = ["Top50", "Top100", "Top150"]

        # Check for Top folder structure
        for top_folder in top_folders:
            top_path = os.path.join(BASE_DIR, top_folder)
            if os.path.exists(top_path):
                cwe_folders = [
                    d
                    for d in os.listdir(top_path)
                    if os.path.isdir(os.path.join(top_path, d)) and d.startswith("CWE")
                ]
                if cwe_folders:
                    log.info(
                        "JulietBatchRunner",
                        f"Found CWEs in {top_folder}: {cwe_folders}",
                    )
                    available_cwes.update(cwe_folders)

        # Check for direct CWE folders in BASE_DIR
        direct_cwe_folders = [
            d
            for d in os.listdir(BASE_DIR)
            if os.path.isdir(os.path.join(BASE_DIR, d)) and d.startswith("CWE")
        ]
        if direct_cwe_folders:
            log.info(
                "JulietBatchRunner", f"Found direct CWE folders: {direct_cwe_folders}"
            )
            available_cwes.update(direct_cwe_folders)

        if not available_cwes:
            log.error("JulietBatchRunner", f"No CWE folders found in {BASE_DIR}")
            interaction.show_message_box(
                "No CWE Folders Found",
                f"Could not find any CWE folders in:\n{BASE_DIR}",
                buttons=interaction.MessageBoxButtonSet.OKButtonSet,
            )
            return

        # Sort CWEs for nice display
        cwe_list = sorted(list(available_cwes))

        # Handle auto-all CWEs mode
        if auto_all_cwes:
            # Find all CWEs that have JSON mapping files
            cwes_with_mappings = []
            cwes_without_mappings = []

            for cwe in cwe_list:
                json_path = os.path.join(
                    JSON_MAPPING_BASE_DIR,
                    f"Juliet{cwe}_source_sink_mapping_CURATED.json",
                )
                if os.path.exists(json_path):
                    cwes_with_mappings.append(cwe)
                else:
                    cwes_without_mappings.append(cwe)

            if not cwes_with_mappings:
                log.error("JulietBatchRunner", "No CWEs with JSON mappings found")
                interaction.show_message_box(
                    "No JSON Mappings Found",
                    f"Could not find any JSON mapping files in:\n{JSON_MAPPING_BASE_DIR}\n\nExpected format: Juliet<CWE>_source_sink_mapping_CURATED.json",
                    buttons=interaction.MessageBoxButtonSet.OKButtonSet,
                )
                return

            log.info(
                "JulietBatchRunner",
                f"Found {len(cwes_with_mappings)} CWEs with JSON mappings: {cwes_with_mappings}",
            )
            if cwes_without_mappings:
                log.warn(
                    "JulietBatchRunner",
                    f"Skipping {len(cwes_without_mappings)} CWEs without mappings: {cwes_without_mappings}",
                )

            # Confirm with user
            confirm = interaction.show_message_box(
                "Confirm Auto-Run All CWEs",
                f"This will process {len(cwes_with_mappings)} CWEs:\n\n"
                f"{', '.join(cwes_with_mappings)}\n\n"
                f"This may take a long time. Continue?",
                buttons=interaction.MessageBoxButtonSet.YesNoButtonSet,
            )

            if confirm != interaction.MessageBoxButtonResult.YesButton:
                log.info("JulietBatchRunner", "User cancelled auto-run all CWEs")
                return

            # Start the auto-all task
            log.info(
                "JulietBatchRunner",
                f"Starting auto-run for {len(cwes_with_mappings)} CWEs...",
            )

            task = JulietBatchRunnerAllCWEsTask(
                path_ctr, cwes_with_mappings, JSON_MAPPING_BASE_DIR
            )
            task.start()
            return

        # Show choice dialog for single CWE mode
        cwe_choice = interaction.get_choice_input(
            "Select CWE to Process", "choices", cwe_list
        )

        if cwe_choice is None:
            log.info("JulietBatchRunner", "User cancelled CWE selection")
            return

        selected_cwe = cwe_list[cwe_choice]

        # Load JSON mapping only if user chose that mode
        source_sink_mapping = None
        if use_json_mapping:
            # Build JSON mapping path based on selected CWE
            # Example: CWE121 -> juliet_source_sink_mapping_CWE121.json
            JSON_MAPPING_PATH = os.path.join(
                JSON_MAPPING_BASE_DIR,
                f"Juliet{selected_cwe}_source_sink_mapping_CURATED.json",
            )

            # Load the source/sink mapping from JSON
            source_sink_mapping = load_source_sink_mapping(JSON_MAPPING_PATH)
            if not source_sink_mapping:
                log.error(
                    "JulietBatchRunner", "Could not load source/sink mapping - aborting"
                )
                interaction.show_message_box(
                    "Mapping File Error",
                    f"Could not load source/sink mapping from:\n{JSON_MAPPING_PATH}\n\nPlease create the JSON mapping file first.",
                    buttons=interaction.MessageBoxButtonSet.OKButtonSet,
                )
                return
            log.info(
                "JulietBatchRunner",
                f"Starting Juliet batch processing for {selected_cwe} with JSON mapping...",
            )
        else:
            # Use empty dict to signal "enable all" mode
            source_sink_mapping = {}
            log.info(
                "JulietBatchRunner",
                f"Starting Juliet batch processing for {selected_cwe} with ALL sources/sinks enabled...",
            )

        task = JulietBatchRunnerTask(path_ctr, selected_cwe, source_sink_mapping)
        task.start()

    class JulietBatchRunnerAllCWEsTask(BackgroundTask):
        """
        Background task for running batch analysis on ALL CWEs in Juliet test suite.
        Automatically iterates through all CWEs that have JSON mapping files.
        """

        def __init__(self, path_ctr, cwe_list, json_mapping_base_dir):
            super().__init__(
                f"Running Juliet batch analysis for ALL {len(cwe_list)} CWEs...", True
            )
            self.path_ctr = path_ctr
            self.cwe_list = cwe_list
            self.json_mapping_base_dir = json_mapping_base_dir
            self.log_capture = LogCapture()

            # Save the ORIGINAL config state once at initialization
            config_model = self.path_ctr.config_ctr.config_model
            self.original_states = {}

            for func in config_model.get_functions(fun_type="Sources"):
                self.original_states[("source", func.name)] = func.enabled

            for func in config_model.get_functions(fun_type="Sinks"):
                self.original_states[("sink", func.name)] = func.enabled

            log.info(
                "JulietBatchRunner",
                f"Saved original state: {len([k for k in self.original_states.keys() if k[0] == 'source'])} sources, "
                f"{len([k for k in self.original_states.keys() if k[0] == 'sink'])} sinks",
            )

        def run(self):
            """
            Run batch processing for all CWEs sequentially.
            """
            overall_start_time = time.time()
            cwe_results = []
            total_cwes = len(self.cwe_list)
            processed_cwes = 0
            total_binaries_all = 0
            total_paths_all = 0

            BASE_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/Binaries_Diff_Opt_Levels_Juliet/compiled_Juliet_O0"
            OUTPUT_BASE_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/Baseline_Results/Baseline_Results_Juliet/evaluate_qwen3-coder:free_temp_02_baseline_juliet"

            log.info(
                "JulietBatchRunner",
                f"Starting auto-run for {total_cwes} CWEs: {self.cwe_list}",
            )

            for cwe_idx, target_cwe in enumerate(self.cwe_list):
                if self.cancelled:
                    log.info("JulietBatchRunner", "Auto-run cancelled by user")
                    break

                self.progress = f"Processing {target_cwe} ({cwe_idx + 1}/{total_cwes})"
                log.info(
                    "JulietBatchRunner",
                    f"=== Starting CWE {cwe_idx + 1}/{total_cwes}: {target_cwe} ===",
                )

                cwe_start_time = time.time()

                # Load JSON mapping for this CWE
                json_path = os.path.join(
                    self.json_mapping_base_dir,
                    f"Juliet{target_cwe}_source_sink_mapping_CURATED.json",
                )
                source_sink_mapping = load_source_sink_mapping(json_path)

                if not source_sink_mapping:
                    log.warn(
                        "JulietBatchRunner",
                        f"Could not load mapping for {target_cwe}, skipping",
                    )
                    cwe_results.append(
                        {
                            "cwe": target_cwe,
                            "status": "skipped",
                            "reason": "mapping_load_failed",
                            "binaries_processed": 0,
                            "paths_found": 0,
                            "time_seconds": 0,
                        }
                    )
                    continue

                # Process this CWE using similar logic to JulietBatchRunnerTask.run()
                cwe_binaries = 0
                cwe_paths = 0

                # Detect directory structure
                has_top_folders = False
                top_folders = ["Top50", "Top100", "Top150"]

                for top_folder in top_folders:
                    if os.path.exists(os.path.join(BASE_DIR, top_folder)):
                        has_top_folders = True
                        break

                direct_cwe_path = os.path.join(BASE_DIR, target_cwe)
                has_direct_cwe = os.path.exists(direct_cwe_path)

                # Build list of paths to process
                paths_to_process = []

                if has_top_folders:
                    for top_folder in top_folders:
                        top_path = os.path.join(BASE_DIR, top_folder)
                        if not os.path.exists(top_path):
                            continue
                        target_cwe_path = os.path.join(top_path, target_cwe)
                        if os.path.exists(target_cwe_path):
                            paths_to_process.append((top_folder, target_cwe_path))

                if has_direct_cwe:
                    paths_to_process.append((None, direct_cwe_path))

                if not paths_to_process:
                    log.warn(
                        "JulietBatchRunner",
                        f"No binary folders found for {target_cwe}, skipping",
                    )
                    cwe_results.append(
                        {
                            "cwe": target_cwe,
                            "status": "skipped",
                            "reason": "no_binary_folders",
                            "binaries_processed": 0,
                            "paths_found": 0,
                            "time_seconds": 0,
                        }
                    )
                    continue

                # Process binaries for this CWE
                for top_folder, cwe_path in paths_to_process:
                    if self.cancelled:
                        break

                    if top_folder:
                        output_cwe_dir = os.path.join(
                            OUTPUT_BASE_DIR, top_folder, target_cwe
                        )
                    else:
                        output_cwe_dir = os.path.join(OUTPUT_BASE_DIR, target_cwe)

                    os.makedirs(output_cwe_dir, exist_ok=True)

                    for category in ["good_versions", "bad_versions"]:
                        if self.cancelled:
                            break

                        category_path = os.path.join(cwe_path, category)
                        if not os.path.exists(category_path):
                            continue

                        output_category_dir = os.path.join(output_cwe_dir, category)
                        os.makedirs(output_category_dir, exist_ok=True)

                        binaries = sorted(
                            [
                                f
                                for f in os.listdir(category_path)
                                if os.path.isfile(os.path.join(category_path, f))
                            ]
                        )

                        for fname in binaries:
                            if self.cancelled:
                                break

                            fpath = os.path.join(category_path, fname)
                            self.progress = (
                                f"{target_cwe} ({cwe_idx + 1}/{total_cwes}) - {fname}"
                            )

                            # Process binary (inline version of process_binary)
                            success, num_paths = self._process_binary_inline(
                                fpath, fname, output_category_dir, source_sink_mapping
                            )

                            if success:
                                cwe_binaries += 1
                                cwe_paths += num_paths

                cwe_elapsed = time.time() - cwe_start_time
                processed_cwes += 1
                total_binaries_all += cwe_binaries
                total_paths_all += cwe_paths

                cwe_results.append(
                    {
                        "cwe": target_cwe,
                        "status": "completed",
                        "binaries_processed": cwe_binaries,
                        "paths_found": cwe_paths,
                        "time_seconds": round(cwe_elapsed, 2),
                    }
                )

                log.info(
                    "JulietBatchRunner",
                    f"=== Completed {target_cwe}: {cwe_binaries} binaries, {cwe_paths} paths in {cwe_elapsed:.2f}s ===",
                )

            # Save overall summary
            overall_elapsed = time.time() - overall_start_time
            overall_minutes = overall_elapsed / 60

            overall_summary = {
                "mode": "auto_all_cwes",
                "total_cwes_attempted": total_cwes,
                "total_cwes_processed": processed_cwes,
                "total_binaries_processed": total_binaries_all,
                "total_paths_found": total_paths_all,
                "total_time_seconds": round(overall_elapsed, 2),
                "total_time_formatted": f"{overall_minutes:.2f}m ({overall_elapsed:.2f}s)",
                "cancelled": self.cancelled,
                "timestamp": datetime.now().isoformat(),
                "cwe_results": cwe_results,
            }

            summary_file = os.path.join(OUTPUT_BASE_DIR, "ALL_CWEs_batch_summary.json")
            try:
                with open(summary_file, "w") as f:
                    json.dump(overall_summary, f, indent=2)
                log.info(
                    "JulietBatchRunner", f"Saved overall summary to {summary_file}"
                )
            except Exception as e:
                log.error("JulietBatchRunner", f"Failed to save overall summary: {e}")

            log.info(
                "JulietBatchRunner",
                f"Auto-run completed! Processed {processed_cwes}/{total_cwes} CWEs, "
                f"{total_binaries_all} binaries, {total_paths_all} paths in {overall_minutes:.2f}m",
            )

        def _process_binary_inline(self, fpath, fname, output_dir, source_sink_mapping):
            """
            Process a single binary (simplified inline version).
            Returns (success, num_paths).
            """
            num_paths = 0
            bv = None

            try:
                bv = load(fpath)
                if not bv:
                    log.warn("JulietBatchRunner", f"Could not open {fname}")
                    return False, 0
                bv.update_analysis_and_wait()
            except Exception as e:
                log.error("JulietBatchRunner", f"Failed to load {fname}: {e}")
                return False, 0

            try:
                config_model = self.path_ctr.config_ctr.config_model

                # Apply source/sink filter
                if fname in source_sink_mapping:
                    mapping = source_sink_mapping[fname]
                    sources = mapping.get("sources", [])
                    sinks = mapping.get("sinks", [])
                    apply_source_sink_filter(config_model, sources, sinks)
                else:
                    # Enable all if not in mapping
                    for func in config_model.get_functions(fun_type="Sources"):
                        func.enabled = True
                    for func in config_model.get_functions(fun_type="Sinks"):
                        func.enabled = True

                self.path_ctr._bv = bv

                if self.path_ctr.path_tree_view:
                    self.path_ctr.path_tree_view.clear_all_paths()
                    time.sleep(0.1)
                else:
                    return False, 0

                # Start capturing logs for debugging no-paths cases
                self.log_capture.start_capture()

                # Find paths
                self.path_ctr.find_paths()

                while not self.path_ctr.thread_finished:
                    if self.cancelled:
                        self.log_capture.stop_capture()
                        return False, 0
                    time.sleep(0.5)

                # Stop log capture and get captured logs
                self.log_capture.stop_capture()
                captured_logs = self.log_capture.get_logs()

                if not self.path_ctr.path_tree_view:
                    return False, 0

                path_ids = list(self.path_ctr.path_tree_view.model.path_ids)

                if not path_ids:
                    # No paths found - collect detailed debug info
                    detected_sources = []
                    detected_sinks = []

                    try:
                        from mole.common.helper.symbol import SymbolHelper

                        # Get configured source functions and check which are in the binary
                        src_funs = self.path_ctr.config_ctr.config_model.get_functions(
                            fun_type="Sources", fun_enabled=True
                        )
                        for src_fun in src_funs:
                            code_refs = SymbolHelper.get_code_refs(bv, src_fun.symbols)
                            for symbol_name, refs in code_refs.items():
                                if refs:
                                    detected_sources.append(symbol_name)

                        # Get configured sink functions and check which are in the binary
                        snk_funs = self.path_ctr.config_ctr.config_model.get_functions(
                            fun_type="Sinks", fun_enabled=True
                        )
                        for snk_fun in snk_funs:
                            code_refs = SymbolHelper.get_code_refs(bv, snk_fun.symbols)
                            for symbol_name, refs in code_refs.items():
                                if refs:
                                    detected_sinks.append(symbol_name)

                    except Exception as e:
                        log.warn(
                            "JulietBatchRunner",
                            f"Could not retrieve detected source/sink info: {e}",
                        )

                    # Remove duplicates and sort for consistency
                    detected_sources = sorted(list(set(detected_sources)))
                    detected_sinks = sorted(list(set(detected_sinks)))

                    # Create informative result even when no paths found
                    no_paths_result = {
                        "binary_file": fname,
                        "status": "no_paths_detected",
                        "detected_sources": detected_sources
                        if detected_sources
                        else ["none_detected"],
                        "detected_sinks": detected_sinks
                        if detected_sinks
                        else ["none_detected"],
                        "message": f"No vulnerability paths detected between sources and sinks in {fname}",
                    }

                    # Save the informative result
                    out_file = os.path.join(output_dir, f"{fname}.json")
                    with open(out_file, "w") as fp:
                        json.dump([no_paths_result], fp, indent=2)
                    log.info("JulietBatchRunner", f"Saved no-paths info to {out_file}")

                    # Save debug logs for no-paths case
                    if captured_logs:
                        debug_log_data = {
                            "binary_file": fname,
                            "status": "debug_logs_no_paths",
                            "analysis_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
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
                                    for level in ["DEBUG", "INFO", "WARNING", "ERROR"]
                                },
                                "capture_status": "enabled"
                                if len(captured_logs) > 0
                                else "no_logs_captured",
                            },
                        }

                        debug_log_file = os.path.join(
                            output_dir, f"{fname}_debug_logs.json"
                        )
                        with open(debug_log_file, "w") as fp:
                            json.dump(debug_log_data, fp, indent=2)
                        log.info(
                            "JulietBatchRunner",
                            f"Saved debug logs to {debug_log_file}",
                        )

                    return True, 0

                num_paths = len(path_ids)

                # Run AI analysis
                self.path_ctr.analyze_paths(path_ids)

                while not self.path_ctr.thread_finished:
                    if self.cancelled:
                        return False, num_paths
                    time.sleep(0.5)

                # Collect results
                results = []
                for pid in path_ids:
                    try:
                        path = self.path_ctr.path_tree_view.get_path(pid)
                        if not path:
                            continue

                        import math

                        num_instructions = (
                            len(path.insts) if hasattr(path, "insts") else 0
                        )
                        num_phi_calls = len(path.phiis) if hasattr(path, "phiis") else 0
                        num_branches = len(path.bdeps) if hasattr(path, "bdeps") else 0
                        complexity_score = (
                            0.5 * math.log(1 + num_branches)
                            + 0.3 * math.log(1 + num_phi_calls)
                            + 0.2 * math.log(1 + num_instructions)
                        )

                        simplified_data = {
                            "binary_file": fname,
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
                            "path_complexity": {
                                "instructions": num_instructions,
                                "phi_calls": num_phi_calls,
                                "branches": num_branches,
                                "structural_complexity_score": round(
                                    complexity_score, 4
                                ),
                            },
                        }

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
                                else [],
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

                        results.append(simplified_data)
                    except Exception as e:
                        log.error(
                            "JulietBatchRunner", f"Failed to export path {pid}: {e}"
                        )
                        continue

                out_file = os.path.join(output_dir, f"{fname}.json")
                with open(out_file, "w") as fp:
                    json.dump(results, fp, indent=2)

                if self.path_ctr.path_tree_view:
                    self.path_ctr.path_tree_view.clear_all_paths()

                return True, num_paths

            except Exception as e:
                log.error("JulietBatchRunner", f"Error processing {fname}: {e}")
                return False, 0

            finally:
                # Restore original states
                try:
                    if hasattr(self, "original_states") and self.original_states:
                        config_model = self.path_ctr.config_ctr.config_model
                        for func in config_model.get_functions(fun_type="Sources"):
                            key = ("source", func.name)
                            if key in self.original_states:
                                func.enabled = self.original_states[key]
                        for func in config_model.get_functions(fun_type="Sinks"):
                            key = ("sink", func.name)
                            if key in self.original_states:
                                func.enabled = self.original_states[key]
                except Exception:
                    pass

                try:
                    if bv:
                        bv.file.close()
                        del bv
                except Exception:
                    pass

    # Register command in BN
    PluginCommand.register(
        "Mole\\Batch Run Juliet",
        "Run Find Paths + AI Analysis on Juliet Test Suite (Background)",
        run_juliet_batch,
    )
