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
            # Hardcoded paths - adjust as needed
            BASE_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/Extracted_Juliets/compiled_binaries_CURATED/"
            OUTPUT_BASE_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/results_Juliet_for_CURATED_mappings"

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

                        # Process the binary
                        success = self.process_binary(fpath, fname, output_category_dir)

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

            if not self.cancelled:
                log.info(
                    "JulietBatchRunner",
                    f"{TARGET_CWE} batch processing completed! Processed {processed_binaries}/{total_binaries} binaries",
                )
            else:
                log.info(
                    "JulietBatchRunner",
                    f"{TARGET_CWE} batch processing cancelled. Processed {processed_binaries}/{total_binaries} binaries",
                )

    def run_juliet_batch(bv=None):
        """
        Start the Juliet batch runner as a background task.
        Shows a UI dialog to select which CWE to process.
        """
        # Hardcoded paths - adjust as needed
        BASE_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/Extracted_Juliets/compiled_binaries_CURATED/"

        # Ask user to choose mode: JSON mapping or enable all
        mode_choice = interaction.get_choice_input(
            "Select Source/Sink Mode",
            "choices",
            [
                "Use JSON mapping (per-binary filtering)",
                "Enable ALL sources/sinks (comprehensive scan)",
            ],
        )

        if mode_choice is None:
            log.info("JulietBatchRunner", "User cancelled mode selection")
            return

        use_json_mapping = mode_choice == 0

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

        # Show choice dialog
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
            JSON_MAPPING_PATH = f"/Users/flaviogottschalk/dev/BachelorArbeit/Source_Sink_mappings/Source_Sink_Mappings_CUT/Juliet{selected_cwe}_source_sink_mapping_CURATED.json"

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

    # Register command in BN
    PluginCommand.register(
        "Mole\\Batch Run Juliet",
        "Run Find Paths + AI Analysis on Juliet Test Suite (Background)",
        run_juliet_batch,
    )
