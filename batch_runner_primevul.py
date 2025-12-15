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
        dict: Mapping of binary names to sources/sinks

    Expected JSON format:
    {
      "binary1": {
        "sources": ["filename", "fread"],
        "sinks": ["system", "malloc"]
      },
      "binary2": {
        "sources": ["user_input"],
        "sinks": ["strcpy"]
      }
    }
    """
    try:
        with open(json_path, "r") as f:
            mapping = json.load(f)
        log.info(
            "PrimeVulBatchRunner",
            f"Loaded source/sink mapping for {len(mapping)} binaries from {json_path}",
        )
        return mapping
    except FileNotFoundError:
        log.error("PrimeVulBatchRunner", f"Mapping file not found: {json_path}")
        return None
    except json.JSONDecodeError as e:
        log.error("PrimeVulBatchRunner", f"Invalid JSON in mapping file: {e}")
        return None
    except Exception as e:
        log.error("PrimeVulBatchRunner", f"Error loading mapping file: {e}")
        return None


def apply_source_sink_filter(config_model, source_functions=None, sink_functions=None):
    """
    Disable all sources/sinks in the config, then enable only the specified ones.
    This modifies the config_model in-place, just like Binary Ninja's UI does.

    If a specified source is not found, ALL sources will be enabled as a fallback.
    If a specified sink is not found, ALL sinks will be enabled as a fallback.

    Args:
        config_model: The ConfigModel to modify
        source_functions: List of source function names to enable (e.g., ['filename', 'fread'])
        sink_functions: List of sink function names to enable (e.g., ['malloc', 'strcpy'])

    Returns:
        dict: Status info with 'sources_fallback' and 'sinks_fallback' booleans

    Example:
        apply_source_sink_filter(config_model, ['filename'], ['malloc'])
    """
    # Get all functions using the same API that Binary Ninja UI uses
    all_sources = config_model.get_functions(fun_type="Sources")
    all_sinks = config_model.get_functions(fun_type="Sinks")

    # FLAVIO: Debug - show all available functions before filtering
    all_source_names = [func.name for func in all_sources]
    all_sink_names = [func.name for func in all_sinks]
    log.info("PrimeVulBatchRunner", f"Available sources: {all_source_names}")
    log.info("PrimeVulBatchRunner", f"Available sinks: {all_sink_names}")

    # Track if we need to fallback to enabling all
    sources_fallback = False
    sinks_fallback = False

    # Check if all specified sources exist
    if source_functions:
        available_sources = {func.name for func in all_sources}
        missing_sources = [s for s in source_functions if s not in available_sources]
        if missing_sources:
            log.warn(
                "PrimeVulBatchRunner",
                f"Source(s) not found: {missing_sources}. Enabling ALL sources as fallback.",
            )
            sources_fallback = True

    # Check if all specified sinks exist
    if sink_functions:
        available_sinks = {func.name for func in all_sinks}
        missing_sinks = [s for s in sink_functions if s not in available_sinks]
        if missing_sinks:
            log.warn(
                "PrimeVulBatchRunner",
                f"Sink(s) not found: {missing_sinks}. Enabling ALL sinks as fallback.",
            )
            sinks_fallback = True

    # Disable ALL sources first
    for func in all_sources:
        func.enabled = False

    # Disable ALL sinks first
    for func in all_sinks:
        func.enabled = False

    log.info(
        "PrimeVulBatchRunner",
        f"Disabled all {len(all_sources)} sources and {len(all_sinks)} sinks",
    )

    # Handle sources: either enable all (fallback) or enable only specified
    if sources_fallback:
        for func in all_sources:
            func.enabled = True
        log.info(
            "PrimeVulBatchRunner",
            f"FALLBACK: Enabled ALL {len(all_sources)} sources",
        )
    elif source_functions:
        available_sources = {func.name for func in all_sources}
        for source_name in source_functions:
            if source_name in available_sources:
                for func in all_sources:
                    if func.name == source_name:
                        func.enabled = True
                        log.info("PrimeVulBatchRunner", f"Enabled source: {func.name}")
                        break

    # Handle sinks: either enable all (fallback) or enable only specified
    if sinks_fallback:
        for func in all_sinks:
            func.enabled = True
        log.info(
            "PrimeVulBatchRunner",
            f"FALLBACK: Enabled ALL {len(all_sinks)} sinks",
        )
    elif sink_functions:
        available_sinks = {func.name for func in all_sinks}
        for sink_name in sink_functions:
            if sink_name in available_sinks:
                for func in all_sinks:
                    if func.name == sink_name:
                        func.enabled = True
                        log.info("PrimeVulBatchRunner", f"Enabled sink: {func.name}")
                        break

    return {"sources_fallback": sources_fallback, "sinks_fallback": sinks_fallback}


def init(path_ctr):
    """
    Initialize the PrimeVul batch runner with the shared path_ctr from the plugin.
    Registers a BN plugin command to run batch analysis on PrimeVul dataset.
    """

    class PrimeVulBatchRunnerTask(BackgroundTask):
        """
        Background task for running batch analysis on PrimeVul dataset.
        Expected structure: BINARIES_DIR/ with binary files
        """

        def __init__(self, path_ctr, binaries_dir, output_dir, source_sink_mapping):
            super().__init__("Running PrimeVul batch analysis...", True)
            self.path_ctr = path_ctr
            self.binaries_dir = binaries_dir
            self.output_dir = output_dir
            self.log_capture = LogCapture()
            self.source_sink_mapping = source_sink_mapping

            # Save the ORIGINAL config state once at initialization
            config_model = self.path_ctr.config_ctr.config_model
            self.original_states = {}

            # Save original state of all sources
            for func in config_model.get_functions(fun_type="Sources"):
                self.original_states[("source", func.name)] = func.enabled

            # Save original state of all sinks
            for func in config_model.get_functions(fun_type="Sinks"):
                self.original_states[("sink", func.name)] = func.enabled

            log.info(
                "PrimeVulBatchRunner",
                f"Saved original state: {len([k for k in self.original_states.keys() if k[0] == 'source'])} sources, "
                f"{len([k for k in self.original_states.keys() if k[0] == 'sink'])} sinks",
            )

        def process_binary(self, fpath, fname):
            """
            Process a single binary file.
            Returns True if successful, False otherwise.
            """
            log.info("PrimeVulBatchRunner", f"Processing {fname}")

            # Load binary in BN - auto-detect format
            try:
                bv = load(fpath)
                if not bv:
                    log.warn("PrimeVulBatchRunner", f"Could not open {fname}")
                    return False
                bv.update_analysis_and_wait()
                log.info("PrimeVulBatchRunner", f"Loaded {fname} as {bv.view_type}")
            except Exception as e:
                log.error("PrimeVulBatchRunner", f"Failed to load {fname}: {e}")
                return False

            try:
                # Initialize log capture variable
                captured_logs = []

                # Get config model
                config_model = self.path_ctr.config_ctr.config_model

                # FLAVIO: Strip .o extension for JSON mapping lookup
                fname_without_ext = (
                    fname.rstrip(".o") if fname.endswith(".o") else fname
                )

                # Check if we're using JSON mapping mode or enable-all mode
                if (
                    len(self.source_sink_mapping) > 0
                    and fname_without_ext in self.source_sink_mapping
                ):
                    # JSON mapping mode: Found specific mapping for this binary
                    mapping = self.source_sink_mapping[fname_without_ext]
                    sources = mapping.get("sources", [])
                    sinks = mapping.get("sinks", [])

                    log.info(
                        "PrimeVulBatchRunner",
                        f"Found mapping for {fname} (matched as {fname_without_ext}) - Sources: {sources}, Sinks: {sinks}",
                    )

                    # Apply the filter (disable all, enable only specified)
                    # If a source/sink is not found, it will fallback to enabling ALL
                    filter_status = apply_source_sink_filter(
                        config_model, sources, sinks
                    )

                    if (
                        filter_status["sources_fallback"]
                        or filter_status["sinks_fallback"]
                    ):
                        log.info(
                            "PrimeVulBatchRunner",
                            f"Applied source/sink filter for {fname} with fallbacks - "
                            f"sources_fallback={filter_status['sources_fallback']}, "
                            f"sinks_fallback={filter_status['sinks_fallback']}",
                        )
                    else:
                        log.info(
                            "PrimeVulBatchRunner",
                            f"Applied source/sink filter for {fname}",
                        )
                else:
                    # Enable-all mode OR binary not found in JSON
                    if len(self.source_sink_mapping) == 0:
                        log.info(
                            "PrimeVulBatchRunner",
                            f"Enable-all mode: activating ALL sources and sinks for {fname}",
                        )
                    else:
                        log.info(
                            "PrimeVulBatchRunner",
                            f"No mapping found for {fname} - enabling ALL sources and sinks",
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
                        "PrimeVulBatchRunner",
                        f"Enabled {len(all_sources)} sources and {len(all_sinks)} sinks for {fname}",
                    )

                # Attach the BinaryView so path_ctr works
                self.path_ctr._bv = bv

                # Clear old paths before processing this binary
                if self.path_ctr.path_tree_view:
                    cleared_count = self.path_ctr.path_tree_view.clear_all_paths()
                    log.info(
                        "PrimeVulBatchRunner",
                        f"Cleared {cleared_count} existing path(s) before processing {fname}",
                    )
                    time.sleep(0.1)
                else:
                    log.warn(
                        "PrimeVulBatchRunner", f"No PathTreeView available for {fname}"
                    )
                    return False

                # Run Mole path finding with log capture
                log.info("PrimeVulBatchRunner", f"Starting path finding for {fname}")

                # Start capturing logs
                self.log_capture.start_capture()

                self.path_ctr.find_paths()

                # Wait until path finding is finished
                while not self.path_ctr.thread_finished:
                    if self.cancelled:
                        log.info(
                            "PrimeVulBatchRunner",
                            "Batch processing cancelled during path finding",
                        )
                        self.log_capture.stop_capture()
                        return False
                    time.sleep(0.5)

                # Stop log capture and get captured logs
                self.log_capture.stop_capture()
                captured_logs = self.log_capture.get_logs()

                log.info(
                    "PrimeVulBatchRunner",
                    f"Captured {len(captured_logs)} log entries during path finding",
                )

                log.info("PrimeVulBatchRunner", f"Path finding completed for {fname}")

                # Verify path_tree_view is available
                if not self.path_ctr.path_tree_view:
                    log.warn(
                        "PrimeVulBatchRunner",
                        f"No PathTreeView available after path finding for {fname}",
                    )
                    return False

                # Get all path IDs from the model
                path_ids = list(self.path_ctr.path_tree_view.model.path_ids)
                if not path_ids:
                    log.info("PrimeVulBatchRunner", f"No paths found in {fname}")

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
                            "PrimeVulBatchRunner",
                            f"Could not retrieve detected source/sink info: {e}",
                        )

                    # Remove duplicates and sort
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
                        "message": f"No vulnerability paths detected in {fname}",
                    }

                    # Save the informative result
                    out_file = os.path.join(self.output_dir, f"{fname}.json")
                    with open(out_file, "w") as fp:
                        json.dump([no_paths_result], fp, indent=2)
                    log.info(
                        "PrimeVulBatchRunner", f"Saved no-paths info to {out_file}"
                    )

                    # Save debug logs
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
                            },
                        }

                        debug_log_file = os.path.join(
                            self.output_dir, f"{fname}_debug_logs.json"
                        )
                        with open(debug_log_file, "w") as fp:
                            json.dump(debug_log_data, fp, indent=2)
                        log.info(
                            "PrimeVulBatchRunner",
                            f"Saved debug logs to {debug_log_file}",
                        )

                    return True

                log.info(
                    "PrimeVulBatchRunner", f"Found {len(path_ids)} path(s) in {fname}"
                )

                # Run AI analysis on all paths
                log.info(
                    "PrimeVulBatchRunner",
                    f"Starting AI analysis for {len(path_ids)} path(s)",
                )
                self.path_ctr.analyze_paths(path_ids)

                # Wait until AI analysis finishes
                while not self.path_ctr.thread_finished:
                    if self.cancelled:
                        log.info(
                            "PrimeVulBatchRunner",
                            "Batch processing cancelled during AI analysis",
                        )
                        return False
                    time.sleep(0.5)

                log.info("PrimeVulBatchRunner", f"AI analysis completed for {fname}")

                # Collect results
                results = []
                for pid in path_ids:
                    try:
                        path = self.path_ctr.path_tree_view.get_path(pid)
                        if not path:
                            log.warn(
                                "PrimeVulBatchRunner", f"Could not retrieve path {pid}"
                            )
                            continue

                        # Create simplified path data
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

                        # Calculate path complexity metrics
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

                            # FLAVIO: Accumulate token usage
                            self.total_prompt_tokens += path.ai_report.prompt_tokens
                            self.total_completion_tokens += (
                                path.ai_report.completion_tokens
                            )
                            self.total_tokens += path.ai_report.total_tokens
                        else:
                            simplified_data["ai_report"] = None

                        results.append(simplified_data)
                    except Exception as e:
                        log.error(
                            "PrimeVulBatchRunner", f"Failed to export path {pid}: {e}"
                        )
                        continue

                # Save JSON report
                out_file = os.path.join(self.output_dir, f"{fname}.json")
                with open(out_file, "w") as fp:
                    json.dump(results, fp, indent=2)

                log.info(
                    "PrimeVulBatchRunner", f"Saved {len(results)} path(s) to {out_file}"
                )

                # Clear paths after saving
                if self.path_ctr.path_tree_view:
                    cleared_count = self.path_ctr.path_tree_view.clear_all_paths()
                    log.info(
                        "PrimeVulBatchRunner",
                        f"Cleared {cleared_count} path(s) after processing {fname}",
                    )

                return True

            except Exception as e:
                log.error("PrimeVulBatchRunner", f"Error processing {fname}: {e}")

                try:
                    self.log_capture.stop_capture()
                except Exception:
                    pass

                return False

            finally:
                # Restore ORIGINAL enabled/disabled states
                try:
                    if hasattr(self, "original_states") and self.original_states:
                        config_model = self.path_ctr.config_ctr.config_model

                        # Restore sources
                        for func in config_model.get_functions(fun_type="Sources"):
                            key = ("source", func.name)
                            if key in self.original_states:
                                func.enabled = self.original_states[key]

                        # Restore sinks
                        for func in config_model.get_functions(fun_type="Sinks"):
                            key = ("sink", func.name)
                            if key in self.original_states:
                                func.enabled = self.original_states[key]

                        log.info(
                            "PrimeVulBatchRunner",
                            "Restored original source/sink states",
                        )
                except Exception as e:
                    log.warn(
                        "PrimeVulBatchRunner", f"Could not restore original states: {e}"
                    )

                # Cleanup
                try:
                    if bv:
                        bv.file.close()
                        del bv
                except Exception as e:
                    log.error("PrimeVulBatchRunner", f"Error closing {fname}: {e}")

        def run(self):
            """
            Run the PrimeVul batch processing in the background.
            """
            # FLAVIO: Track execution time and statistics
            batch_start_time = time.time()
            binary_timings = []
            total_paths_found = 0
            # FLAVIO: Track token usage across all AI analyses (as instance variables for cross-method access)
            self.total_prompt_tokens = 0
            self.total_completion_tokens = 0
            self.total_tokens = 0

            os.makedirs(self.output_dir, exist_ok=True)

            binary_files = [
                f
                for f in os.listdir(self.binaries_dir)
                if os.path.isfile(os.path.join(self.binaries_dir, f))
            ]
            total_files = len(binary_files)
            processed_binaries = 0

            log.info(
                "PrimeVulBatchRunner",
                f"Found {total_files} binaries to process in {self.binaries_dir}",
            )

            for i, fname in enumerate(binary_files):
                if self.cancelled:
                    log.info(
                        "PrimeVulBatchRunner", "Batch processing cancelled by user"
                    )
                    break

                self.progress = f"Processing {fname} ({i + 1}/{total_files})"
                fpath = os.path.join(self.binaries_dir, fname)

                # FLAVIO: Track per-binary timing
                binary_start_time = time.time()

                success = self.process_binary(fpath, fname)

                # FLAVIO: Record timing and path count
                binary_elapsed = time.time() - binary_start_time

                num_paths = 0
                try:
                    json_file = os.path.join(self.output_dir, f"{fname}.json")
                    if os.path.exists(json_file):
                        with open(json_file, "r") as f:
                            paths_data = json.load(f)
                            num_paths = (
                                len(paths_data) if isinstance(paths_data, list) else 0
                            )
                            total_paths_found += num_paths
                except Exception:
                    pass

                binary_timings.append((fname, binary_elapsed, num_paths))

                if success:
                    processed_binaries += 1
                    log.info(
                        "PrimeVulBatchRunner",
                        f"Successfully processed {fname} ({i + 1}/{total_files})",
                    )
                else:
                    log.warn(
                        "PrimeVulBatchRunner",
                        f"Failed to process {fname} ({i + 1}/{total_files})",
                    )

            # FLAVIO: Calculate and save execution statistics
            batch_end_time = time.time()
            elapsed_seconds = batch_end_time - batch_start_time
            elapsed_minutes = elapsed_seconds / 60
            elapsed_hours = elapsed_minutes / 60

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
                "dataset": "PrimeVul",
                "total_binaries_processed": processed_binaries,
                "total_binaries_found": total_files,
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
                "total_prompt_tokens": self.total_prompt_tokens,
                "total_completion_tokens": self.total_completion_tokens,
                "total_tokens": self.total_tokens,
                "cancelled": self.cancelled,
                "timestamp": datetime.now().isoformat(),
            }

            # Save summary
            summary_file = os.path.join(self.output_dir, "primevul_batch_summary.json")
            try:
                with open(summary_file, "w") as f:
                    json.dump(summary, f, indent=2)
                log.info(
                    "PrimeVulBatchRunner", f"Saved batch summary to {summary_file}"
                )
            except Exception as e:
                log.error("PrimeVulBatchRunner", f"Failed to save summary: {e}")

            if not self.cancelled:
                log.info(
                    "PrimeVulBatchRunner",
                    f"PrimeVul batch processing completed! Processed {processed_binaries}/{total_files} binaries, found {total_paths_found} paths in {time_str}",
                )
            else:
                log.info(
                    "PrimeVulBatchRunner",
                    f"PrimeVul batch processing cancelled. Processed {processed_binaries}/{total_files} binaries in {time_str}",
                )

    def run_primevul_batch(bv=None):
        """
        Start the PrimeVul batch runner as a background task.
        """
        # Hardcoded paths - adjust as needed
        BINARIES_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/Binaries_Diff_Opt_Levels_PrimeVul/Compiled_PrimeVul_O0_nobuiltin_nofortify"
        OUTPUT_DIR = "/Users/flaviogottschalk/dev/BachelorArbeit/Baseline_Results_run2/Baseline_Results_PrimeVul/PrimeVul_baseline_evaluation_kimi_k2_temp=0.2"

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
            log.info("PrimeVulBatchRunner", "User cancelled mode selection")
            return

        use_json_mapping = mode_choice == 0

        # Load JSON mapping if user chose that mode
        source_sink_mapping = None
        if use_json_mapping:
            JSON_MAPPING_PATH = "/Users/flaviogottschalk/dev/BachelorArbeit/Source_Sink_mappings/source_sink_mapping_clean_PrimeVul.json"

            source_sink_mapping = load_source_sink_mapping(JSON_MAPPING_PATH)
            if not source_sink_mapping:
                log.error(
                    "PrimeVulBatchRunner",
                    "Could not load source/sink mapping - aborting",
                )
                interaction.show_message_box(
                    "Mapping File Error",
                    f"Could not load source/sink mapping from:\n{JSON_MAPPING_PATH}\n\nPlease create the JSON mapping file first.",
                    buttons=interaction.MessageBoxButtonSet.OKButtonSet,
                )
                return
            log.info(
                "PrimeVulBatchRunner",
                "Starting PrimeVul batch processing with JSON mapping...",
            )
        else:
            # Use empty dict to signal "enable all" mode
            source_sink_mapping = {}
            log.info(
                "PrimeVulBatchRunner",
                "Starting PrimeVul batch processing with ALL sources/sinks enabled...",
            )

        task = PrimeVulBatchRunnerTask(
            path_ctr, BINARIES_DIR, OUTPUT_DIR, source_sink_mapping
        )
        task.start()

    # Register command in BN
    PluginCommand.register(
        "Mole\\Batch Run PrimeVul",
        "Run Find Paths + AI Analysis on PrimeVul Dataset (Background)",
        run_primevul_batch,
    )
