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


# Dataset configurations - hardcoded paths for automatic loading
DATASET_CONFIGS = {
    "CASTLE": {
        "name": "CASTLE",
        "mapping_path": "/Users/flaviogottschalk/dev/BachelorArbeit/Source_Sink_mappings/castle_source_sink_mapping.json",
        "lookup_by": "filename_without_ext",
    },
    "PrimeVul": {
        "name": "PrimeVul",
        "mapping_path": "/Users/flaviogottschalk/dev/BachelorArbeit/Source_Sink_mappings/source_sink_mapping_clean_PrimeVul.json",
        "lookup_by": "filename_without_ext",
    },
    "Juliet": {
        "name": "Juliet",
        "mapping_base_dir": "/Users/flaviogottschalk/dev/BachelorArbeit/Source_Sink_mappings/Source_Sink_Mappings_CUT",
        "mapping_pattern": "Juliet{cwe}_source_sink_mapping_CURATED.json",
        "lookup_by": "filename_with_ext",
    },
}


def load_source_sink_mapping(json_path):
    """
    Load the JSON mapping file that defines which sources/sinks to use for each binary.

    Args:
        json_path: Path to the JSON mapping file

    Returns:
        dict: Mapping of binary names to sources/sinks
    """
    try:
        with open(json_path, "r") as f:
            mapping = json.load(f)
        log.info(
            "SingleBinaryRunner",
            f"Loaded source/sink mapping for {len(mapping)} binaries from {json_path}",
        )
        return mapping
    except FileNotFoundError:
        log.error("SingleBinaryRunner", f"Mapping file not found: {json_path}")
        return None
    except json.JSONDecodeError as e:
        log.error("SingleBinaryRunner", f"Invalid JSON in mapping file: {e}")
        return None
    except Exception as e:
        log.error("SingleBinaryRunner", f"Error loading mapping file: {e}")
        return None


def detect_dataset_type(binary_path):
    """
    Auto-detect dataset type from the binary path.

    Returns:
        tuple: (dataset_type, cwe) where cwe is only set for Juliet
    """
    path_lower = binary_path.lower()
    path_parts = binary_path.replace("\\", "/").split("/")

    # Check for Juliet (look for CWE folder pattern)
    for part in path_parts:
        if part.startswith("CWE") and len(part) > 3:
            return "Juliet", part  # e.g., ("Juliet", "CWE121")

    # Check for dataset keywords in path
    if "castle" in path_lower:
        return "CASTLE", None
    elif "primevul" in path_lower:
        return "PrimeVul", None

    # Default to enabling all sources/sinks
    return "Other", None


def load_mapping_for_dataset(dataset_type, cwe=None):
    """
    Load the appropriate source/sink mapping for a dataset.

    Args:
        dataset_type: One of "CASTLE", "PrimeVul", "Juliet", "Other"
        cwe: For Juliet, the CWE identifier (e.g., "CWE121")

    Returns:
        tuple: (mapping_dict, lookup_method)
    """
    if dataset_type == "Other":
        return {}, "filename_without_ext"

    config = DATASET_CONFIGS.get(dataset_type)
    if not config:
        log.warn("SingleBinaryRunner", f"Unknown dataset: {dataset_type}")
        return {}, "filename_without_ext"

    if dataset_type == "Juliet":
        if not cwe:
            log.warn("SingleBinaryRunner", "Juliet requires CWE to load mapping")
            return {}, config.get("lookup_by", "filename_with_ext")

        mapping_file = config["mapping_pattern"].format(cwe=cwe)
        mapping_path = os.path.join(config["mapping_base_dir"], mapping_file)

        if os.path.exists(mapping_path):
            mapping = load_source_sink_mapping(mapping_path)
            return mapping or {}, config.get("lookup_by", "filename_with_ext")
        else:
            log.warn("SingleBinaryRunner", f"Juliet mapping not found: {mapping_path}")
            return {}, config.get("lookup_by", "filename_with_ext")
    else:
        # CASTLE or PrimeVul
        mapping_path = config.get("mapping_path")
        if mapping_path and os.path.exists(mapping_path):
            mapping = load_source_sink_mapping(mapping_path)
            return mapping or {}, config.get("lookup_by", "filename_without_ext")
        else:
            log.warn("SingleBinaryRunner", f"Mapping not found: {mapping_path}")
            return {}, config.get("lookup_by", "filename_without_ext")


def apply_source_sink_filter(config_model, source_functions=None, sink_functions=None):
    """
    Disable all sources/sinks in the config, then enable only the specified ones.
    This modifies the config_model in-place.

    Args:
        config_model: The ConfigModel to modify
        source_functions: List of source function names to enable
        sink_functions: List of sink function names to enable
    """
    # Get all functions
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
                log.info("SingleBinaryRunner", f"Enabled source: {func.name}")

    # Enable only the specified sinks
    if sink_functions:
        for func in all_sinks:
            if func.name in sink_functions:
                func.enabled = True
                log.info("SingleBinaryRunner", f"Enabled sink: {func.name}")


def init(path_ctr):
    """
    Initialize the single binary runner with the shared path_ctr from the plugin.
    Registers a BN plugin command to run analysis on a single binary.
    """

    class SingleBinaryRunnerTask(BackgroundTask):
        """
        Background task for running analysis on a single binary file.
        """

        def __init__(
            self,
            path_ctr,
            binary_path,
            output_dir,
            source_sink_mapping,
            dataset_type,
            lookup_by,
        ):
            fname = os.path.basename(binary_path)
            super().__init__(f"Running analysis on {fname}...", True)
            self.path_ctr = path_ctr
            self.binary_path = binary_path
            self.output_dir = output_dir
            self.log_capture = LogCapture()
            self.source_sink_mapping = source_sink_mapping
            self.dataset_type = dataset_type
            self.lookup_by = lookup_by  # 'filename_with_ext' or 'filename_without_ext'

            # Save the ORIGINAL config state
            config_model = self.path_ctr.config_ctr.config_model
            self.original_states = {}

            # Save original state of all sources
            for func in config_model.get_functions(fun_type="Sources"):
                self.original_states[("source", func.name)] = func.enabled

            # Save original state of all sinks
            for func in config_model.get_functions(fun_type="Sinks"):
                self.original_states[("sink", func.name)] = func.enabled

            log.info(
                "SingleBinaryRunner",
                f"Saved original state: {len([k for k in self.original_states.keys() if k[0] == 'source'])} sources, "
                f"{len([k for k in self.original_states.keys() if k[0] == 'sink'])} sinks",
            )

        def run(self):
            """
            Run the analysis on the single binary.
            """
            start_time = time.time()
            fname = os.path.basename(self.binary_path)

            os.makedirs(self.output_dir, exist_ok=True)

            log.info("SingleBinaryRunner", f"Processing {fname}")
            log.info("SingleBinaryRunner", f"Output directory: {self.output_dir}")

            # Load binary in BN - auto-detect format
            try:
                bv = load(self.binary_path)
                if not bv:
                    log.error("SingleBinaryRunner", f"Could not open {fname}")
                    interaction.show_message_box(
                        "Error",
                        f"Could not open binary:\n{self.binary_path}",
                        buttons=interaction.MessageBoxButtonSet.OKButtonSet,
                    )
                    return
                bv.update_analysis_and_wait()
                log.info("SingleBinaryRunner", f"Loaded {fname} as {bv.view_type}")
            except Exception as e:
                log.error("SingleBinaryRunner", f"Failed to load {fname}: {e}")
                interaction.show_message_box(
                    "Error",
                    f"Failed to load binary:\n{self.binary_path}\n\nError: {e}",
                    buttons=interaction.MessageBoxButtonSet.OKButtonSet,
                )
                return

            try:
                # Initialize log capture variable
                captured_logs = []

                # Get config model
                config_model = self.path_ctr.config_ctr.config_model

                # Determine the key for JSON mapping lookup based on lookup_by setting
                if self.lookup_by == "filename_with_ext":
                    # Juliet: Use filename as-is with extension
                    lookup_key = fname
                else:
                    # CASTLE/PrimeVul: Remove extension
                    lookup_key = os.path.splitext(fname)[0]

                # Check if we're using JSON mapping mode or enable-all mode
                if (
                    len(self.source_sink_mapping) > 0
                    and lookup_key in self.source_sink_mapping
                ):
                    # JSON mapping mode: Found specific mapping for this binary
                    mapping = self.source_sink_mapping[lookup_key]
                    sources = mapping.get("sources", [])
                    sinks = mapping.get("sinks", [])

                    log.info(
                        "SingleBinaryRunner",
                        f"Found mapping for {fname} (matched as {lookup_key}) - Sources: {sources}, Sinks: {sinks}",
                    )

                    # Apply the filter (disable all, enable only specified)
                    apply_source_sink_filter(config_model, sources, sinks)
                    log.info(
                        "SingleBinaryRunner", f"Applied source/sink filter for {fname}"
                    )
                else:
                    # Enable-all mode OR binary not found in JSON
                    if len(self.source_sink_mapping) == 0:
                        log.info(
                            "SingleBinaryRunner",
                            f"Enable-all mode: activating ALL sources and sinks for {fname}",
                        )
                    else:
                        log.info(
                            "SingleBinaryRunner",
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
                        "SingleBinaryRunner",
                        f"Enabled {len(all_sources)} sources and {len(all_sinks)} sinks for {fname}",
                    )

                # Attach the BinaryView so path_ctr works
                self.path_ctr._bv = bv

                # Clear old paths before processing this binary
                if self.path_ctr.path_tree_view:
                    cleared_count = self.path_ctr.path_tree_view.clear_all_paths()
                    log.info(
                        "SingleBinaryRunner",
                        f"Cleared {cleared_count} existing path(s) before processing {fname}",
                    )
                    time.sleep(0.1)
                else:
                    log.warn(
                        "SingleBinaryRunner", f"No PathTreeView available for {fname}"
                    )
                    return

                # Run Mole path finding with log capture
                log.info("SingleBinaryRunner", f"Starting path finding for {fname}")

                # Start capturing logs
                self.log_capture.start_capture()

                self.path_ctr.find_paths()

                # Wait until path finding is finished
                while not self.path_ctr.thread_finished:
                    if self.cancelled:
                        log.info(
                            "SingleBinaryRunner",
                            "Analysis cancelled during path finding",
                        )
                        self.log_capture.stop_capture()
                        return
                    time.sleep(0.5)

                # Stop log capture and get captured logs
                self.log_capture.stop_capture()
                captured_logs = self.log_capture.get_logs()

                log.info(
                    "SingleBinaryRunner",
                    f"Captured {len(captured_logs)} log entries during path finding",
                )

                log.info("SingleBinaryRunner", f"Path finding completed for {fname}")

                # Verify path_tree_view is available
                if not self.path_ctr.path_tree_view:
                    log.warn(
                        "SingleBinaryRunner",
                        f"No PathTreeView available after path finding for {fname}",
                    )
                    return

                # Get all path IDs from the model
                path_ids = list(self.path_ctr.path_tree_view.model.path_ids)
                if not path_ids:
                    log.info("SingleBinaryRunner", f"No paths found in {fname}")

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
                            "SingleBinaryRunner",
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
                    log.info("SingleBinaryRunner", f"Saved no-paths info to {out_file}")

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
                            "SingleBinaryRunner",
                            f"Saved debug logs to {debug_log_file}",
                        )

                    elapsed = time.time() - start_time
                    interaction.show_message_box(
                        "Analysis Complete",
                        f"No paths found in {fname}\n\nTime: {elapsed:.2f}s\nOutput: {self.output_dir}",
                        buttons=interaction.MessageBoxButtonSet.OKButtonSet,
                    )
                    return

                log.info(
                    "SingleBinaryRunner", f"Found {len(path_ids)} path(s) in {fname}"
                )

                # Run AI analysis on all paths
                log.info(
                    "SingleBinaryRunner",
                    f"Starting AI analysis for {len(path_ids)} path(s)",
                )
                self.path_ctr.analyze_paths(path_ids)

                # Wait until AI analysis finishes
                while not self.path_ctr.thread_finished:
                    if self.cancelled:
                        log.info(
                            "SingleBinaryRunner",
                            "Analysis cancelled during AI analysis",
                        )
                        return
                    time.sleep(0.5)

                log.info("SingleBinaryRunner", f"AI analysis completed for {fname}")

                # Collect results
                results = []
                for pid in path_ids:
                    try:
                        path = self.path_ctr.path_tree_view.get_path(pid)
                        if not path:
                            log.warn(
                                "SingleBinaryRunner", f"Could not retrieve path {pid}"
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
                        else:
                            simplified_data["ai_report"] = None

                        results.append(simplified_data)
                    except Exception as e:
                        log.error(
                            "SingleBinaryRunner", f"Failed to export path {pid}: {e}"
                        )
                        continue

                # Save JSON report
                out_file = os.path.join(self.output_dir, f"{fname}.json")
                with open(out_file, "w") as fp:
                    json.dump(results, fp, indent=2)

                log.info(
                    "SingleBinaryRunner", f"Saved {len(results)} path(s) to {out_file}"
                )

                # Clear paths after saving
                if self.path_ctr.path_tree_view:
                    cleared_count = self.path_ctr.path_tree_view.clear_all_paths()
                    log.info(
                        "SingleBinaryRunner",
                        f"Cleared {cleared_count} path(s) after processing {fname}",
                    )

                elapsed = time.time() - start_time
                interaction.show_message_box(
                    "Analysis Complete",
                    f"Successfully analyzed {fname}\n\nPaths found: {len(results)}\nTime: {elapsed:.2f}s\nOutput: {self.output_dir}",
                    buttons=interaction.MessageBoxButtonSet.OKButtonSet,
                )

            except Exception as e:
                log.error("SingleBinaryRunner", f"Error processing {fname}: {e}")
                interaction.show_message_box(
                    "Error",
                    f"Error processing {fname}:\n\n{e}",
                    buttons=interaction.MessageBoxButtonSet.OKButtonSet,
                )

                try:
                    self.log_capture.stop_capture()
                except Exception:
                    pass

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
                            "SingleBinaryRunner",
                            "Restored original source/sink states",
                        )
                except Exception as e:
                    log.warn(
                        "SingleBinaryRunner", f"Could not restore original states: {e}"
                    )

                # Cleanup
                try:
                    if bv:
                        bv.file.close()
                        del bv
                except Exception as e:
                    log.error("SingleBinaryRunner", f"Error closing {fname}: {e}")

    class MultiBinaryRunnerTask(BackgroundTask):
        """
        Background task for running analysis on multiple binary files sequentially.
        This wrapper ensures the UI doesn't freeze while processing multiple binaries.
        """

        def __init__(self, path_ctr, binaries_dir, output_dir, selected_binaries):
            super().__init__(f"Processing {len(selected_binaries)} binaries...", True)
            self.path_ctr = path_ctr
            self.binaries_dir = binaries_dir
            self.output_dir = output_dir
            self.selected_binaries = selected_binaries

        def run(self):
            """
            Process all selected binaries sequentially in the background.
            """
            total = len(self.selected_binaries)
            log.info(
                "MultiBinaryRunner", f"Starting batch processing of {total} binaries"
            )

            for i, fname in enumerate(self.selected_binaries):
                if self.cancelled:
                    log.info("MultiBinaryRunner", "Batch processing cancelled by user")
                    break

                self.progress = f"Processing {fname} ({i + 1}/{total})"
                binary_path = os.path.join(self.binaries_dir, fname)

                # Auto-detect dataset type from binary path
                dataset_type, cwe = detect_dataset_type(binary_path)

                if i == 0:  # Log detection info only once
                    log.info(
                        "MultiBinaryRunner",
                        f"Auto-detected dataset: {dataset_type}"
                        + (f" (CWE: {cwe})" if cwe else ""),
                    )

                # Auto-load appropriate source/sink mapping
                source_sink_mapping, lookup_by = load_mapping_for_dataset(
                    dataset_type, cwe
                )

                if i == 0:
                    if source_sink_mapping:
                        log.info(
                            "MultiBinaryRunner",
                            f"Loaded {len(source_sink_mapping)} mappings for {dataset_type} (lookup by: {lookup_by})",
                        )
                    else:
                        log.info(
                            "MultiBinaryRunner",
                            f"No mapping available for {dataset_type} - will enable ALL sources/sinks",
                        )

                # Process this binary using the existing SingleBinaryRunnerTask logic inline
                self._process_single_binary(
                    binary_path, source_sink_mapping or {}, dataset_type, lookup_by
                )

                log.info("MultiBinaryRunner", f"Completed {i + 1}/{total}: {fname}")

            if not self.cancelled:
                log.info("MultiBinaryRunner", f"All {total} binaries processed!")

        def _process_single_binary(
            self, binary_path, source_sink_mapping, dataset_type, lookup_by
        ):
            """
            Process a single binary (inlined logic from SingleBinaryRunnerTask).
            """
            fname = os.path.basename(binary_path)
            log_capture = LogCapture()

            # Save the ORIGINAL config state
            config_model = self.path_ctr.config_ctr.config_model
            original_states = {}

            for func in config_model.get_functions(fun_type="Sources"):
                original_states[("source", func.name)] = func.enabled
            for func in config_model.get_functions(fun_type="Sinks"):
                original_states[("sink", func.name)] = func.enabled

            os.makedirs(self.output_dir, exist_ok=True)

            log.info("MultiBinaryRunner", f"Processing {fname}")

            # Load binary
            try:
                bv = load(binary_path)
                if not bv:
                    log.error("MultiBinaryRunner", f"Could not open {fname}")
                    return
                bv.update_analysis_and_wait()
                log.info("MultiBinaryRunner", f"Loaded {fname} as {bv.view_type}")
            except Exception as e:
                log.error("MultiBinaryRunner", f"Failed to load {fname}: {e}")
                return

            try:
                # Determine lookup key
                if lookup_by == "filename_with_ext":
                    lookup_key = fname
                else:
                    lookup_key = os.path.splitext(fname)[0]

                # Apply source/sink filter
                if len(source_sink_mapping) > 0 and lookup_key in source_sink_mapping:
                    mapping = source_sink_mapping[lookup_key]
                    sources = mapping.get("sources", [])
                    sinks = mapping.get("sinks", [])
                    log.info(
                        "MultiBinaryRunner",
                        f"Found mapping for {fname} - Sources: {sources}, Sinks: {sinks}",
                    )
                    apply_source_sink_filter(config_model, sources, sinks)
                else:
                    all_sources = config_model.get_functions(fun_type="Sources")
                    all_sinks = config_model.get_functions(fun_type="Sinks")
                    for func in all_sources:
                        func.enabled = True
                    for func in all_sinks:
                        func.enabled = True

                # Attach BinaryView
                self.path_ctr._bv = bv

                # Clear old paths
                if self.path_ctr.path_tree_view:
                    self.path_ctr.path_tree_view.clear_all_paths()
                    time.sleep(0.1)
                else:
                    log.warn(
                        "MultiBinaryRunner", f"No PathTreeView available for {fname}"
                    )
                    return

                # Run path finding
                log_capture.start_capture()
                self.path_ctr.find_paths()

                while not self.path_ctr.thread_finished:
                    if self.cancelled:
                        log_capture.stop_capture()
                        return
                    time.sleep(0.5)

                log_capture.stop_capture()
                # Note: log_capture.get_logs() available if debug logging needed

                if not self.path_ctr.path_tree_view:
                    return

                path_ids = list(self.path_ctr.path_tree_view.model.path_ids)
                if not path_ids:
                    log.info("MultiBinaryRunner", f"No paths found in {fname}")
                    # Save no-paths result
                    no_paths_result = {
                        "binary_file": fname,
                        "status": "no_paths_detected",
                        "message": f"No vulnerability paths detected in {fname}",
                    }
                    out_file = os.path.join(self.output_dir, f"{fname}.json")
                    with open(out_file, "w") as fp:
                        json.dump([no_paths_result], fp, indent=2)
                    return

                log.info(
                    "MultiBinaryRunner", f"Found {len(path_ids)} path(s) in {fname}"
                )

                # Run AI analysis
                self.path_ctr.analyze_paths(path_ids)

                while not self.path_ctr.thread_finished:
                    if self.cancelled:
                        return
                    time.sleep(0.5)

                log.info("MultiBinaryRunner", f"AI analysis completed for {fname}")

                # Collect and save results
                import math

                results = []
                for pid in path_ids:
                    try:
                        path = self.path_ctr.path_tree_view.get_path(pid)
                        if not path:
                            continue

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

                        # Path complexity
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

                        # AI report
                        if hasattr(path, "ai_report") and path.ai_report:
                            simplified_data["ai_report"] = {
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
                        else:
                            simplified_data["ai_report"] = None

                        results.append(simplified_data)
                    except Exception as e:
                        log.error(
                            "MultiBinaryRunner", f"Failed to export path {pid}: {e}"
                        )

                # Save results
                out_file = os.path.join(self.output_dir, f"{fname}.json")
                with open(out_file, "w") as fp:
                    json.dump(results, fp, indent=2)
                log.info(
                    "MultiBinaryRunner", f"Saved {len(results)} path(s) to {out_file}"
                )

                # Clear paths
                if self.path_ctr.path_tree_view:
                    self.path_ctr.path_tree_view.clear_all_paths()

            except Exception as e:
                log.error("MultiBinaryRunner", f"Error processing {fname}: {e}")
                try:
                    log_capture.stop_capture()
                except Exception:
                    pass

            finally:
                # Restore original states
                try:
                    for func in config_model.get_functions(fun_type="Sources"):
                        key = ("source", func.name)
                        if key in original_states:
                            func.enabled = original_states[key]
                    for func in config_model.get_functions(fun_type="Sinks"):
                        key = ("sink", func.name)
                        if key in original_states:
                            func.enabled = original_states[key]
                except Exception as e:
                    log.warn(
                        "MultiBinaryRunner", f"Could not restore original states: {e}"
                    )

                # Cleanup
                try:
                    if bv:
                        bv.file.close()
                        del bv
                except Exception as e:
                    log.error("MultiBinaryRunner", f"Error closing {fname}: {e}")

    def run_single_binary(bv=None):
        """
        Start the single binary runner with simplified UI prompts.
        Allows selecting one or multiple binaries from a directory.
        Dataset type and source/sink mapping are auto-detected from path.
        """
        # Step 1: Ask user to select the output directory
        output_dir = interaction.get_directory_name_input(
            "Select Output Directory for Results", default_name=""
        )

        if not output_dir:
            log.info("SingleBinaryRunner", "User cancelled output directory selection")
            return

        # Step 2: Ask user to select the binaries directory
        binaries_dir = interaction.get_directory_name_input(
            "Select Directory Containing Binaries", default_name=""
        )

        if not binaries_dir:
            log.info(
                "SingleBinaryRunner", "User cancelled binaries directory selection"
            )
            return

        # Get all files in the directory (non-recursive)
        try:
            all_files = [
                f
                for f in os.listdir(binaries_dir)
                if os.path.isfile(os.path.join(binaries_dir, f))
                and not f.startswith(".")  # Skip hidden files
                and not f.endswith(".json")  # Skip JSON files
                and not f.endswith(".txt")  # Skip text files
            ]
            all_files.sort()
        except Exception as e:
            log.error("SingleBinaryRunner", f"Could not list directory: {e}")
            interaction.show_message_box(
                "Error",
                f"Could not list directory:\n{binaries_dir}\n\nError: {e}",
                buttons=interaction.MessageBoxButtonSet.OKButtonSet,
            )
            return

        if not all_files:
            log.info("SingleBinaryRunner", "No binary files found in directory")
            interaction.show_message_box(
                "No Files Found",
                f"No binary files found in:\n{binaries_dir}",
                buttons=interaction.MessageBoxButtonSet.OKButtonSet,
            )
            return

        # Step 3: Ask user to choose selection mode
        mode_choice = interaction.get_choice_input(
            f"Found {len(all_files)} files. How do you want to select?",
            "Selection Mode",
            [
                f"Process ALL {len(all_files)} binaries",
                "Select specific binaries (comma-separated indices)",
                "Select a single binary from list",
            ],
        )

        if mode_choice is None:
            log.info("SingleBinaryRunner", "User cancelled selection mode")
            return

        selected_binaries = []

        if mode_choice == 0:
            # Process all binaries
            selected_binaries = all_files
            log.info("SingleBinaryRunner", f"Selected all {len(all_files)} binaries")

        elif mode_choice == 1:
            # Show numbered list and ask for indices
            file_list = "\n".join([f"{i}: {f}" for i, f in enumerate(all_files)])

            # Show the list first
            indices_str = interaction.get_text_line_input(
                f"Files (0-{len(all_files) - 1}):\n{file_list[:2000]}{'...' if len(file_list) > 2000 else ''}\n\nEnter indices (comma-separated, e.g., 0,2,5-10):",
                "Select Binaries",
            )

            if not indices_str:
                log.info("SingleBinaryRunner", "User cancelled index selection")
                return

            # Handle bytes input (macOS returns bytes)
            if isinstance(indices_str, bytes):
                indices_str = indices_str.decode("utf-8")

            # Parse indices (supports ranges like "0,2,5-10")
            try:
                indices = set()
                for part in indices_str.replace(" ", "").split(","):
                    if "-" in part:
                        start, end = part.split("-")
                        indices.update(range(int(start), int(end) + 1))
                    else:
                        indices.add(int(part))

                selected_binaries = [
                    all_files[i] for i in sorted(indices) if 0 <= i < len(all_files)
                ]
            except Exception as e:
                log.error("SingleBinaryRunner", f"Invalid index format: {e}")
                interaction.show_message_box(
                    "Invalid Input",
                    f"Could not parse indices: {indices_str}\n\nUse format like: 0,2,5-10",
                    buttons=interaction.MessageBoxButtonSet.OKButtonSet,
                )
                return

        elif mode_choice == 2:
            # Single selection from dropdown
            file_choice = interaction.get_choice_input(
                "Select binary to analyze",
                "Binary Selection",
                all_files,
            )

            if file_choice is None:
                log.info("SingleBinaryRunner", "User cancelled binary selection")
                return

            selected_binaries = [all_files[file_choice]]

        if not selected_binaries:
            log.info("SingleBinaryRunner", "No binaries selected")
            return

        log.info(
            "SingleBinaryRunner", f"Will process {len(selected_binaries)} binary(ies)"
        )

        # Start the multi-binary runner as a background task
        task = MultiBinaryRunnerTask(
            path_ctr, binaries_dir, output_dir, selected_binaries
        )
        task.start()

    # Register command in BN
    PluginCommand.register(
        "Mole\\Run Single Binary",
        "Run Find Paths + AI Analysis on a Single Binary (Background)",
        run_single_binary,
    )
