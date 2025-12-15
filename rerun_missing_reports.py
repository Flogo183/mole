#!/usr/bin/env python3
"""
Script to rerun AI analysis for paths that are missing vulnerability reports.

This script scans JSON result files, identifies paths without AI reports, and reruns
only those specific paths while preserving the existing results for paths that succeeded.

Supports three datasets:
- CASTLE: Uses castle_source_sink_mapping.json
- PrimeVul: Uses primevul_source_sink_mapping.json
- Juliet: Uses Juliet<CWE>_source_sink_mapping_CURATED.json (auto-detected from binary path)
"""

import os
import json
import time
from binaryninja import PluginCommand, load, interaction
from mole.common.log import log
from mole.common.task import BackgroundTask


# Dataset configurations
DATASET_CONFIGS = {
    "CASTLE": {
        "name": "CASTLE",
        "mapping_path": "/Users/flaviogottschalk/dev/BachelorArbeit/Source_Sink_mappings/castle_source_sink_mapping.json",
        "lookup_by": "filename_without_ext",  # Look up by filename without extension
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
        "lookup_by": "filename_with_ext",  # Juliet looks up by filename with extension
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
            "RerunMissingReports",
            f"Loaded source/sink mapping for {len(mapping)} binaries",
        )
        return mapping
    except Exception as e:
        log.error("RerunMissingReports", f"Error loading source/sink mapping: {e}")
        return None


def load_mapping_for_dataset(dataset_name, binary_path=None):
    """
    Load the appropriate source/sink mapping for a dataset.

    Args:
        dataset_name: One of "CASTLE", "PrimeVul", "Juliet"
        binary_path: For Juliet, the binary path is used to detect the CWE

    Returns:
        tuple: (mapping_dict, lookup_method) where lookup_method is 'filename_with_ext' or 'filename_without_ext'
    """
    config = DATASET_CONFIGS.get(dataset_name)
    if not config:
        log.error("RerunMissingReports", f"Unknown dataset: {dataset_name}")
        return None, None

    if dataset_name == "Juliet":
        # For Juliet, we need to detect the CWE from the binary path
        if not binary_path:
            log.error(
                "RerunMissingReports", "Juliet requires binary_path to detect CWE"
            )
            return None, config.get("lookup_by")

        # Try to extract CWE from path (e.g., /path/to/CWE121/binary.out)
        cwe = None
        path_parts = binary_path.replace("\\", "/").split("/")
        for part in path_parts:
            if part.startswith("CWE") and len(part) > 3:
                cwe = part  # e.g., "CWE121"
                break

        if not cwe:
            log.warn(
                "RerunMissingReports", f"Could not detect CWE from path: {binary_path}"
            )
            return None, config.get("lookup_by")

        mapping_file = config["mapping_pattern"].format(cwe=cwe)
        mapping_path = os.path.join(config["mapping_base_dir"], mapping_file)

        if os.path.exists(mapping_path):
            mapping = load_source_sink_mapping(mapping_path)
            return mapping, config.get("lookup_by")
        else:
            log.warn("RerunMissingReports", f"Juliet mapping not found: {mapping_path}")
            return None, config.get("lookup_by")
    else:
        # CASTLE or PrimeVul - single mapping file
        mapping_path = config.get("mapping_path")
        if mapping_path and os.path.exists(mapping_path):
            mapping = load_source_sink_mapping(mapping_path)
            return mapping, config.get("lookup_by")
        else:
            log.warn(
                "RerunMissingReports",
                f"Mapping not found for {dataset_name}: {mapping_path}",
            )
            return None, config.get("lookup_by")


def apply_source_sink_filter(config_model, source_functions=None, sink_functions=None):
    """
    Disable all sources/sinks in the config, then enable only the specified ones.

    Args:
        config_model: The ConfigModel to modify
        source_functions: List of source function names to enable
        sink_functions: List of sink function names to enable
    """
    # Get all functions
    all_sources = config_model.get_functions(fun_type="Sources")
    all_sinks = config_model.get_functions(fun_type="Sinks")

    # Disable ALL sources and sinks
    for func in all_sources:
        func.enabled = False
    for func in all_sinks:
        func.enabled = False

    # Enable only the specified sources
    if source_functions:
        for source_name in source_functions:
            for func in all_sources:
                if func.name == source_name:
                    func.enabled = True
                    log.info("RerunMissingReports", f"Enabled source: {func.name}")
                    break

    # Enable only the specified sinks
    if sink_functions:
        for sink_name in sink_functions:
            for func in all_sinks:
                if func.name == sink_name:
                    func.enabled = True
                    log.info("RerunMissingReports", f"Enabled sink: {func.name}")
                    break


def scan_json_files_for_missing_reports(json_files):
    """
    Scan JSON files and identify which binaries have paths without AI reports.
    Also handles completely missing JSON files (treats as needing full analysis).

    Args:
        json_files: List of JSON file paths to scan

    Returns:
        dict: {
            'model_dir/binary.json': {
                'binary_file': 'binary_name',
                'missing_path_ids': [1, 3, 5] or 'ALL',
                'total_paths': 10 or 0,
                'model_dir': 'path/to/model/results',
                'file_missing': False or True
            }
        }
    """
    missing_reports = {}

    for json_file in json_files:
        # Check if file exists
        if not os.path.exists(json_file):
            # File completely missing - extract binary name from filename
            json_filename = os.path.basename(json_file)
            binary_name = (
                json_filename[:-5] if json_filename.endswith(".json") else json_filename
            )
            model_dir = os.path.dirname(json_file)

            missing_reports[json_file] = {
                "binary_file": binary_name,
                "missing_path_ids": "ALL",  # Special marker for complete file missing
                "total_paths": 0,
                "model_dir": model_dir,
                "json_file": json_file,
                "file_missing": True,
            }

            log.warn(
                "RerunMissingReports",
                f"JSON file missing - will run complete analysis for {binary_name}",
            )
            continue

        try:
            with open(json_file, "r") as f:
                data = json.load(f)

            if not isinstance(data, list) or len(data) == 0:
                continue

            # Extract binary name and check for missing reports
            binary_name = None
            missing_path_ids = []
            total_paths = len(data)

            for path_data in data:
                if not binary_name and "binary_file" in path_data:
                    binary_name = path_data["binary_file"]

                # Check if ai_report is missing or None
                if "path_id" in path_data:
                    ai_report = path_data.get("ai_report", None)
                    if ai_report is None:
                        missing_path_ids.append(path_data["path_id"])

            # Only add to results if there are missing reports
            if missing_path_ids and binary_name:
                model_dir = os.path.dirname(json_file)
                missing_reports[json_file] = {
                    "binary_file": binary_name,
                    "missing_path_ids": sorted(missing_path_ids),
                    "total_paths": total_paths,
                    "model_dir": model_dir,
                    "json_file": json_file,
                    "file_missing": False,
                }

                log.info(
                    "RerunMissingReports",
                    f"Found {len(missing_path_ids)}/{total_paths} missing reports in {binary_name}",
                )

        except Exception as e:
            log.error("RerunMissingReports", f"Error scanning {json_file}: {e}")

    return missing_reports


def load_binary_and_find_paths(
    binary_path, path_ctr, source_sink_mapping=None, lookup_by="filename_without_ext"
):
    """
    Load a binary and run path finding to get all paths.

    Args:
        binary_path: Path to the binary file
        path_ctr: PathController instance
        source_sink_mapping: Optional dict mapping binary names to sources/sinks
        lookup_by: How to look up the binary in the mapping: 'filename_with_ext' or 'filename_without_ext'

    Returns:
        tuple: (bv, path_ids) or (None, None) on failure
    """
    fname = os.path.basename(binary_path)
    fname_without_ext = os.path.splitext(fname)[0]

    # Determine lookup key based on dataset type
    lookup_key = fname if lookup_by == "filename_with_ext" else fname_without_ext

    try:
        bv = load(binary_path)
        if not bv:
            log.error("RerunMissingReports", f"Could not open {binary_path}")
            return None, None

        bv.update_analysis_and_wait()
        log.info("RerunMissingReports", f"Loaded {fname}")

        # Attach binary view
        path_ctr._bv = bv

        # Clear old paths
        if path_ctr.path_tree_view:
            path_ctr.path_tree_view.clear_all_paths()

        # Apply source/sink filter if mapping provided
        if source_sink_mapping and lookup_key in source_sink_mapping:
            mapping = source_sink_mapping[lookup_key]
            sources = mapping.get("sources", [])
            sinks = mapping.get("sinks", [])
            log.info(
                "RerunMissingReports",
                f"Applying source/sink filter for {fname}: sources={sources}, sinks={sinks}",
            )
            apply_source_sink_filter(path_ctr.config_ctr.config_model, sources, sinks)
        else:
            log.info(
                "RerunMissingReports",
                f"No source/sink mapping for {lookup_key}, using current settings",
            )

        # Run path finding
        log.info("RerunMissingReports", f"Finding paths in {fname}")
        path_ctr.find_paths()

        # Wait for completion
        while not path_ctr.thread_finished:
            time.sleep(0.5)

        # Get path IDs
        if not path_ctr.path_tree_view:
            log.error("RerunMissingReports", f"No PathTreeView for {fname}")
            return bv, None

        path_ids = list(path_ctr.path_tree_view.model.path_ids)
        log.info("RerunMissingReports", f"Found {len(path_ids)} total paths in {fname}")

        return bv, path_ids

    except Exception as e:
        log.error("RerunMissingReports", f"Error loading {fname}: {e}")
        return None, None


def rerun_missing_paths(
    binary_path,
    missing_path_ids,
    json_file,
    path_ctr,
    source_sink_mapping=None,
    lookup_by="filename_without_ext",
):
    """
    Rerun AI analysis for specific missing paths and merge with existing results.

    Args:
        binary_path: Path to the binary file
        missing_path_ids: List of path IDs that need AI analysis
        json_file: Path to the JSON file to update
        path_ctr: PathController instance
        source_sink_mapping: Dict mapping binary names to their sources/sinks
        lookup_by: How to look up the binary in the mapping: 'filename_with_ext' or 'filename_without_ext'

    Returns:
        bool: True if successful, False otherwise
    """
    fname = os.path.basename(binary_path)

    # Load binary and find all paths
    bv, all_path_ids = load_binary_and_find_paths(
        binary_path, path_ctr, source_sink_mapping, lookup_by
    )

    if not bv or all_path_ids is None:
        log.error(
            "RerunMissingReports", f"Failed to load binary or find paths for {fname}"
        )
        return False

    try:
        # Handle 'ALL' case (file was completely missing)
        if missing_path_ids == "ALL":
            log.info(
                "RerunMissingReports",
                f"JSON file was missing - analyzing ALL {len(all_path_ids)} paths in {fname}",
            )
            available_missing_ids = all_path_ids
        else:
            # Verify that missing path IDs exist
            available_missing_ids = [
                pid for pid in missing_path_ids if pid in all_path_ids
            ]

            if not available_missing_ids:
                log.warn(
                    "RerunMissingReports",
                    f"None of the missing path IDs found in current analysis of {fname}",
                )
                return False

            if len(available_missing_ids) < len(missing_path_ids):
                log.warn(
                    "RerunMissingReports",
                    f"Only {len(available_missing_ids)}/{len(missing_path_ids)} missing paths found in {fname}",
                )

        # Run AI analysis on missing paths (or all paths if file was missing)
        log.info(
            "RerunMissingReports",
            f"Running AI analysis on {len(available_missing_ids)} path(s) in {fname}",
        )

        path_ctr.analyze_paths(available_missing_ids)

        # Wait for AI analysis to complete
        while not path_ctr.thread_finished:
            time.sleep(0.5)

        log.info("RerunMissingReports", f"AI analysis completed for {fname}")

        # Load existing results or create new structure
        if os.path.exists(json_file):
            with open(json_file, "r") as f:
                existing_results = json.load(f)
            existing_by_id = {
                item["path_id"]: item for item in existing_results if "path_id" in item
            }
        else:
            # File didn't exist - create new structure
            log.info("RerunMissingReports", f"Creating new JSON file for {fname}")
            existing_results = []
            existing_by_id = {}

        # Collect new results for the missing paths
        for pid in available_missing_ids:
            try:
                path = path_ctr.path_tree_view.get_path(pid)
                if not path:
                    log.warn("RerunMissingReports", f"Could not retrieve path {pid}")
                    continue

                # Check if path already exists in results or needs to be created
                if pid in existing_by_id:
                    if hasattr(path, "ai_report") and path.ai_report:
                        ai_data = {
                            "truePositive": path.ai_report.truePositive,
                            "vulnerabilityClass": str(path.ai_report.vulnerabilityClass)
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
                        existing_by_id[pid]["ai_report"] = ai_data
                        log.info(
                            "RerunMissingReports", f"Updated AI report for path {pid}"
                        )
                    else:
                        log.warn(
                            "RerunMissingReports",
                            f"No AI report generated for path {pid}",
                        )
                else:
                    # Create new entry (file was missing or path wasn't in original results)
                    # Calculate path complexity
                    import math

                    num_instructions = len(path.insts) if hasattr(path, "insts") else 0
                    num_phi_calls = len(path.phiis) if hasattr(path, "phiis") else 0
                    num_branches = len(path.bdeps) if hasattr(path, "bdeps") else 0
                    complexity_score = (
                        0.5 * math.log(1 + num_branches)
                        + 0.3 * math.log(1 + num_phi_calls)
                        + 0.2 * math.log(1 + num_instructions)
                    )

                    new_entry = {
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
                            "structural_complexity_score": round(complexity_score, 4),
                        },
                    }

                    if hasattr(path, "ai_report") and path.ai_report:
                        new_entry["ai_report"] = {
                            "truePositive": path.ai_report.truePositive,
                            "vulnerabilityClass": str(path.ai_report.vulnerabilityClass)
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
                        new_entry["ai_analysis_errors"] = None
                        existing_by_id[pid] = new_entry
                        log.info(
                            "RerunMissingReports", f"Created new entry for path {pid}"
                        )
                    else:
                        new_entry["ai_report"] = None
                        new_entry["ai_analysis_errors"] = None
                        existing_by_id[pid] = new_entry
                        log.warn(
                            "RerunMissingReports",
                            f"No AI report generated for new path {pid}",
                        )

            except Exception as e:
                log.error("RerunMissingReports", f"Failed to process path {pid}: {e}")
                continue

        # Reconstruct the results list maintaining original order (or create new list if file was missing)
        if existing_results:
            # Preserve original order
            updated_results = [
                existing_by_id[item["path_id"]] if "path_id" in item else item
                for item in existing_results
            ]
        else:
            # New file - just convert dict to sorted list
            updated_results = [
                existing_by_id[pid] for pid in sorted(existing_by_id.keys())
            ]

        # Save updated results back to the same file
        with open(json_file, "w") as f:
            json.dump(updated_results, f, indent=2)

        log.info("RerunMissingReports", f"Updated results saved to {json_file}")

        # Cleanup
        if bv:
            bv.file.close()
            del bv

        return True

    except Exception as e:
        log.error("RerunMissingReports", f"Error rerunning paths for {fname}: {e}")
        return False


def init(path_ctr):
    """
    Initialize the rerun missing reports functionality with the shared path_ctr from the plugin.
    Registers a BN plugin command to rerun analysis for paths with missing AI reports.
    """

    def run_rerun_missing_reports(bv=None):
        """
        Start the rerun process for paths with missing AI reports.
        """
        # Step 1: Select dataset type
        dataset_choice = interaction.get_choice_input(
            "Select Dataset Type",
            "Which dataset are you processing?",
            ["CASTLE", "PrimeVul", "Juliet"],
        )

        if dataset_choice is None:
            log.info("RerunMissingReports", "User cancelled dataset selection")
            return

        dataset_name = ["CASTLE", "PrimeVul", "Juliet"][dataset_choice]
        log.info("RerunMissingReports", f"Selected dataset: {dataset_name}")

        # Show instructions
        interaction.show_message_box(
            "Rerun Missing AI Reports - Instructions",
            f"Dataset: {dataset_name}\n\n"
            "You will be asked to select:\n"
            "1. Results directory - folder containing JSON result files to scan\n"
            f"   (e.g., /path/to/Baseline_Results_{dataset_name}/model_name/)\n"
            f"2. Binaries directory (e.g., /path/to/Compiled_{dataset_name}_O0/)\n\n"
            "The tool will automatically scan all JSON files in the results directory\n"
            "and rerun AI analysis for any paths with missing reports (ai_report: null).\n\n"
            f"Source/Sink mapping will be automatically loaded for {dataset_name}.\n\n"
            "IMPORTANT: Make sure your Mole AI settings match the model you want to use!",
            buttons=interaction.MessageBoxButtonSet.OKButtonSet,
        )

        # Step 2: Ask user to select the directory containing JSON result files
        results_dir = interaction.get_directory_name_input(
            "Step 1/2: Select results directory containing JSON files to scan",
            default_name="",
        )

        if not results_dir:
            log.info("RerunMissingReports", "User cancelled directory selection")
            return

        # Step 3: Ask user to select the binaries directory
        binaries_dir = interaction.get_directory_name_input(
            "Step 2/2: Select Binaries Directory (where compiled binaries are stored)",
            default_name="",
        )

        if not binaries_dir:
            log.info(
                "RerunMissingReports", "User cancelled binaries directory selection"
            )
            return

        # Load source/sink mapping based on dataset
        # For Juliet, we'll load per-binary (CWE-specific) so pass None here
        # and load dynamically in the task
        source_sink_mapping = None
        lookup_by = "filename_without_ext"

        if dataset_name == "CASTLE":
            config = DATASET_CONFIGS["CASTLE"]
            if os.path.exists(config["mapping_path"]):
                source_sink_mapping = load_source_sink_mapping(config["mapping_path"])
                lookup_by = config["lookup_by"]
                if source_sink_mapping:
                    log.info(
                        "RerunMissingReports",
                        f"Loaded CASTLE mapping with {len(source_sink_mapping)} entries",
                    )
        elif dataset_name == "PrimeVul":
            config = DATASET_CONFIGS["PrimeVul"]
            if os.path.exists(config["mapping_path"]):
                source_sink_mapping = load_source_sink_mapping(config["mapping_path"])
                lookup_by = config["lookup_by"]
                if source_sink_mapping:
                    log.info(
                        "RerunMissingReports",
                        f"Loaded PrimeVul mapping with {len(source_sink_mapping)} entries",
                    )
        elif dataset_name == "Juliet":
            # Juliet loads mapping per-binary based on CWE in path
            lookup_by = DATASET_CONFIGS["Juliet"]["lookup_by"]
            log.info(
                "RerunMissingReports",
                "Juliet: will load CWE-specific mappings per binary",
            )

        # Scan results directory for all JSON files
        log.info("RerunMissingReports", f"Scanning {results_dir} for JSON files...")
        json_files = []
        for root, dirs, files in os.walk(results_dir):
            for f in files:
                if f.endswith(".json") and not f.startswith("summary"):
                    json_files.append(os.path.join(root, f))

        if not json_files:
            interaction.show_message_box(
                "No JSON Files Found",
                f"No JSON result files found in:\n{results_dir}",
                buttons=interaction.MessageBoxButtonSet.OKButtonSet,
            )
            return

        log.info("RerunMissingReports", f"Found {len(json_files)} JSON files to scan")

        # Scan JSON files for missing reports
        log.info("RerunMissingReports", "Scanning JSON files for missing AI reports...")
        missing_reports = scan_json_files_for_missing_reports(json_files)

        if not missing_reports:
            interaction.show_message_box(
                "No Missing Reports",
                f"All paths in {len(json_files)} JSON files have AI reports!",
                buttons=interaction.MessageBoxButtonSet.OKButtonSet,
            )
            return

        # Extract model info from the results directory name
        dir_name = os.path.basename(results_dir.rstrip("/"))
        # Try to make it more readable
        if "claude_sonnet" in dir_name.lower():
            pass  # Claude Sonnet detected
        elif "gemini" in dir_name.lower():
            pass  # Gemini detected
        elif "llama" in dir_name.lower():
            pass  # Llama detected
        elif "mixtral" in dir_name.lower():
            pass  # Mixtral detected
        elif "deepseek" in dir_name.lower():
            pass  # DeepSeek detected

        # Show summary and confirm
        total_missing_paths = sum(
            len(info["missing_path_ids"]) if info["missing_path_ids"] != "ALL" else 1
            for info in missing_reports.values()
        )
        total_binaries = len(missing_reports)

        # Get current Mole AI settings
        current_model = "Not configured"
        model_setting = path_ctr.config_ctr.get_setting("openai_model")
        if model_setting:
            current_model = str(model_setting.value)

        confirm = interaction.show_message_box(
            "Confirm Rerun",
            f"Scanned {len(json_files)} JSON files.\n"
            f"Found {total_missing_paths} missing path report(s) across {total_binaries} binary/binaries.\n\n"
            f"Results directory: {dir_name}\n"
            f"Current Mole model: {current_model}\n\n"
            f"⚠️  Make sure your Mole AI settings match the model you want to use!\n\n"
            f"Proceed with rerunning AI analysis?",
            buttons=interaction.MessageBoxButtonSet.YesNoButtonSet,
        )

        if confirm != interaction.MessageBoxButtonResult.YesButton:
            log.info("RerunMissingReports", "User cancelled rerun operation")
            return

        # Create and start background task
        class RerunTask(BackgroundTask):
            def __init__(
                self,
                missing_reports,
                binaries_dir,
                results_dir,
                path_ctr,
                source_sink_mapping,
                dataset_name,
                lookup_by,
            ):
                super(RerunTask, self).__init__(
                    "Rerunning Missing AI Reports", can_cancel=False
                )
                self.missing_reports = missing_reports
                self.binaries_dir = binaries_dir
                self.results_dir = results_dir
                self.path_ctr = path_ctr
                self.source_sink_mapping = source_sink_mapping
                self.dataset_name = dataset_name
                self.lookup_by = lookup_by
                self.success_count = 0
                self.failure_count = 0

            def run(self):
                try:
                    for json_file, info in self.missing_reports.items():
                        binary_name = info["binary_file"]
                        missing_path_ids = info["missing_path_ids"]

                        log.info(
                            "RerunMissingReports",
                            f"Processing {binary_name} ({len(missing_path_ids)} missing path(s))",
                        )

                        # For Juliet, preserve the subdirectory structure (CWE*/good_versions/, CWE*/bad_versions/)
                        # by using the relative path from results_dir
                        if self.dataset_name == "Juliet":
                            # Get relative path from results dir to JSON file's directory
                            json_dir = os.path.dirname(json_file)
                            rel_path = os.path.relpath(json_dir, self.results_dir)
                            binary_path = os.path.join(
                                self.binaries_dir, rel_path, binary_name
                            )
                        else:
                            # CASTLE and PrimeVul: binaries are flat in the binaries directory
                            binary_path = os.path.join(self.binaries_dir, binary_name)

                        if not os.path.exists(binary_path):
                            log.error(
                                "RerunMissingReports",
                                f"Binary not found: {binary_path}",
                            )
                            self.failure_count += 1
                            continue

                        # For Juliet, load CWE-specific mapping for each binary
                        current_mapping = self.source_sink_mapping
                        current_lookup = self.lookup_by
                        if self.dataset_name == "Juliet":
                            current_mapping, current_lookup = load_mapping_for_dataset(
                                "Juliet", binary_path
                            )
                            if current_mapping:
                                log.info(
                                    "RerunMissingReports",
                                    f"Loaded Juliet CWE mapping for {binary_name}",
                                )

                        # Rerun AI analysis for missing paths
                        success = rerun_missing_paths(
                            binary_path,
                            missing_path_ids,
                            json_file,
                            self.path_ctr,
                            current_mapping,
                            current_lookup,
                        )

                        if success:
                            self.success_count += 1
                        else:
                            self.failure_count += 1

                    # Log completion
                    log.info(
                        "RerunMissingReports",
                        f"Rerun complete! Success: {self.success_count}, Failed: {self.failure_count}",
                    )

                    # Show completion message (scheduled on UI thread)
                    interaction.show_message_box(
                        "Rerun Complete",
                        f"Rerun operation completed!\n\nSuccess: {self.success_count} binaries\nFailed: {self.failure_count} binaries\n\nResults updated in place.",
                        buttons=interaction.MessageBoxButtonSet.OKButtonSet,
                    )
                finally:
                    self.finish()

        # Start the background task
        task = RerunTask(
            missing_reports,
            binaries_dir,
            results_dir,
            path_ctr,
            source_sink_mapping,
            dataset_name,
            lookup_by,
        )
        task.start()

    # Register command in BN
    PluginCommand.register(
        "Mole\\Rerun Missing AI Reports",
        "Rerun AI analysis for paths with missing vulnerability reports",
        run_rerun_missing_reports,
    )
