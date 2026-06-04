"""CLI flag validation tests for cognee-research.

Tests that all enhance CLI flags parse correctly across subcommands:
- All subcommands: --quiet, --no-color
- cognify_command: --dry-run, --timeout, --no-cache
- search_command: --output-dir, --max-results, --format
- add_command: --force
- Main cli: --version
"""

import os
import sys
import subprocess
import pytest

PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..", "..")


def run_help(args=None):
    """Run cognee CLI with --help and return stdout"""
    cmd = [sys.executable, "-m", "cognee.cli.minimal_cli"]
    if args:
        cmd.extend(args)
    cmd.append("--help")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_DIR)
    return result.stdout


def run_subcommand_help(subcommand):
    """Run cognee <subcommand> --help and return stdout"""
    cmd = [sys.executable, "-m", "cognee.cli.minimal_cli", subcommand, "--help"]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_DIR)
    return result.stdout


# --- Main CLI ---

def test_version_flag():
    """Verify --version flag exists on main CLI"""
    help_out = run_help()
    assert "--version" in help_out, "--version flag should be defined on main CLI"


# --- All subcommands ---

@pytest.mark.parametrize("subcommand", ["add", "cognify", "search", "config", "delete"])
def test_quiet_flag_on_all_subcommands(subcommand):
    """Verify --quiet flag exists on all subcommands"""
    help_out = run_subcommand_help(subcommand)
    assert "--quiet" in help_out, f"--quiet flag should be defined on {subcommand} command"


@pytest.mark.parametrize("subcommand", ["add", "cognify", "search", "config", "delete"])
def test_no_color_flag_on_all_subcommands(subcommand):
    """Verify --no-color flag exists on all subcommands"""
    help_out = run_subcommand_help(subcommand)
    assert "--no-color" in help_out, f"--no-color flag should be defined on {subcommand} command"


# --- cognify_command specific ---

def test_cognify_dry_run_flag():
    """Verify --dry-run flag exists on cognify command"""
    help_out = run_subcommand_help("cognify")
    assert "--dry-run" in help_out, "--dry-run flag should be defined on cognify command"


def test_cognify_timeout_flag():
    """Verify --timeout flag exists on cognify command"""
    help_out = run_subcommand_help("cognify")
    assert "--timeout" in help_out, "--timeout flag should be defined on cognify command"


def test_cognify_no_cache_flag():
    """Verify --no-cache flag exists on cognify command"""
    help_out = run_subcommand_help("cognify")
    assert "--no-cache" in help_out, "--no-cache flag should be defined on cognify command"


# --- search_command specific ---

def test_search_output_dir_flag():
    """Verify --output-dir flag exists on search command"""
    help_out = run_subcommand_help("search")
    assert "--output-dir" in help_out, "--output-dir flag should be defined on search command"


def test_search_max_results_flag():
    """Verify --max-results flag exists on search command"""
    help_out = run_subcommand_help("search")
    assert "--max-results" in help_out, "--max-results flag should be defined on search command"


def test_search_format_flag():
    """Verify --format flag exists on search command"""
    help_out = run_subcommand_help("search")
    assert "--format" in help_out, "--format flag should be defined on search command"


# --- add_command specific ---

def test_add_force_flag():
    """Verify --force flag exists on add command"""
    help_out = run_subcommand_help("add")
    assert "--force" in help_out, "--force flag should be defined on add command"
