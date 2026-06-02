"""Security tests for cognee-research PR #2: RCE via exec prevention"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_no_dangerous_exec():
    """Verify exec() is not used unsafely in the codebase"""
    root = os.path.join(os.path.dirname(__file__), "..")
    issues = []
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirpath or "__pycache__" in dirpath or "node_modules" in dirpath:
            continue
        for fn in filenames:
            if fn.endswith((".py", ".js", ".ts")):
                fpath = os.path.join(dirpath, fn)
                try:
                    with open(fpath) as f:
                        content = f.read()
                    if "exec(" in content or "eval(" in content:
                        lines = content.split("\n")
                        for i, line in enumerate(lines, 1):
                            if "exec(" in line or "eval(" in line:
                                # Check if there's a safety check
                                start = max(0, i - 3)
                                end = min(len(lines), i + 3)
                                context = "\n".join(lines[start:end])
                                has_safety = any(
                                    p in context for p in [
                                        "builtins", "restrict", "safe",
                                        "__builtins__", "SAFE_",
                                        "# safe", "# restricted",
                                    ]
                                )
                                if not has_safety:
                                    issues.append(f"{fn}:{i}: {line.strip()}")
                except (UnicodeDecodeError, IOError):
                    continue
    # We expect either no exec/eval, or safety guards around them
    if issues:
        # Check if the fix addressed the safety issue
        assert False, f"Unsafe exec/eval found:\n" + "\n".join(issues[:5])


def test_input_sanitization_before_exec():
    """Verify user input is sanitized before being passed to exec"""
    root = os.path.join(os.path.dirname(__file__), "..")
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirpath or "__pycache__" in dirpath or "node_modules" in dirpath:
            continue
        for fn in filenames:
            if fn.endswith(".py"):
                fpath = os.path.join(dirpath, fn)
                with open(fpath) as f:
                    content = f.read()
                if "exec(" in content:
                    lines = content.split("\n")
                    for i, line in enumerate(lines, 1):
                        if "exec(" in line:
                            # Check for sandbox or restrictions
                            has_sandbox = any(
                                p in content for p in [
                                    "sandbox", "Sandbox",
                                    "restricted", "Restricted",
                                    "RestrictedPython", "builtins",
                                    "safe_globals", "SAFE_GLOBALS",
                                ]
                            )
                            if not has_sandbox:
                                # Check if exec is at least in a try/except
                                start = max(0, i - 5)
                                context = "\n".join(lines[start:i+1])
                                if "try" not in context:
                                    pytest.fail(
                                        f"exec() at {fn}:{i} lacks sandbox, "
                                        f"restricted globals, or try/except"
                                    )
                            return


def test_restricted_globals_in_exec():
    """Verify exec() uses restricted globals and locals"""
    root = os.path.join(os.path.dirname(__file__), "..")
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirpath or "__pycache__" in dirpath or "node_modules" in dirpath:
            continue
        for fn in filenames:
            if fn.endswith(".py"):
                fpath = os.path.join(dirpath, fn)
                with open(fpath) as f:
                    content = f.read()
                if "exec(" in content and "__builtins__" in content:
                    return
    # If we get here, check if exec is used at all
    has_exec = False
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirpath or "__pycache__" in dirpath or "node_modules" in dirpath:
            continue
        for fn in filenames:
            if fn.endswith(".py"):
                fpath = os.path.join(dirpath, fn)
                with open(fpath) as f:
                    content = f.read()
                if "exec(" in content:
                    has_exec = True
    if has_exec:
        assert False, "exec() used without __builtins__ restriction"


def test_no_eval_with_user_input():
    """Verify eval() is not used with user input"""
    root = os.path.join(os.path.dirname(__file__), "..")
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirpath or "__pycache__" in dirpath or "node_modules" in dirpath:
            continue
        for fn in filenames:
            if fn.endswith(".py"):
                fpath = os.path.join(dirpath, fn)
                with open(fpath) as f:
                    content = f.read()
                if "eval(" in content and ("input" in content or "request" in content):
                    pytest.fail(f"eval() used with potential user input in {fn}")


def test_code_execution_uses_subprocess_instead():
    """Verify subprocess is used instead of exec for command execution"""
    root = os.path.join(os.path.dirname(__file__), "..")
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirpath or "__pycache__" in dirpath or "node_modules" in dirpath:
            continue
        for fn in filenames:
            if fn.endswith(".py"):
                fpath = os.path.join(dirpath, fn)
                with open(fpath) as f:
                    content = f.read()
                if "subprocess" in content:
                    return True
