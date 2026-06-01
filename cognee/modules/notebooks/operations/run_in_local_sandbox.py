import ast
import io
import sys
import traceback
from typing import List, Optional, Dict, Any

import cognee


# ── Security: List of forbidden import/module patterns ──────────────────────
FORBIDDEN_MODULES = {
    "os", "subprocess", "shutil", "signal", "ctypes", "socket",
    "multiprocessing", "threading", "webbrowser", "telnetlib",
    "ftplib", "smtplib", "http", "socketserver",
    "crypt", "fcntl", "termios", "tty", "pty", "grp", "pwd",
    "resource", "syslog", "dbm", "posix", "_posixsubprocess",
    "code", "codeop", "codecs",
}

# Modules that are dangerous when specific sub-imports happen
FORBIDDEN_MODULE_PREFIXES = {
    "os.", "subprocess.", "ctypes.", "multiprocessing.", "posix.",
}

# Built-in functions that are dangerous in user code
FORBIDDEN_BUILTINS = {
    "exec", "eval", "compile", "__import__", "open",
    "breakpoint", "input",
}

# AST node types that represent direct dangerous calls
FORBIDDEN_CALL_NAMES = {
    "exec", "eval", "compile", "__import__",
    "open",
}

# Attributes that allow sandbox escape via class introspection
FORBIDDEN_ATTR_NAMES = {
    "__subclasses__", "__bases__", "__mro__", "__globals__",
    "__code__", "__closure__", "__func__", "__self__",
}


def _check_code_safety(code: str) -> Optional[str]:
    """Analyse the code AST for dangerous patterns.
    Returns an error string if the code is unsafe, or None if OK."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return f"Syntax error in notebook code: {e}"

    for node in ast.walk(tree):
        # Block dangerous imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in FORBIDDEN_MODULES or alias.name.split(".")[0] in FORBIDDEN_MODULES:
                    return (
                        f"Security: importing '{alias.name}' is not allowed "
                        "in notebook sandbox."
                    )

        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module in FORBIDDEN_MODULES:
                return (
                    f"Security: importing from '{module}' is not allowed "
                    "in notebook sandbox."
                )

        # Block calls to dangerous functions (direct names)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in FORBIDDEN_CALL_NAMES:
                return (
                    f"Security: calling '{node.func.id}()' is not allowed "
                    "in notebook sandbox."
                )

        # Block attribute access to dangerous dunder attributes
        if isinstance(node, ast.Attribute):
            if node.attr in FORBIDDEN_ATTR_NAMES:
                return (
                    f"Security: access to '.{node.attr}' is not allowed "
                    "in notebook sandbox."
                )

    return None


def _make_restricted_builtins() -> Dict[str, Any]:
    """Return a dict of safe builtins, excluding dangerous functions."""
    safe = {}
    for name, value in __builtins__.items() if isinstance(__builtins__, dict) else vars(__builtins__).items():
        if name not in FORBIDDEN_BUILTINS:
            safe[name] = value
    return safe


def wrap_in_async_handler(user_code: str) -> str:
    return (
        "import asyncio\n"
        + "asyncio.set_event_loop(running_loop)\n\n"
        + "from cognee.infrastructure.utils.run_sync import run_sync\n\n"
        + "async def __user_main__():\n"
        + "\n".join("    " + line for line in user_code.strip().split("\n"))
        + "\n"
        + "    globals().update(locals())\n\n"
        + "run_sync(__user_main__(), running_loop)\n"
    )


def run_in_local_sandbox(
    code: str,
    environment: Optional[Dict[str, Any]] = None,
    loop=None,
) -> tuple[List[Any], Optional[str]]:
    """Execute user-provided notebook code in a sandboxed environment.

    Security measures:
    - AST-level scan blocks dangerous imports, calls, and attribute access
      before the code is ever executed.
    - The exec() environment uses a restricted set of builtins that
      excludes eval, exec, compile, __import__, open, etc.
    - Dangerous modules (os, subprocess, ctypes, etc.) are blocked at
      the AST level.
    - Sandbox-escape attribute patterns (__subclasses__, __bases__,
      __globals__, etc.) are blocked at the AST level.
    - The supplied ``cognee`` reference is the only non-builtin module
      made available.
    """
    error = _check_code_safety(code)
    if error is not None:
        return [], error

    environment = environment or {}
    code = wrap_in_async_handler(code.replace("\xa0", "\n"))

    # Use restricted builtins
    environment.setdefault("__builtins__", _make_restricted_builtins())

    buffer = io.StringIO()
    sys_stdout = sys.stdout
    sys.stdout = buffer
    sys.stderr = buffer

    error = None

    printOutput = []

    def customPrintFunction(output):
        printOutput.append(output)

    environment["print"] = customPrintFunction
    environment["running_loop"] = loop
    environment["cognee"] = cognee

    try:
        exec(code, environment)
    except Exception:
        error = traceback.format_exc()
    finally:
        sys.stdout = sys_stdout
        sys.stderr = sys_stdout

    return printOutput, error


if __name__ == "__main__":
    run_in_local_sandbox("""
import cognee

await cognee.add("Test file with some random content 3.")

a = "asd"

b = {"c": "dfgh"}
""")
