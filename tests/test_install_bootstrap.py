"""The bootstraps and the installer they fetch: Python 3.8 and the stdlib, HTTPS, pins and the one-liners."""
from __future__ import annotations

import tests
from tests import loopback
from tests import scratch_dir

import contextlib
import io
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

from tests.netguard import module_guard
from tests.installsupport import REPO_ROOT, install, reported


# No connection off the loopback and no card of the host reaches a test:
# the module fails at its end otherwise.
setUpModule, tearDownModule = module_guard("test_install_bootstrap")


def _parenthesized_withs(tokens: list) -> list[str]:
    import tokenize

    found = []
    for i, tok in enumerate(tokens):
        if tok.type == tokenize.NAME and tok.string == "with" and i + 1 < len(tokens):
            if tokens[i + 1].string != "(":
                continue
            depth = 0
            for inner in tokens[i + 1:]:
                if inner.string in "([{" and inner.type == tokenize.OP:
                    depth += 1
                elif inner.string in ")]}" and inner.type == tokenize.OP:
                    depth -= 1
                    if depth == 0:
                        break
                elif depth == 1 and inner.type == tokenize.NAME and inner.string == "as":
                    found.append(f"line {tok.start[0]}: parenthesized with")
                    break
    return found


def _nested_fstrings(tokens: list) -> list[str]:
    import tokenize

    found: list[str] = []
    fstring_start = getattr(tokenize, "FSTRING_START", None)
    if fstring_start is None:
        return found
    stack = []
    for tok in tokens:
        if tok.type == fstring_start:
            if stack:
                found.append(f"line {tok.start[0]}: f-string inside an f-string")
            stack.append(tok.string[-1])
        elif tok.type == tokenize.FSTRING_END:
            stack.pop()
        elif stack and tok.type == tokenize.STRING and stack[-1] in tok.string:
            found.append(f"line {tok.start[0]}: f-string reuses its quote")
        elif stack and tok.type == tokenize.FSTRING_MIDDLE:
            continue
        elif stack and tok.type == tokenize.ERRORTOKEN and tok.string == "\\":
            found.append(f"line {tok.start[0]}: backslash in an f-string field")
    return found


class InstallerStaysOnPython38AndTheStdlib(unittest.TestCase):
    """install.py runs where the bootstraps let it run: Python 3.8, stdlib only.

    The suite runs on 3.12 with pyyaml installed, so a removeprefix() or an
    import of yaml kept every test green and died at the user's first run,
    after the bootstrap had told them 3.8 was enough.
    """

    SOURCE = (REPO_ROOT / "install.py").read_text(encoding="utf-8")

    def test_the_grammar_is_python_38(self):
        import ast

        ast.parse(self.SOURCE, filename="install.py", feature_version=(3, 8))

    def test_every_import_is_standard_library(self):
        import ast
        import sys

        tree = ast.parse(self.SOURCE)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(sorted(imported - set(sys.stdlib_module_names)), [])

    def test_no_api_newer_than_38(self):
        newer = (".removeprefix(", ".removesuffix(", "zoneinfo", "graphlib",
                 "functools.cache(", ".bit_count(", "math.lcm(", "math.nextafter(",
                 "tomllib", ".is_relative_to(", ".with_stem(", ".hardlink_to(",
                 "itertools.pairwise(", "str.removeprefix", "types.NoneType")
        used = [api for api in newer if api in self.SOURCE]
        self.assertEqual(used, [])

    def test_a_python_38_interpreter_compiles_and_imports_it(self):
        """ast.parse(feature_version=(3, 8)) on 3.12 accepts parenthesized
        context managers and PEP 701 f-strings: only a 3.8 interpreter says."""
        import shutil
        import subprocess

        python38 = shutil.which("python3.8")
        if python38 is None:
            self.skipTest("no python3.8 on PATH, the static checks below still run")
        code = (
            "import importlib.util; "
            "spec = importlib.util.spec_from_file_location('install', 'install.py'); "
            "spec.loader.exec_module(importlib.util.module_from_spec(spec))"
        )
        proc = subprocess.run(
            [python38, "-I", "-c", code], cwd=REPO_ROOT,
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_a_python_38_interpreter_runs_it_end_to_end(self):
        """An import proves the grammar, not the calls a function makes.

        dict | dict, zip(strict=True) or functools.cache import cleanly on
        3.8 and raise the first time their path runs: listing, narrowing by
        system, region and target, installing and checking all run here, on
        the repository's own manifests served over loopback. CI installs the
        interpreter, so there it may not skip.
        """
        import shutil
        import subprocess

        python38 = shutil.which("python3.8")
        if python38 is None:
            if os.environ.get("CI"):
                self.fail("CI must provide python3.8 for the installer's floor")
            self.skipTest("no python3.8 on PATH, the static checks below still run")
        base = loopback.serve(self, REPO_ROOT)
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, True)
        env = {
            **os.environ,
            "HOME": str(home),
            "RETROBIOS_OS": "linux",
            "RETROBIOS_BASE_URL": base,
        }
        dest = home / "system"
        base = [python38, "-I", "install.py", "--platform", "retroarch", "--no-input"]
        for extra in (
            ["--list-systems"],
            ["--list-cores"],
            ["--list-targets"],
            ["--dest", str(dest), "--system", "atari-lynx", "--region", "us",
             "--target", "switch", "--yes"],
            ["--dest", str(dest), "--system", "atari-lynx", "--check"],
        ):
            with self.subTest(args=extra):
                proc = subprocess.run(
                    base + extra, cwd=REPO_ROOT, env=env,
                    capture_output=True, text=True, timeout=300, check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertNotIn("Traceback", proc.stderr)
        self.assertTrue((dest / "lynxboot.img").is_file())
        # A check is scripted as `--check && launch`: missing files fail it.
        proc = subprocess.run(
            base + ["--dest", str(home / "empty"), "--system", "atari-lynx", "--check"],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=300,
            check=False,
        )
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertIn("to download.", proc.stdout)

    def test_no_syntax_a_312_parser_lets_through(self):
        """Parenthesized context managers (3.9) and f-strings reusing their
        own quote or a backslash inside a replacement field (3.12)."""
        import io
        import tokenize

        tokens = list(tokenize.generate_tokens(io.StringIO(self.SOURCE).readline))
        found = _parenthesized_withs(tokens) + _nested_fstrings(tokens)
        self.assertEqual(found, [])

    def test_no_runtime_generic_builtin(self):
        """dict[str, Path] outside an annotation runs on 3.9 and later only."""
        import ast

        tree = ast.parse(self.SOURCE)
        annotations = set()
        for node in ast.walk(tree):
            for field in ("annotation", "returns"):
                sub = getattr(node, field, None)
                if sub is not None:
                    annotations.update(id(n) for n in ast.walk(sub))
        generic = {"dict", "list", "tuple", "set", "frozenset", "type"}
        used = sorted(
            f"line {node.lineno}: {node.value.id}[...]"
            for node in ast.walk(tree)
            if isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id in generic
            and id(node) not in annotations
        )
        self.assertEqual(used, [])


    def test_no_local_is_assigned_and_never_read(self):
        """ruff --select F in py38 mode is the installer's lint gate, and an
        unread `appdata` in _os_default_dests made it exit 1. The suite has
        no ruff, so the rule is read from the syntax tree."""
        import ast

        tree = ast.parse((Path(__file__).resolve().parents[1] / "install.py").read_text())
        unread = []
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            stored, loaded = {}, set()
            for node in ast.walk(func):
                if isinstance(node, ast.Name):
                    if isinstance(node.ctx, ast.Store):
                        stored.setdefault(node.id, node.lineno)
                    else:
                        loaded.add(node.id)
            nested = {
                n.id for inner in ast.walk(func) if inner is not func
                and isinstance(inner, (ast.FunctionDef, ast.Lambda))
                for n in ast.walk(inner) if isinstance(n, ast.Name)
            }
            unread += [
                f"{func.name}:{line} {name}" for name, line in stored.items()
                if name not in loaded | nested and not name.startswith("_")
                and not any(
                    isinstance(g, (ast.Global, ast.Nonlocal)) and name in g.names
                    for g in ast.walk(func)
                )
            ]
        self.assertEqual(unread, [])
        # Nor a module rebound: a loop variable named `platform` shadowed the
        # platform module in _detect_by_path (F402).
        modules = {
            alias.asname or alias.name.split(".")[0]
            for node in tree.body if isinstance(node, ast.Import)
            for alias in node.names
        }
        rebound = sorted(
            f"{node.id}:{node.lineno}" for node in ast.walk(tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
            and node.id in modules
        )
        self.assertEqual(rebound, [])


class TestBaseUrlScheme(unittest.TestCase):
    """The bootstraps insist on HTTPS, so the installer must not be laxer."""

    def test_https_is_accepted(self):
        self.assertEqual(
            install._checked_base_url("https://example.test/repo"),
            "https://example.test/repo",
        )

    def test_plain_http_is_refused(self):
        with self.assertRaises(ValueError):
            install._checked_base_url("http://example.test/repo")

    def test_local_file_scheme_is_refused(self):
        with self.assertRaises(ValueError):
            install._checked_base_url("file:///etc")

    def test_a_refused_base_is_said_by_main_and_ends_on_code_1(self):
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_BASE_URL": "http://example.test"}), \
                unittest.mock.patch.object(sys, "argv", ["install.py", "--help"]), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit) as stopped:
            install.main()
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(err.getvalue(),
                         "Error: RETROBIOS_BASE_URL must use HTTPS, got 'http://example.test'\n")

    def test_an_empty_variable_is_unset(self):
        # Set but empty, the base killed even an import of install.py, where
        # every other reading of it takes it as unset.
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_BASE_URL": "",
                                                   "RETROBIOS_REF": ""}):
            remote = install.remote_from_env()
        self.assertEqual(remote, install.Remote(
            install.DEFAULT_RELEASE_REF, install.default_base_url(install.DEFAULT_RELEASE_REF),
            False))

    def test_loopback_http_is_allowed_for_end_to_end_runs(self):
        for url in (
            "http://127.0.0.1:8080/repo",
            "http://localhost:8080/repo",
            "http://[::1]:8080/repo",
        ):
            self.assertEqual(install._checked_base_url(url), url)


class NoPythonNamesThisSystemsCommand(unittest.TestCase):
    """Without Python the bootstrap said `sudo apt install python3` on every
    system: Termux has no sudo and installs with `pkg install python`, and
    macOS has no apt."""

    def _run(self, extra_env: dict, uname: str = "Linux") -> subprocess.CompletedProcess:
        root = scratch_dir(self)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        for tool in ("sed", "tr", "dirname", "cat"):
            found = shutil.which(tool)
            if found:
                (fake_bin / tool).symlink_to(found)
        (fake_bin / "uname").write_text(f"#!/bin/sh\necho {uname}\n", encoding="utf-8")
        (fake_bin / "uname").chmod(0o755)
        # No terminal: the Termux offer is a question asked on /dev/tty.
        return subprocess.run(
            ["/bin/sh", str(REPO_ROOT / "install.sh")], cwd=root,
            env={"PATH": str(fake_bin), "HOME": str(root), **extra_env},
            capture_output=True, text=True, timeout=30, check=False,
            start_new_session=True,
        )

    def test_termux_is_told_pkg(self):
        proc = self._run({"TERMUX_VERSION": "0.118",
                          "PREFIX": "/data/data/com.termux/files/usr"})
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Install it with: pkg install python", proc.stderr)
        self.assertNotIn("sudo", proc.stderr)

    def test_macos_is_told_xcode_select(self):
        proc = self._run({}, uname="Darwin")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Install it with: xcode-select --install", proc.stderr)
        self.assertNotIn("apt", proc.stderr)


class ABootstrapPythonCanDoHttps(unittest.TestCase):
    """find_python checked the version only: a python3 built without ssl
    was chosen over a full python, and every download then failed."""

    def _bin(self) -> tuple[Path, Path]:
        root = scratch_dir(self)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        for tool in ("sed", "tr", "dirname", "cat", "awk", "uname"):
            found = shutil.which(tool)
            if found:
                (fake_bin / tool).symlink_to(found)
        shadow = root / "no-ssl"
        shadow.mkdir()
        (shadow / "ssl.py").write_text('raise ImportError("built without ssl")\n')
        (fake_bin / "python3").write_text(
            f'#!/bin/sh\nPYTHONPATH="{shadow}" exec {shlex.quote(sys.executable)} "$@"\n')
        (fake_bin / "python3").chmod(0o755)
        (root / "install.py").write_text("import ssl; print('installer ran')\n")
        shutil.copy(REPO_ROOT / "install.sh", root / "install.sh")
        return root, fake_bin

    def _run(self, root: Path, fake_bin: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["/bin/sh", str(root / "install.sh")], cwd=root,
            env={"PATH": str(fake_bin), "HOME": str(root)},
            capture_output=True, text=True, timeout=30, check=False,
            stdin=subprocess.DEVNULL, start_new_session=True,
        )

    def test_a_full_python_is_preferred(self):
        root, fake_bin = self._bin()
        (fake_bin / "python").symlink_to(sys.executable)
        proc = self._run(root, fake_bin)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("installer ran", proc.stdout)

    def test_an_old_python_is_named_with_its_version(self):
        """Debian Buster's python3 3.7 got "Install it with: sudo apt install
        python3", which apt answers with "already the newest version"."""
        root, fake_bin = self._bin()
        (fake_bin / "python3").write_text(
            '#!/bin/sh\ncase "$2" in *print*) echo 3.7.3 ;; esac\nexit 1\n')
        proc = self._run(root, fake_bin)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Python 3.8 or newer is required, and python3 here is 3.7.3.",
                      proc.stderr)
        self.assertNotIn("Install it with: sudo apt", proc.stderr)

    def test_the_missing_module_is_named(self):
        root, fake_bin = self._bin()
        proc = self._run(root, fake_bin)
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn("installer ran", proc.stdout)
        self.assertIn("python3 is built without a module the installer needs", proc.stderr)


@unittest.skipUnless(shutil.which("pwsh") and shutil.which("script"), "needs PowerShell and a terminal")
class WindowsWithoutPythonIsOfferedWinget(unittest.TestCase):
    """A Windows machine without Python was told to install it, open a new
    window and run the command again, while winget, present on Windows 10
    and 11, could do it from the bootstrap."""

    def _folder(self) -> tuple[Path, Path]:
        folder = scratch_dir(self)
        shutil.copy(REPO_ROOT / "install.ps1", folder / "install.ps1")
        (folder / "install.py").write_text("print('installer ran')\n")
        fake_bin = folder / "bin"
        fake_bin.mkdir()
        python = shutil.which("python3") or sys.executable
        (fake_bin / "winget").write_text(
            f"#!/bin/sh\necho \"winget $*\"\n{shutil.which('ln')} -s {shlex.quote(python)} "
            f"{shlex.quote(str(fake_bin / 'python3'))}\n"
        )
        (fake_bin / "winget").chmod(0o755)
        return folder, fake_bin

    def _run(self, folder: Path, fake_bin: Path, answer: str) -> subprocess.CompletedProcess:
        pwsh = shutil.which("pwsh")
        command = (f"{shlex.quote(pwsh)} -NoProfile -File "
                   f"{shlex.quote(str(folder / 'install.ps1'))}")
        return subprocess.run(
            [shutil.which("script"), "-qec", command, "/dev/null"], input=answer,
            env={**os.environ, "PATH": f"{fake_bin}{os.pathsep}/usr/bin/nonexistent"},
            capture_output=True, text=True, timeout=120, check=False,
        )

    def test_yes_installs_and_carries_on(self):
        folder, fake_bin = self._folder()
        proc = self._run(folder, fake_bin, "y\n")
        self.assertIn("Install Python 3.12 now with winget?", proc.stdout)
        self.assertIn("winget install --id Python.Python.3.12", proc.stdout)
        self.assertIn("installer ran", proc.stdout)
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_no_names_the_command(self):
        folder, fake_bin = self._folder()
        proc = self._run(folder, fake_bin, "n\n")
        self.assertNotIn("installer ran", proc.stdout)
        self.assertIn("winget install Python.Python.3.12", proc.stdout)
        self.assertFalse((fake_bin / "python3").exists())


@unittest.skipUnless(shutil.which("script"), "needs a terminal")
class TermuxStorageIsSetUpByTheBootstrap(unittest.TestCase):
    """The installer told an Android user to run termux-setup-storage and
    start the whole run over: the bootstrap runs it and waits for ~/storage."""

    def _run(self, storage_exists: bool) -> tuple[subprocess.CompletedProcess, Path]:
        root = scratch_dir(self)
        shutil.copy(REPO_ROOT / "install.sh", root / "install.sh")
        (root / "install.py").write_text("print('installer ran')\n")
        home = root / "home"
        home.mkdir()
        if storage_exists:
            (home / "storage").mkdir()
        fake_bin = root / "bin"
        fake_bin.mkdir()
        for tool in ("sed", "tr", "dirname", "cat", "awk", "uname", "sleep", "mkdir"):
            found = shutil.which(tool)
            if found:
                (fake_bin / tool).symlink_to(found)
        (fake_bin / "python3").symlink_to(sys.executable)
        # The app creates ~/storage once Android's dialog is answered.
        (fake_bin / "termux-setup-storage").write_text(
            f'#!/bin/sh\necho ran >> "{root}/setup.log"\nmkdir "$HOME/storage"\n')
        (fake_bin / "termux-setup-storage").chmod(0o755)
        command = (f"PATH={shlex.quote(str(fake_bin))} HOME={shlex.quote(str(home))} "
                   f"TERMUX_VERSION=0.118 /bin/sh {shlex.quote(str(root / 'install.sh'))}")
        proc = subprocess.run(
            [shutil.which("script"), "-qec", command, "/dev/null"],
            capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL, check=False)
        return proc, root

    def test_it_runs_once_then_the_installer(self):
        proc, root = self._run(storage_exists=False)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertEqual((root / "setup.log").read_text(), "ran\n")
        self.assertIn("allow it", proc.stdout)
        self.assertIn("installer ran", proc.stdout)

    def test_a_set_up_storage_is_left_alone(self):
        proc, root = self._run(storage_exists=True)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertFalse((root / "setup.log").exists())
        self.assertIn("installer ran", proc.stdout)


@unittest.skipUnless(shutil.which("pwsh"), "needs PowerShell")
class APyLauncherWithoutARuntimeIsPassed(unittest.TestCase):
    """findPython returned the py launcher as soon as it existed: one left
    with no usable runtime hid a Python 3.12 on PATH, and the bootstrap
    offered a second install or gave up."""

    def test_python_on_path_runs_the_installer(self):
        folder = scratch_dir(self)
        shutil.copy(REPO_ROOT / "install.ps1", folder / "install.ps1")
        (folder / "install.py").write_text("print('installer ran')\n")
        fake_bin = folder / "bin"
        fake_bin.mkdir()
        (fake_bin / "py").write_text("#!/bin/sh\necho 'No installed Python found!' >&2\nexit 1\n")
        (fake_bin / "py").chmod(0o755)
        (fake_bin / "python3").symlink_to(sys.executable)
        proc = subprocess.run(
            [shutil.which("pwsh"), "-NoProfile", "-File", str(folder / "install.ps1")],
            env={**os.environ, "PATH": f"{fake_bin}{os.pathsep}/usr/bin/nonexistent"},
            capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL, check=False)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("installer ran", proc.stdout)


@unittest.skipUnless(shutil.which("pwsh"), "needs PowerShell")
class APowerShellDownloadThatNeverAnswersEnds(unittest.TestCase):
    """Invoke-WebRequest had no timeout: behind a server that takes the
    connection and never answers, the window waited forever with no line."""

    def test_a_silent_server_ends_on_the_network_advice(self):
        folder = scratch_dir(self)
        shutil.copy(REPO_ROOT / "install.ps1", folder / "install.ps1")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            port = listener.getsockname()[1]
            started = time.monotonic()
            proc = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(folder / "install.ps1"), "--check"],
                env={**os.environ,
                     "RETROBIOS_INSTALL_URL": f"https://127.0.0.1:{port}/install.py"},
                capture_output=True, text=True, timeout=150, stdin=subprocess.DEVNULL, check=False)
        self.assertLess(time.monotonic() - started, 120)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("could not be downloaded", " ".join((proc.stdout + proc.stderr).split()))


class ThePowerShellWrapperPassesTheStatusOn(unittest.TestCase):
    """Every non-zero exit became a red "installer failed" exception and
    code 1: a --check that found work read as a crash, 2 and 130 were lost."""

    @unittest.skipUnless(shutil.which("pwsh"), "needs PowerShell")
    def test_the_installer_code_comes_back_unchanged(self):
        folder = scratch_dir(self)
        shutil.copy(REPO_ROOT / "install.ps1", folder / "install.ps1")
        for code in (0, 1, 2, 130):
            with self.subTest(code=code):
                (folder / "install.py").write_text(f"import sys\nsys.exit({code})\n")
                proc = subprocess.run(
                    ["pwsh", "-NoProfile", "-File", str(folder / "install.ps1")],
                    capture_output=True, text=True, timeout=120,
                    check=False,
                )
                self.assertEqual(proc.returncode, code, proc.stderr)
                self.assertNotIn("installer failed", proc.stdout + proc.stderr)


class ThePowerShellWrapperPassesEveryArgument(unittest.TestCase):
    """A [Parameter()] attribute made install.ps1 an advanced script, whose
    common parameters took `-v` (read as `-Verbose`), `-vb`, `-d` and `-ea`:
    the documented `-v` never reached install.py."""

    @unittest.skipUnless(shutil.which("pwsh"), "needs PowerShell")
    def test_short_flags_reach_the_installer(self):
        folder = scratch_dir(self)
        shutil.copy(REPO_ROOT / "install.ps1", folder / "install.ps1")
        (folder / "install.py").write_text(
            "import json, sys\nprint(json.dumps(sys.argv[1:]))\n"
        )
        for args in (["-v", "--check"], ["-vb"], ["-Verbose"], ["-d", "-ea", "x"],
                     ["--platform", "a b"], []):
            with self.subTest(args=args):
                proc = subprocess.run(
                    ["pwsh", "-NoProfile", "-File", str(folder / "install.ps1"), *args],
                    capture_output=True, text=True, timeout=120,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(json.loads(proc.stdout), args)


class ThePagesQuoteTheBootstrapsOwnWords(unittest.TestCase):
    """The installer page and the FAQ quoted "install.py SHA-256 mismatch",
    a message the bootstraps no longer print."""

    def test_the_quoted_message_is_printed(self):
        quoted = "does not match its expected"
        for wrapper in ("install.sh", "install.ps1"):
            self.assertIn(quoted, (REPO_ROOT / wrapper).read_text(encoding="utf-8"))
        for page in ("wiki/installer.md", "wiki/faq.md"):
            text = (REPO_ROOT / page).read_text(encoding="utf-8")
            self.assertNotIn("SHA-256 mismatch`", text)
            self.assertIn(quoted, " ".join(text.split()))


class TheInstallerFitsTheOneLiners(unittest.TestCase):
    """install.sh and install.ps1 refuse an installer over their cap, 8 MiB:
    the SHA-256 pin refuses any changed byte, and the cap only stops a page
    served in its place. install.py grew from 596 KB to 1.1 MB in twelve
    days: past REVIEW_BYTES its growth is looked at before it goes on."""

    # The size past which install.py's growth is reviewed, well below the cap.
    REVIEW_BYTES = 3 * 1024 ** 2

    def _caps(self) -> dict[str, int]:
        import re

        shell = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
        ps1 = (REPO_ROOT / "install.ps1").read_text(encoding="utf-8")
        units = {"": 1, "KB": 1024, "MB": 1024 ** 2}
        number, unit = re.search(r"\$maximumInstallerBytes = (\d+)(KB|MB)?", ps1).groups()
        return {"install.sh": int(re.search(r"^MAX_INSTALLER_BYTES=(\d+)$", shell, re.M)[1]),
                "install.ps1": int(number) * units[unit or ""]}

    def test_both_one_liners_accept_the_same_size(self):
        self.assertEqual(set(self._caps().values()), {8 * 1024 ** 2})

    def test_install_py_stays_below_the_review_size(self):
        size = (REPO_ROOT / "install.py").stat().st_size
        self.assertLess(self.REVIEW_BYTES, min(self._caps().values()))
        self.assertLess(
            size, self.REVIEW_BYTES,
            f"install.py is {size} bytes, past the {self.REVIEW_BYTES} that call for a "
            "look at its growth: shrink it, or raise REVIEW_BYTES once reviewed")

    def test_the_refusal_names_a_cause_and_a_way_out(self):
        for script in ("install.sh", "install.ps1"):
            text = " ".join((REPO_ROOT / script).read_text(encoding="utf-8").split())
            with self.subTest(script=script):
                self.assertIn("this script accepts", text)
                self.assertIn("open any web page to sign in", text)


class AnOverrideIsNamedWhenItIsTheCause(unittest.TestCase):
    """A RETROBIOS_INSTALL_SHA256 of the user's own read as a cut download,
    and a dead RETROBIOS_BASE_URL as a network fault naming no host."""

    def test_an_unreachable_base_url_is_named(self):
        error = install.urllib.error.URLError("timed out")
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_BASE_URL": "https://mirror.invalid"}), \
                unittest.mock.patch.object(install, "_fetch_json", side_effect=error), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            reported(install.fetch_manifest, "retroarch")
        text = err.getvalue()
        self.assertIn("Address: https://mirror.invalid/install/retroarch.json", text)
        self.assertIn("RETROBIOS_BASE_URL is set", text)

    def test_a_pinned_fingerprint_is_named(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            (fake_bin / "curl").write_text(
                "#!/bin/sh\noutput=\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = --output ]; then output=$2; shift 2; else shift; fi\n"
                "done\n"
                "echo 'print(1)' > \"$output\"\n")
            (fake_bin / "curl").chmod(0o755)
            env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                   "TMPDIR": str(root), "RETROBIOS_INSTALL_SHA256": "0" * 64}
            proc = subprocess.run(["sh", "-s"], cwd=root, env=env, capture_output=True,
                                  input=(REPO_ROOT / "install.sh").read_text(),
                                  text=True, timeout=30, check=False)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("RETROBIOS_INSTALL_SHA256 is set", proc.stderr)
        self.assertNotIn("cut short", proc.stderr)
        ps1 = (REPO_ROOT / "install.ps1").read_text()
        self.assertIn('"RETROBIOS_INSTALL_URL", "RETROBIOS_INSTALL_SHA256"', ps1)


@unittest.skipUnless(shutil.which("pwsh"), "needs PowerShell")
class ThePowerShellOneLinerLeavesTheSessionAlone(unittest.TestCase):
    """irm | iex left $ErrorActionPreference = Stop and the script's
    variables in the user's session: their next error stopped everything."""

    def test_nothing_is_left_behind(self):
        script = (
            "Get-Content install.ps1 -Raw | Invoke-Expression; "
            "\"EAP=$ErrorActionPreference temporary=[$temporary] installer=[$installer] "
            "bootstrap=[$env:RETROBIOS_BOOTSTRAP]\""
        )
        # Refused before any request, so the run needs no network.
        env = {**os.environ, "RETROBIOS_INSTALL_URL": "http://127.0.0.1/install.py"}
        env.pop("RETROBIOS_BOOTSTRAP", None)
        proc = subprocess.run(["pwsh", "-NoProfile", "-Command", script], cwd=REPO_ROOT,
                              env=env, capture_output=True, text=True, timeout=120, check=False)
        self.assertIn("must use HTTPS", proc.stderr)
        self.assertIn("EAP=Continue temporary=[] installer=[] bootstrap=[]", proc.stdout)


class AStrippedPythonIsNamed(unittest.TestCase):
    """A Python built without ssl blamed the network three times, and one
    without zlib or unicodedata stopped on a ModuleNotFoundError traceback."""

    def _run(self, hidden: str, *argv: str) -> subprocess.CompletedProcess:
        code = (f"import runpy, sys; sys.modules[{hidden!r}] = None; "
                "sys.argv = sys.argv[1:]; "
                "runpy.run_path(sys.argv[0], run_name='__main__')")
        env = {key: value for key, value in os.environ.items()
               if key not in ("RETROBIOS_BASE_URL", install.OFFLINE_VARIABLE)}
        return subprocess.run(
            [sys.executable, "-c", code, str(REPO_ROOT / "install.py"), *argv],
            env=env, capture_output=True, text=True, timeout=60,
            stdin=subprocess.DEVNULL, check=False)

    def test_a_missing_c_module_is_named(self):
        for hidden in ("zlib", "unicodedata"):
            with self.subTest(module=hidden):
                proc = self._run(hidden, "--help")
                self.assertEqual(proc.returncode, 1)
                self.assertNotIn("Traceback", proc.stderr)
                self.assertIn(f"built without its {hidden} module", proc.stderr)

    def test_no_ssl_is_said_once_not_retried(self):
        with tempfile.TemporaryDirectory() as dest:
            proc = self._run("ssl", "--platform", "retroarch", "--dest", dest,
                             "--check", "--no-input")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("built without its ssl module and cannot use HTTPS", proc.stderr)
        self.assertNotIn("trying again", proc.stderr)
        self.assertNotIn("HTTPS_PROXY", proc.stderr)


class APackageHintNamesThePackageCommand(unittest.TestCase):
    """Run from the retrobios package, a hint said `python3 install.py`,
    a file the user does not have."""

    def test_the_environment_names_the_command(self):
        for prefix, command in (
            ("/home/me/.cache/uv/archive-v0/UwL4i3xOlCEYSTnw", "uvx retrobios"),
            ("C:\\Users\\me\\AppData\\Local\\uv\\cache\\archive-v0\\x1", "uvx retrobios"),
            ("/home/me/.cache/pipx/539b8243c11ee7c", "pipx run retrobios"),
            ("/home/me/.local/pipx/.cache/539b8243c11ee7c", "pipx run retrobios"),
            ("/home/me/.local/share/pipx/venvs/retrobios", "retrobios"),
            ("/home/me/.local/share/uv/tools/retrobios", "retrobios"),
            ("/home/me/venv", "retrobios"),
        ):
            with self.subTest(prefix=prefix):
                self.assertEqual(install.package_command(prefix), command)

    def test_the_launcher_is_the_package_command(self):
        hint = install.Invocation()
        with unittest.mock.patch.dict(os.environ, {"RETROBIOS_BOOTSTRAP": "pypi"}), \
                unittest.mock.patch.object(install.sys, "prefix", "/home/me/.cache/uv/archive-v0/a"):
            self.assertEqual(hint.launcher(), "uvx retrobios")
            self.assertEqual(hint.launcher(elevated=True), "sudo uvx retrobios")
            self.assertTrue(hint.command("retroarch", "DIR").startswith(
                "uvx retrobios --platform retroarch --dest DIR"))


if __name__ == "__main__":
    unittest.main()
