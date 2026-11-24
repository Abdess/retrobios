"""install.py offers the platforms the manifests describe, names them and runs against the real lists."""
from __future__ import annotations

import tests
from tests import scratch_dir

import contextlib
import hashlib
import io
import json
import os
import shlex
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

from tests.netguard import module_guard
from tests.installsupport import REPO_ROOT, install, reported, _LoopbackRun, _install_run


# No connection off the loopback and no card of the host reaches a test:
# the module fails at its end otherwise.
setUpModule, tearDownModule = module_guard("test_install_platforms")


# What a stale pin's failure says: the fix is one command.
PIN_ADVICE = "install.py changed: python scripts/pin_installer.py rewrites both pins"


class SaveFilesAListHoldsNoneOfAreNotPromised(unittest.TestCase):
    """RetroPie, ROCKNIX, AmberELEC, EmuELEC and RomM keep their save
    directory in no fixed place: their lists leave those files out with no
    hash or address. The run said "Name it with --save-dir", and said it
    again with --save-dir given, which installs none of them."""

    def test_the_reason_is_said_and_no_option_is_offered(self):
        manifest = json.loads((REPO_ROOT / "install" / "retropie.json").read_text())
        self.assertIsNone(manifest.get("save_directory"))
        root = scratch_dir(self)
        env = dict(os.environ, RETROBIOS_OS="linux")
        for extra in ([], ["--save-dir", str(root / "saves")]):
            with self.subTest(extra=extra):
                proc = _install_run(
                    env, "--platform", "retropie", "--dest", str(root / "bios"),
                    "--manifest", "install/retropie.json", "--offline", "--no-input",
                    "--yes", "--emulator", "azahar", *extra)
                out = proc.stdout + proc.stderr
                self.assertIn("read from RetroPie's save directory left out: RetroPie "
                              "keeps it in no fixed place, and its file list holds none "
                              "of them.", out)
                self.assertNotIn("Name it with --save-dir", out)


class TestNormalizePlatform(unittest.TestCase):
    """Manifest URLs are case sensitive: user input must be normalized."""

    def test_lowercases_input(self):
        self.assertEqual(install.normalize_platform("Batocera"), "batocera")

    def test_strips_whitespace(self):
        self.assertEqual(install.normalize_platform(" retroarch "), "retroarch")

    def test_unknown_platform_exits(self):
        with self.assertRaises(SystemExit):
            install.normalize_platform("launchbox")

    def test_all_available_platforms_accepted(self):
        for plat in install.AVAILABLE_PLATFORMS:
            self.assertEqual(install.normalize_platform(plat), plat)


class TestAvailablePlatforms(unittest.TestCase):
    """The platform list must match the generated manifests."""

    def test_matches_install_manifests(self):
        manifests = {p.stem for p in (REPO_ROOT / "install").glob("*.json")}
        self.assertEqual(set(install.AVAILABLE_PLATFORMS), manifests)

    def test_every_registered_platform_is_installable(self):
        """The installer serves every registered platform from its manifest."""
        from model.registry import list_registered_platforms

        registered = set(
            list_registered_platforms(
                str(REPO_ROOT / "platforms")
            )
        )
        missing = registered - set(install.AVAILABLE_PLATFORMS)
        self.assertEqual(missing, set(), f"no install manifest for {sorted(missing)}")

    def test_powershell_wrapper_pins_installer_hash(self):
        content = (REPO_ROOT / "install.ps1").read_text()
        match = re.search(r'\$defaultInstallSha256 = "([0-9a-f]{64})"', content)
        self.assertIsNotNone(match, "install.ps1 must embed the installer SHA256")
        expected = hashlib.sha256((REPO_ROOT / "install.py").read_bytes()).hexdigest()
        self.assertEqual(match.group(1), expected, PIN_ADVICE)

    def test_powershell_wrapper_rejects_non_https_bootstrap(self):
        content = (REPO_ROOT / "install.ps1").read_text()
        self.assertIn('$uri.Scheme -ne "https"', content)

    def test_shell_wrapper_pins_installer_hash(self):
        content = (REPO_ROOT / "install.sh").read_text()
        match = re.search(r'DEFAULT_INSTALL_SHA256="([0-9a-f]{64})"', content)
        self.assertIsNotNone(match, "install.sh must embed the installer SHA256")
        expected = hashlib.sha256((REPO_ROOT / "install.py").read_bytes()).hexdigest()
        self.assertEqual(match.group(1), expected, PIN_ADVICE)

    def test_pin_script_writes_both_pins(self):
        """Every edit to install.py meant a sha256sum pasted by hand into two
        files with two syntaxes, and the failing test named no command."""
        from installer_build import pins

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("install.py", "install.sh", "install.ps1"):
                shutil.copy2(REPO_ROOT / name, root / name)
            (root / "install.py").write_text("# changed\n", encoding="utf-8")
            sh_mode = (root / "install.sh").stat().st_mode
            self.assertEqual(pins.stale_pins(root), ["install.sh", "install.ps1"])
            self.assertEqual(pins.write_pins(root), ["install.sh", "install.ps1"])
            self.assertEqual(pins.stale_pins(root), [])
            digest = hashlib.sha256(b"# changed\n").hexdigest()
            for name in ("install.sh", "install.ps1"):
                before = (REPO_ROOT / name).read_text(encoding="utf-8").splitlines()
                after = (root / name).read_text(encoding="utf-8").splitlines()
                changed = [b for a, b in zip(before, after) if a != b]
                self.assertEqual(len(changed), 1, name)
                self.assertIn(digest, changed[0])
            self.assertEqual((root / "install.sh").stat().st_mode, sh_mode)

    def test_a_second_pin_line_is_refused(self):
        """sh keeps the last assignment: a second pin line after the right one
        is the value the bootstrap runs with, so the check refuses it."""
        from installer_build import pins

        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "tmp" / "tests") as directory:
            root = Path(directory)
            for name in ("install.py", "install.sh", "install.ps1"):
                shutil.copy2(REPO_ROOT / name, root / name)
            text = (root / "install.sh").read_text(encoding="utf-8")
            pin = f'DEFAULT_INSTALL_SHA256="{pins.installer_sha256(root)}"\n'
            self.assertIn(pin, text)
            doubled = text.replace(pin, f'{pin}DEFAULT_INSTALL_SHA256="{"0" * 64}"\n')
            (root / "install.sh").write_text(doubled, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "2 installer pin lines"):
                pins.stale_pins(root)
            with self.assertRaisesRegex(ValueError, "2 installer pin lines"):
                pins.pinned_sha256("install.sh", root)

    def test_shell_one_liner_downloads_verifies_and_forwards_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # A piped script must not trust a same-named file in the caller's
            # working directory. Only a real local install.sh may use its peer.
            (root / "install.py").write_text(
                "raise SystemExit('untrusted cwd installer ran')\n",
                encoding="utf-8",
            )
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "curl-called"
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                "#!/bin/sh\n"
                "output=\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = --output ]; then output=$2; shift 2; else shift; fi\n"
                "done\n"
                "cp -- \"$FAKE_INSTALLER_SOURCE\" \"$output\"\n"
                ": > \"$FAKE_CURL_MARKER\"\n",
                encoding="utf-8",
            )
            fake_curl.chmod(0o755)

            env = os.environ.copy()
            env.update(
                PATH=f"{fake_bin}{os.pathsep}{env['PATH']}",
                TMPDIR=str(root),
                RETROBIOS_INSTALL_URL="https://example.invalid/install.py",
                RETROBIOS_INSTALL_SHA256=hashlib.sha256(
                    (REPO_ROOT / "install.py").read_bytes()
                ).hexdigest(),
                FAKE_INSTALLER_SOURCE=str(REPO_ROOT / "install.py"),
                FAKE_CURL_MARKER=str(marker),
            )
            proc = subprocess.run(
                ["sh", "-s", "--", "--list-platforms"],
                cwd=root,
                env=env,
                input=(REPO_ROOT / "install.sh").read_text(encoding="utf-8"),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertTrue(marker.is_file(), "piped bootstrap did not download install.py")
            self.assertIn("retroarch", proc.stdout)

    def test_busybox_wget_downloads_the_installer(self):
        """BusyBox wget, the only one in the RomM image, refuses
        --https-only: with no curl the one-liner always failed and blamed
        the network."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            for tool in ("mktemp", "wc", "tr", "sha256sum", "awk", "rm", "rmdir",
                         "grep", "tail", "cp", "dirname", "cat", "python3"):
                found = shutil.which(tool)
                if found:
                    (fake_bin / tool).symlink_to(found)
            (fake_bin / "wget").write_text(
                "#!/bin/sh\n"
                "output=\n"
                "for arg in \"$@\"; do\n"
                "  case \"$arg\" in\n"
                "    --help) echo 'Usage: wget [-cqS] [-O FILE] [-T SEC] URL' >&2; exit 1 ;;\n"
                "    --https-only) echo \"wget: unrecognized option '$arg'\" >&2; exit 1 ;;\n"
                "    --output-document=*) output=${arg#--output-document=} ;;\n"
                "  esac\n"
                "done\n"
                "cp -- \"$FAKE_INSTALLER_SOURCE\" \"$output\"\n",
                encoding="utf-8",
            )
            (fake_bin / "wget").chmod(0o755)
            env = {
                "PATH": str(fake_bin), "HOME": str(root), "TMPDIR": str(root),
                "RETROBIOS_INSTALL_URL": "https://example.invalid/install.py",
                "FAKE_INSTALLER_SOURCE": str(REPO_ROOT / "install.py"),
            }
            proc = subprocess.run(
                ["/bin/sh", "-s", "--", "--list-platforms"], cwd=root, env=env,
                input=(REPO_ROOT / "install.sh").read_text(encoding="utf-8"),
                capture_output=True, text=True, timeout=60, check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("retroarch", proc.stdout)

    @unittest.skipIf(os.name == "nt", "the sh bootstrap is POSIX")
    def test_ctrl_c_during_the_download_ends_with_130(self):
        """Ctrl+C while install.py downloaded: the trap cleaned up and the
        script went on to blame the network, with code 1."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            started = root / "started"
            (fake_bin / "curl").write_text(
                f"#!/bin/sh\n: > '{started}'\nexec sleep 60\n", encoding="utf-8")
            (fake_bin / "curl").chmod(0o755)
            env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                   "TMPDIR": str(root),
                   "RETROBIOS_INSTALL_URL": "https://example.invalid/install.py"}
            for shell in ("sh", "bash"):
                if not shutil.which(shell):
                    continue
                with self.subTest(shell=shell):
                    started.unlink(missing_ok=True)
                    proc = subprocess.Popen(
                        [shell, "-s", "--", "--check"], cwd=root, env=env,
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, start_new_session=True)
                    proc.stdin.write((REPO_ROOT / "install.sh").read_text(encoding="utf-8"))
                    proc.stdin.close()
                    proc.stdin = None
                    try:
                        deadline = time.monotonic() + 30
                        while not started.exists() and time.monotonic() < deadline:
                            time.sleep(0.05)
                        self.assertTrue(started.exists(), "the download never started")
                        os.killpg(proc.pid, signal.SIGINT)
                        _out, err = proc.communicate(timeout=30)
                    finally:
                        if proc.poll() is None:
                            os.killpg(proc.pid, signal.SIGKILL)
                            proc.communicate()
                    self.assertEqual(proc.returncode, 130, err)
                    self.assertNotIn("could not be downloaded", err)
                    self.assertEqual(sorted(p.name for p in root.iterdir()),
                                     ["bin", "started"])

    @unittest.skipIf(os.name == "nt", "the sh bootstrap is POSIX")
    def test_a_versioned_python_is_found_beside_an_old_python3(self):
        """Buster keeps python3 at 3.7: the user installs python3.8 as the
        advice says, and the bootstrap, trying python3 and python alone,
        gave the same advice again."""
        root = scratch_dir(self)
        shutil.copy(REPO_ROOT / "install.sh", root / "install.sh")
        (root / "install.py").write_text("import sys\nprint('ran', sys.version_info >= (3, 8))\n")
        fake_bin = root / "bin"
        fake_bin.mkdir()
        old = ("#!/bin/sh\ncase \"$*\" in *SystemExit*) exit 1 ;; esac\n"
               "echo 3.7.3\n")
        for name in ("python3", "python"):
            (fake_bin / name).write_text(old)
            (fake_bin / name).chmod(0o755)
        tools = root / "tools"
        tools.mkdir()
        for tool in ("sh", "grep", "sort", "basename", "dirname", "uname", "sed", "tr"):
            found = shutil.which(tool)
            if found:
                (tools / tool).symlink_to(found)
        (fake_bin / "python3.11").symlink_to(sys.executable)
        proc = subprocess.run(
            [shutil.which("sh"), str(root / "install.sh")],
            env={"PATH": f"{fake_bin}{os.pathsep}{tools}", "HOME": str(root)},
            capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL, check=False)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("ran True", proc.stdout)

    def test_a_failed_download_says_so_in_one_message(self):
        """Offline, the one-liner printed curl's progress table and
        "curl: (6) ...", then exited 6, a code the table does not list."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            (fake_bin / "curl").write_text(
                "#!/bin/sh\necho 'curl: (6) Could not resolve host: x' >&2\nexit 6\n",
                encoding="utf-8",
            )
            (fake_bin / "curl").chmod(0o755)
            env = os.environ.copy()
            env.update(
                PATH=f"{fake_bin}{os.pathsep}{env['PATH']}",
                TMPDIR=str(root),
                RETROBIOS_INSTALL_URL="https://example.invalid/install.py",
            )
            proc = subprocess.run(
                ["sh", "-s"], cwd=root, env=env,
                input=(REPO_ROOT / "install.sh").read_text(encoding="utf-8"),
                capture_output=True, text=True, timeout=30, check=False,
            )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("could not be downloaded", proc.stderr)
        self.assertIn("Nothing was run and nothing was written", proc.stderr)
        self.assertEqual(proc.stderr.count("curl: (6)"), 1)

    def test_powershell_turns_a_failure_into_one_line(self):
        source = (REPO_ROOT / "install.ps1").read_text(encoding="utf-8")
        self.assertIn('[Console]::Error.WriteLine("Error: "', source)
        self.assertIn("winget install Python", source)

    @unittest.skipUnless(shutil.which("script"), "script(1) provides the terminal")
    def test_piped_one_liner_hands_the_terminal_to_the_installer(self):
        """curl | sh gives the installer the script as stdin, so isatty()
        was false and every question it asks was skipped on Linux and Mac."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe = root / "probe.py"
            probe.write_text(
                "import sys\nprint('installer stdin is a terminal:', sys.stdin.isatty())\n",
                encoding="utf-8",
            )
            fake_bin = root / "bin"
            fake_bin.mkdir()
            (fake_bin / "curl").write_text(
                "#!/bin/sh\n"
                "output=\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = --output ]; then output=$2; shift 2; else shift; fi\n"
                "done\n"
                f"cp -- {shlex.quote(str(probe))} \"$output\"\n",
                encoding="utf-8",
            )
            (fake_bin / "curl").chmod(0o755)
            env = os.environ.copy()
            env.update(
                PATH=f"{fake_bin}{os.pathsep}{env['PATH']}",
                TMPDIR=str(root),
                RETROBIOS_INSTALL_URL="https://example.invalid/install.py",
                RETROBIOS_INSTALL_SHA256=hashlib.sha256(probe.read_bytes()).hexdigest(),
            )
            piped = f"sh -s < {shlex.quote(str(REPO_ROOT / 'install.sh'))}"
            proc = subprocess.run(
                ["script", "-qec", piped, "/dev/null"],
                cwd=root, env=env, capture_output=True, text=True, timeout=30,
                check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("installer stdin is a terminal: True", proc.stdout)


class CaseVariants(unittest.TestCase):
    """The RetroArch list is folded for Windows and macOS: a Linux user got
    BIOS.col and np2kai/2608_BD.WAV only, while Mesen-CE opens bios.col and
    np2kai np2kai/2608_bd.wav. The manifest carries those as case_variants,
    installed where the directory keeps case."""

    def _manifest(self, variants):
        entry = {
            "dest": "BIOS.col", "sha1": "a" * 40, "sha256": "b" * 64,
            "size": 8192, "repo_path": "bios/Coleco/BIOS.col", "cores": None,
        }
        return {
            "manifest_version": 2, "platform": "retroarch", "files": [entry],
            "total_files": 1, "total_size": 8192, "case_variants": variants,
        }

    def test_a_kept_case_directory_is_detected(self):
        directory = scratch_dir(self) / "not" / "yet"
        self.assertTrue(install.keeps_case(directory))
        self.assertEqual(list(Path(directory.parents[1]).iterdir()), [])

    def test_variants_cross_the_trust_boundary(self):
        variant = {
            "dest": "bios.col", "sha1": "a" * 40, "sha256": "b" * 64,
            "size": 8192, "repo_path": "bios/Coleco/BIOS.col", "cores": ["mesence"],
        }
        install._validate_manifest(self._manifest([variant]), "retroarch")
        for bad in ({**variant, "dest": "../x"}, {**variant, "dest": "BIOS.col"}):
            with self.subTest(dest=bad["dest"]), self.assertRaises(ValueError):
                install._validate_manifest(self._manifest([bad]), "retroarch")

    def test_main_adds_them_only_where_case_is_kept(self):
        source = (REPO_ROOT / "install.py").read_text(encoding="utf-8")
        compact = " ".join(source.split())
        self.assertIn(
            'variants = manifest.get("case_variants", []) '
            "case_kept = keeps_case(bios_path) if variants and case_kept:", compact,
        )

    def test_the_published_retroarch_list_carries_them(self):
        manifest = json.loads((REPO_ROOT / "install" / "retroarch.json").read_text())
        variants = {e["dest"] for e in manifest.get("case_variants", [])}
        self.assertIn("bios.col", variants)
        lakka = json.loads((REPO_ROOT / "install" / "lakka.json").read_text())
        folded = {e["dest"] for e in manifest["files"]}
        # A case-keeping RetroArch install is the Lakka list, less what
        # Lakka's own core packages install (installed_on: lakka).
        from model.profiles import load_emulator_profiles

        installed = {
            entry.get("path") or entry.get("name")
            for profile in load_emulator_profiles(str(REPO_ROOT / "emulators")).values()
            for entry in profile.get("files") or []
            if isinstance(entry, dict) and "lakka" in (entry.get("installed_on") or [])
        }
        lakka_dests = {e["dest"] for e in lakka["files"]}
        self.assertEqual(lakka_dests - (folded | variants), set())
        self.assertEqual((folded | variants) - lakka_dests - installed, set(),
                         "a case-keeping RetroArch install equals the Lakka list")


class CaseTwinsOnAFoldingVolume(unittest.TestCase):
    """Batocera and Recalbox list np2kai/bios.rom and np2kai/BIOS.ROM, other
    bytes each. Installed to a share opened from Windows or an exFAT card,
    the second overwrote the first and --check never converged."""

    def test_one_file_per_name_is_kept(self):
        files = [{"dest": "np2kai/bios.rom"}, {"dest": "np2kai/BIOS.ROM"}, {"dest": "x.bin"}]
        kept, folded = install.fold_case_twins(files)
        self.assertEqual([f["dest"] for f in kept], ["np2kai/bios.rom", "x.bin"])
        self.assertEqual(folded, ["np2kai/BIOS.ROM"])

    def test_main_folds_only_where_case_is_not_kept(self):
        source = " ".join((REPO_ROOT / "install.py").read_text(encoding="utf-8").split())
        self.assertIn("if not case_kept: files, folded = fold_case_twins(files)", source)


class AListingAppliesItsOptionsOrRefusesThem(unittest.TestCase):
    """--list-systems --list-cores printed the systems alone, and
    --list-platforms, --list-targets and --list-emulators printed the same
    list with --system, --region or --core as without, code 0."""

    def test_two_listings_or_an_option_a_listing_ignores_are_refused(self):
        env = dict(os.environ, RETROBIOS_OS="linux")
        given = ["--platform", "retroarch", "--offline", "--no-input",
                 "--manifest", "install/retroarch.json"]
        for argv, words in (
            ([*given, "--list-systems", "--list-cores"],
             "--list-systems and --list-cores each print a list"),
            ([*given, "--list-cores", "--list-emulators"],
             "--list-cores and --list-emulators each print a list"),
            (["--list-platforms", "--list-systems", "--platform", "retroarch"],
             "--list-platforms and --list-systems each print a list"),
            (["--list-platforms", "--region", "us"],
             "--list-platforms prints the whole list, which --region does not narrow"),
            (["--list-platforms", "--platform", "retroarch"],
             "--list-platforms prints the whole list, which --platform does not narrow"),
            ([*given, "--list-targets", "--system", "sony-playstation"],
             "--list-targets prints the whole list, which --system does not narrow"),
            ([*given, "--list-targets", "--target", "switch"],
             "--list-targets prints the whole list, which --target does not narrow"),
            ([*given, "--list-emulators", "--system", "sony-playstation"],
             "--list-emulators prints the whole list, which --system does not narrow"),
            ([*given, "--list-emulators", "--core", "beetle_psx"],
             "--list-emulators prints the whole list, which --core does not narrow"),
        ):
            with self.subTest(argv=argv):
                proc = _install_run(env, *argv)
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertIn(words, proc.stderr)

    def test_the_options_a_listing_reads_still_apply(self):
        env = dict(os.environ, RETROBIOS_OS="linux")
        given = ["--platform", "retroarch", "--offline", "--no-input",
                 "--manifest", "install/retroarch.json"]
        whole = _install_run(env, *given, "--list-cores")
        narrowed = _install_run(env, *given, "--list-cores", "--system", "nintendo-gba")
        self.assertEqual((whole.returncode, narrowed.returncode), (0, 0), narrowed.stderr)
        self.assertLess(len(narrowed.stdout), len(whole.stdout))


class AMissingPackNamesTheOptionAndThePacksBeside(unittest.TestCase):
    """A typo in --from-pack said "Error: X does not exist": not the option,
    not the pack sitting next to the name typed."""

    def test_the_pack_beside_is_named(self):
        folder = scratch_dir(self)
        (folder / "RetroArch_BIOS_Pack.zip").write_bytes(b"")
        with self.assertRaises(ValueError) as raised:
            install.PackSource._resolve([folder / "RetroArch_BIOS_Pak.zip"])
        said = str(raised.exception)
        self.assertIn("--from-pack names a pack ZIP", said)
        self.assertIn(f"The packs in {folder}: RetroArch_BIOS_Pack.zip.", said)


class AnUnknownNameIsAnEvent(unittest.TestCase):
    """--events carried start then end with code 1 for an unknown platform,
    target or system: the reason was on stderr only, which readers ignore."""

    def _events(self, *argv: str) -> tuple[int, list[dict]]:
        env = {key: value for key, value in os.environ.items()
               if key != "RETROBIOS_BASE_URL"}
        env[install.OFFLINE_VARIABLE] = "1"
        with tempfile.TemporaryDirectory() as dest:
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "install.py"), "--dest", dest,
                 "--check", "--events", "--no-input", *argv],
                env=env, capture_output=True, text=True, timeout=120,
                stdin=subprocess.DEVNULL, check=False)
        return proc.returncode, [json.loads(line) for line in proc.stdout.splitlines()]

    def test_each_refusal_says_why(self):
        manifest = str(REPO_ROOT / "install" / "retroarch.json")
        for argv, words in (
                (["--platform", "nope"], "Unknown platform 'nope'"),
                (["--platform", "retroarch", "--manifest", manifest, "--system", "nope"],
                 "unknown system: nope"),
                (["--platform", "retroarch", "--manifest", manifest, "--core", "nope"],
                 "unknown core: nope"),
                (["--platform", "retroarch", "--manifest", manifest, "--emulator", "nope"],
                 "unknown emulator: nope")):
            with self.subTest(argv=argv):
                code, events = self._events(*argv)
                self.assertEqual(code, 2)
                errors = [event for event in events if event["event"] == "error"]
                self.assertEqual(len(errors), 1, events)
                self.assertEqual((errors[0]["stage"], errors[0]["reason"]),
                                 ("option", "unknown"))
                self.assertIn(words, errors[0]["message"])
                self.assertFalse(errors[0]["message"].startswith("Error"))
                self.assertEqual(events[-1]["event"], "end")


class ATypoGetsTheClosestName(unittest.TestCase):
    """--platform batocra, --system playstation or --core swanstaton were
    answered with every name the platform has, up to 400 on one line, and
    MiSTer FPGA as the site writes it was refused."""

    def test_the_names_the_site_writes_are_platforms(self):
        self.assertEqual(install.normalize_platform("MiSTer FPGA"), "misterfpga")
        self.assertEqual(install.normalize_platform("RetroArch "), "retroarch")
        self.assertEqual(install.normalize_platform("RetroDECK"), "retrodeck")

    def test_a_system_name_stands_for_the_list_it_gets(self):
        """--list-platforms printed `muOS: retroarch`, and --platform muos
        answered "Unknown platform"."""
        for typed, plat in (("muos", "retroarch"), ("muOS", "retroarch"),
                            ("ArkOS", "retroarch"), ("PAN4ELEC", "amberelec"),
                            ("JELOS", "retroarch")):
            out = io.StringIO()
            with self.subTest(typed=typed), contextlib.redirect_stdout(out):
                self.assertEqual(install.normalize_platform(typed), plat)
            self.assertIn(f"--platform {plat}", out.getvalue())

    def test_a_system_that_gets_no_list_is_still_refused(self):
        """TrimUI, which --list-platforms prints, was answered "Unknown
        platform" with no way forward."""
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            reported(install.normalize_platform, "TrimUI")
        self.assertNotIn("Unknown platform", err.getvalue())
        self.assertIn("--platform retroarch --dest FOLDER", err.getvalue())

    def test_a_frontend_without_a_bios_folder_says_what_to_do(self):
        """ES-DE, LaunchBox and Android have no BIOS folder: each emulator
        reads its own, and --platform es-de was "Unknown platform"."""
        for typed, said in (("es-de", "ES-DE"), ("esde", "ES-DE"),
                            ("launchbox", "LaunchBox"), ("android", "Android")):
            err = io.StringIO()
            with self.subTest(typed=typed), contextlib.redirect_stderr(err), \
                    self.assertRaises(SystemExit) as raised:
                reported(install.normalize_platform, typed)
            self.assertEqual(raised.exception.code, 2)
            self.assertIn(f"{said} has no BIOS folder of its own: run again without "
                          "--platform", err.getvalue())

    def test_a_system_name_is_suggested(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            reported(install.normalize_platform, "spruce")
        self.assertIn("Close matches: spruceOS.", err.getvalue())
        # The distinct names --list-platforms prints: Batocera is both a
        # platform and a system it recognises.
        names = [*install.AVAILABLE_PLATFORMS,
                 *(line.split(":")[0] for line in install._system_lines()),
                 *install._NO_BIOS_FOLDER]
        listed = len({install._name_key(name) for name in names})
        self.assertIn(f"lists all {listed}.", err.getvalue())

    def test_a_platform_typo_is_answered_with_one_name(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
            reported(install.normalize_platform, "batocra")
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("Close matches: batocera.", err.getvalue())
        self.assertNotIn("recalbox", err.getvalue())

    def test_a_system_is_found_inside_its_full_id(self):
        known = ["3do", "nintendo-gba", "sega-saturn", "sony-playstation", "sony-playstation-2"]
        with self.assertRaises(ValueError) as raised:
            install.resolve_choices(["playstation"], known, "system")
        text = str(raised.exception)
        self.assertIn("unknown system: playstation", text)
        self.assertIn("sony-playstation", text)
        self.assertIn("--list-systems", text)
        self.assertNotIn("3do", text)

    def test_a_core_typo_points_at_the_listing(self):
        known = [f"core{i}" for i in range(200)] + ["swanstation"]
        with self.assertRaises(ValueError) as raised:
            install.resolve_choices(["swanstaton"], known, "core")
        text = str(raised.exception)
        self.assertIn("Close matches: swanstation.", text)
        self.assertIn("--list-cores lists all 201", text)
        self.assertNotIn("core17", text)

    def test_a_name_spelled_as_the_site_writes_it(self):
        known = ["sony-playstation", "sony-playstation-2"]
        self.assertEqual(
            install.resolve_choices(["Sony PlayStation"], known, "system"),
            ["sony-playstation"],
        )

    def test_a_target_typo(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            reported(install._unknown_target, "swich", "retroarch",
                     {"switch": {}, "desktop": {}})
        self.assertIn("Close matches: switch.", err.getvalue())
        self.assertIn("--list-targets", err.getvalue())


class PlatformsAreNamedAsTheyNameThemselves(unittest.TestCase):
    """str.capitalize() printed Retroarch, Retrodeck and Misterfpga on the
    first screen a user sees."""

    def test_the_table_is_the_manifests(self):
        for plat in install.AVAILABLE_PLATFORMS:
            manifest = json.loads((REPO_ROOT / "install" / f"{plat}.json").read_text())
            with self.subTest(plat=plat):
                self.assertEqual(install.PLATFORM_NAMES[plat], manifest["display_name"])

    def test_the_menus_use_them(self):
        out = io.StringIO()
        with unittest.mock.patch("builtins.input", lambda _prompt="": "1"), \
                contextlib.redirect_stdout(out):
            install._prompt_platform_choice(
                [("misterfpga", Path("/m")), ("retrodeck", Path("/r"))])
        self.assertIn("MiSTer FPGA: /m", out.getvalue())
        self.assertIn("RetroDECK: /r", out.getvalue())
        self.assertEqual(install.display_name("romm", {"display_name": "RomM"}), "RomM")
        self.assertEqual(install.display_name("romm", {"display_name": "\x1b[2J"}), "RomM")


class RunsAgainstTheRealLists(unittest.TestCase, _LoopbackRun):
    """Behaviour read end to end over loopback."""

    def setUp(self):
        self.env = self.serve(self)

    def test_a_wrong_hash_is_listed_first(self):
        dest = self.home / "system"
        dest.mkdir()
        (dest / "scph5501.bin").write_bytes(b"junk")
        proc = _install_run(self.env, "--platform", "retroarch", "--dest", str(dest),
                            "--check", "--no-input", "--verbose")
        self.assertEqual(proc.returncode, 3, proc.stderr)
        listing = proc.stdout.split("to download.\n", 1)[1].splitlines()
        self.assertEqual(listing[0].strip(), "wrong copy: scph5501.bin")

    def test_a_dry_run_counts_the_data_trees_and_ends_on_its_last_line(self):
        proc = _install_run(self.env, "--platform", "retroarch", "--dest",
                            str(self.home / "s"), "--dry-run", "--no-input")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        self.assertIn("Nothing was written", lines[-1])
        at = next(index for index, line in enumerate(lines) if line.startswith("Would download"))
        # One total on the header, the data files among the kinds under it.
        self.assertNotIn("data files", lines[at])
        self.assertIn("data files", lines[at + 1])

    def test_dest_alone_says_whose_list_it_is(self):
        proc = _install_run(self.env, "--dest", str(self.home / "card"), "--dry-run",
                            "--no-input", "--system", "atari-lynx")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("File list: RetroArch", proc.stdout)
        self.assertIn("--platform", proc.stdout)

    def test_check_says_in_place_only_when_the_data_files_are_too(self):
        """The PSP BIOS in place and PPSSPP's assets absent: --check said
        "Everything is in place." then "169 to fetch", and exited 1."""
        dest = self.home / "psp"
        (dest / "PPSSPP").mkdir(parents=True)
        for repo_path in ("bios/Sony/PlayStation Portable/ppge_atlas.zim",
                          "bios/Other/ppsspp/PPSSPP/ppge_atlas.meta"):
            shutil.copy(REPO_ROOT / repo_path, dest / "PPSSPP")
        proc = _install_run(self.env, "--platform", "retroarch", "--dest", str(dest),
                            "--system", "sony-psp", "--check", "--no-input", "--verbose")
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertNotIn("Every file on the list is in place", proc.stdout)
        found = re.search(r"(\d+) in place, (\d+) missing", proc.stdout)
        self.assertIsNotNone(found, proc.stdout)
        self.assertIn(f"\n  {found.group(2)} data files to fetch\n", proc.stdout)

    def test_check_gives_one_total_offline(self):
        """Offline on an empty folder: "10805 missing", then "8164 files not in
        place" and "8164 files need the internet", the data files left out."""
        dest = self.home / "empty"
        dest.mkdir()
        proc = _install_run({**self.env, "RETROBIOS_INSTALL_OFFLINE": "1"}, "--platform",
                            "retroarch", "--dest", str(dest), "--check", "--no-input",
                            "--verbose",
                            "--manifest", str(REPO_ROOT / "install" / "retroarch.json"))
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        missing = re.search(r"0 in place, (\d+) missing", proc.stdout).group(1)
        self.assertIn(f"\n  {missing} files not in place.\n", proc.stdout)
        self.assertIn(f"  {missing} files need the internet", proc.stdout)

    def test_a_cores_folder_can_be_named(self):
        cores = self.home / "cores"
        cores.mkdir()
        (cores / "handy_libretro.so").write_bytes(b"")
        proc = _install_run(self.env, "--platform", "retroarch", "--dest",
                            str(self.home / "s"), "--cores-dir", str(cores),
                            "--dry-run", "--no-input", "--verbose")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("to the installed cores", proc.stdout)

    def test_a_cores_folder_that_cannot_be_listed_says_why(self):
        """A typo (core/ for cores/) or a closed folder read as an empty
        one: the run said "none in" and asked for the --cores-dir given."""
        missing = self.home / "core"
        a_file = self.home / "cores.txt"
        a_file.write_text("")
        for folder, why in ((missing, "does not exist"), (a_file, "is not a folder")):
            with self.subTest(why=why):
                proc = _install_run(self.env, "--platform", "retroarch", "--dest",
                                    str(self.home / "s"), "--cores-dir", str(folder),
                                    "--dry-run", "--no-input")
                self.assertEqual(proc.returncode, 1)
                self.assertIn(f"--cores-dir {folder} {why}", proc.stderr)
                self.assertNotIn("none in", proc.stderr)

    @unittest.skipIf(os.name == "nt" or os.geteuid() == 0,
                     "a folder without read permission is POSIX")
    def test_a_closed_cores_folder_says_so(self):
        cores = self.home / "closed"
        cores.mkdir()
        (cores / "handy_libretro.so").write_bytes(b"")
        os.chmod(cores, 0o000)
        try:
            proc = _install_run(self.env, "--platform", "retroarch", "--dest",
                                str(self.home / "s"), "--cores-dir", str(cores),
                                "--dry-run", "--no-input")
        finally:
            os.chmod(cores, 0o755)
        self.assertEqual(proc.returncode, 1)
        self.assertIn(f"--cores-dir {cores} cannot be opened by this user", proc.stderr)

    def test_no_core_found_says_how_to_go_on(self):
        proc = _install_run(self.env, "--platform", "retroarch", "--dest",
                            str(self.home / "s"), "--installed-cores", "--dry-run",
                            "--no-input")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("--cores-dir <cores folder>", proc.stderr)
        self.assertIn("without --installed-cores", proc.stderr)

    def test_a_refusal_reaches_the_event_stream(self):
        """--events read start, detect, then end with code 1: the reason
        went to stderr alone."""
        for options, reason in ((["--cores-dir", str(self.home / "core")], "not_found"),
                                (["--installed-cores"], "none")):
            with self.subTest(reason=reason):
                proc = _install_run(self.env, "--platform", "retroarch", "--dest",
                                    str(self.home / "s"), *options, "--dry-run", "--events")
                self.assertEqual(proc.returncode, 1, proc.stderr)
                events = [json.loads(line) for line in proc.stdout.splitlines()]
                self.assertEqual([event["event"] for event in events][-2:], ["error", "end"])
                error = events[-2]
                self.assertEqual((error["stage"], error["reason"], error["platform"]),
                                 ("cores", reason, "retroarch"))
                self.assertIn(error["message"].split(". ")[0], proc.stderr)


if __name__ == "__main__":
    unittest.main()
