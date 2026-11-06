"""The PortMaster port: its archive, its event reader and its fallback screens.

The screens are driven here with PortMasterDialog's functions replaced by
stubs that record each command and answer from a script, and with a fake
install.py that writes canned --events streams. What a device adds (pugwash
drawing, the pad, mount, the network) is not exercised. The full-screen
route of the port, and the other launchers, are in test_handheld_launchers.
"""
from __future__ import annotations

import tests  # noqa: F401  offline, scratch under tmp/, the suite's own cache

import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PORT = REPO_ROOT / "ports" / "RetroBIOS"
SHARED = REPO_ROOT / "ports" / "shared"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import build_port  # noqa: E402

_spec = importlib.util.spec_from_file_location("install", REPO_ROOT / "install.py")
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)
_spec = importlib.util.spec_from_file_location("rbevents", SHARED / "rbevents.py")
rbevents = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rbevents)

SCRIPTS = [PORT / "RetroBIOS.sh", PORT / "retrobios" / "screens.txt"]


def _tempdir(test: unittest.TestCase) -> Path:
    scratch = REPO_ROOT / "tmp"
    scratch.mkdir(exist_ok=True)
    path = Path(tempfile.mkdtemp(dir=str(scratch)))
    test.addCleanup(shutil.rmtree, path, True)
    return path


class EveryScriptParses(unittest.TestCase):
    def test_only_dialog_functions_the_oldest_releases_have(self):
        """PortMaster 2024.02.26 and 8.5.23 define these in PortMasterDialog.txt,
        and have no funcs.txt: pm_message and the rest would be undefined."""
        known = {"PortMasterDialogInit", "PortMasterDialog", "PortMasterDialogResult",
                 "PortMasterDialogExit", "PortMasterIPCheck"}
        commands = {"register_set_info", "register_clear", "selection_list",
                    "messages_begin", "message", "messages_end", "progress",
                    "progress_clear", "check_runtime"}
        text = "\n".join(path.read_text(encoding="utf-8") for path in SCRIPTS)
        used = set(re.findall(r"\b(PortMasterDialog\w*|PortMasterIPCheck)\b", text))
        self.assertLessEqual(used - {"PortMasterDialog.txt"}, known)
        self.assertNotRegex(text, r"\bpm_message\b|\bpm_platform_helper\b")
        sent = set(re.findall(r'(?:PortMasterDialog|rb_answer) "(\w+)"', text))
        self.assertLessEqual(sent, commands)
        self.assertNotIn("register_clear_info", text)

    def test_pugwash_applies_the_button_layout(self):
        """Under no-harbour pugwash skips apply_button_mapping, so A and B
        land swapped on the devices PortMaster fixes (PortMaster-GUI
        pugwash/main.py, app.py): every start is no-check."""
        text = (PORT / "retrobios" / "screens.txt").read_text(encoding="utf-8")
        inits = re.findall(r'PortMasterDialogInit "([\w-]+)"', text)
        self.assertTrue(inits)
        self.assertEqual(set(inits), {"no-check"})


class ThePortArchive(unittest.TestCase):
    def setUp(self):
        self.out = _tempdir(self)

    def _build(self, name: str = "RetroBIOS.zip") -> Path:
        return build_port.build_port(self.out / name)

    def test_layout_portmaster_installs(self):
        """One launch script at the top, one folder holding port.json: what
        harbourmaster's captain.check_port accepts without a warning."""
        with zipfile.ZipFile(self._build()) as zf:
            names = zf.namelist()
            port = json.loads(zf.read("retrobios/port.json"))
            mode = zf.getinfo("RetroBIOS.sh").external_attr >> 16
        self.assertEqual(names, sorted(names))
        self.assertEqual([n for n in names if "/" not in n], ["RetroBIOS.sh"])
        self.assertEqual({n.split("/")[0] for n in names if "/" in n}, {"retrobios"})
        self.assertEqual([n for n in names if n.endswith(".sh")], ["RetroBIOS.sh"])
        for member in ("retrobios/install.py", "retrobios/rbevents.py",
                       "retrobios/screens.txt", "retrobios/tui.txt",
                       "retrobios/retrobios.gptk", "retrobios/gameinfo.xml",
                       "retrobios/retrobios.md", "retrobios/licenses/LICENSE-retrobios.txt"):
            self.assertIn(member, names)
        self.assertEqual(port["version"], 4)
        self.assertEqual(port["name"], "retrobios.zip")
        self.assertEqual(port["items"], ["RetroBIOS.sh", "retrobios"])
        self.assertEqual(port["attr"]["genres"], ["other"])
        self.assertTrue(mode & 0o111, "the launch script is executable")

    def test_bundled_installer_is_the_pinned_one(self):
        with zipfile.ZipFile(self._build()) as zf:
            bundled = hashlib.sha256(zf.read("retrobios/install.py")).hexdigest()
        self.assertEqual(bundled, build_port.pinned_installer_sha256())
        install_sh = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn(f'DEFAULT_INSTALL_SHA256="{bundled}"', install_sh)


class LauncherIndex(unittest.TestCase):
    """install/launchers/index.json, which --add-app reads, lists the members of
    the archives built from the same tree, each with its size and hash."""

    def test_the_committed_list_is_current(self):
        import generate_launcher_index  # noqa: PLC0415

        text = generate_launcher_index.render(generate_launcher_index.build_index())
        self.assertEqual(
            generate_launcher_index.OUTPUT.read_text(encoding="utf-8"), text,
            "install/launchers/index.json is stale: run "
            "python scripts/generate_launcher_index.py")

    def test_the_installer_page_says_when_to_rewrite_it(self):
        """The list records install.py's SHA-256, and the page that says
        what a change to install.py rewrites named only the two pins."""
        page = (REPO_ROOT / "wiki" / "installer.md").read_text(encoding="utf-8")
        section = page.split("## Changing the installer", 1)[1].split("\n## ", 1)[0]
        self.assertIn("scripts/generate_launcher_index.py", section)

    def test_every_member_of_the_archives_is_listed(self):
        import generate_launcher_index  # noqa: PLC0415

        index = json.loads(generate_launcher_index.OUTPUT.read_text(encoding="utf-8"))
        places = {place.key: place for place in install.APP_PLACES.values()}
        for key, archive in generate_launcher_index.LAUNCHER_ARCHIVES.items():
            with self.subTest(key=key):
                launcher = index["launchers"][key]
                listed = launcher.get("members") or launcher["files"]
                names = [entry.get("name") or entry["dest"] for entry in listed]
                prefix = "" if "members" in launcher else places[key].folder + "/"
                self.assertEqual(sorted(names), sorted(
                    prefix + name for name, _path in build_port.archive_members(archive)))
                for entry in listed:
                    if "repo_path" in entry:
                        data = (REPO_ROOT / entry["repo_path"]).read_bytes()
                        self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])

    def test_the_list_refuses_an_installer_the_bootstraps_do_not_pin(self):
        import generate_launcher_index  # noqa: PLC0415

        root = _tempdir(self)
        shutil.copyfile(REPO_ROOT / "install.py", root / "install.py")
        (root / "install.sh").write_text('DEFAULT_INSTALL_SHA256="' + "0" * 64 + '"\n')
        with self.assertRaises(ValueError):
            generate_launcher_index.build_index(root)


class EventRecords(unittest.TestCase):
    """rbevents turns --events into fields the FIFO carries intact."""

    def test_fields_are_fifo_safe(self):
        self.assertEqual(rbevents.clean("a\tb\n[x]*?  c"), "a b x c")
        out = io.StringIO()
        rbevents.record(out, "file", "", "a")
        self.assertEqual(out.getvalue(), "file\t-\ta\n")

    def test_follow_writes_the_outcome(self):
        stream = [
            json.dumps({"event": "download", "platform": "p", "files": 1, "bytes": 2048}),
            "not json",
            json.dumps({"event": "downloaded", "dest": "x.bin", "ok": False,
                        "reason": "HTTP 404", "size": 2048, "files_done": 1,
                        "files_total": 1, "bytes_done": 0, "bytes_total": 2048}),
            json.dumps({"event": "summary", "mode": "install", "installed": 0,
                        "up_to_date": 4, "pending": 1,
                        "failed": [{"dest": "x.bin", "reason": "HTTP 404"}],
                        "skipped": [], "left_out": [],
                        "kept": [{"folder": "/b/retrobios-backup/1", "files": 1,
                                  "bytes": 2048}], "interrupted": False}),
            json.dumps({"event": "end", "code": 2}),
        ]
        out, summary = io.StringIO(), io.StringIO()
        rbevents.follow(stream, out, summary)
        self.assertEqual(out.getvalue().splitlines(), [
            "download\t1\t2 KB", "file\t1\t1\tfailed\tx.bin\t0 B\t2 KB"])
        self.assertEqual(summary.getvalue().splitlines(), [
            "summary\t0\t4\t1\t0", "failed\tx.bin\tHTTP 404",
            "kept\t/b/retrobios-backup/1\t1\t2 KB", "end\t2"])

    def test_a_system_id_that_is_no_slug_is_dropped(self):
        # The id becomes a bash array subscript in the launcher, where a
        # command substitution in it would run.
        def system(name):
            return json.dumps({"event": "system", "platform": "p", "system": name,
                               "name": "N", "files": 1, "present": 0, "missing": 1,
                               "wrong_hash": 0, "bytes_needed": 1})
        stream = [
            json.dumps({"event": "detect", "os": "linux", "os_name": "X",
                        "platforms": [{"platform": "p", "name": "P", "bios_dir": "/b"}]}),
            system("$(touch pwned)"), system("a`id`"), system("sony-playstation"),
        ]
        out = io.StringIO()
        rbevents.status(stream, out)
        ids = [line.split("\t")[1] for line in out.getvalue().splitlines()
               if line.startswith("system\t")]
        self.assertEqual(ids, ["sony-playstation"])

    def test_launcher_never_double_expands_a_subscript(self):
        text = (PORT / "retrobios" / "screens.txt").read_text()
        self.assertNotRegex(text, r'unset\s+"[^"]*\[\$')

    def test_a_run_without_end_says_so(self):
        out = io.StringIO()
        rbevents.status([], out)
        self.assertEqual(out.getvalue(), "end\tnone\n")


FAKE_INSTALL = r'''
import json, os, sys
from pathlib import Path

state = Path(os.environ["FAKE_STATE"])
scenario = os.environ["FAKE_SCENARIO"]
keys = json.loads(os.environ["FAKE_KEYS"])
with (state / "calls.txt").open("a") as fh:
    fh.write(" ".join(sys.argv[1:]) + "\n")
check = "--check" in sys.argv


def emit(kind, **fields):
    assert sorted(fields) == sorted(keys[kind]), kind
    print(json.dumps({"event": kind, **fields}), flush=True)


def end(code):
    emit("end", code=code)
    sys.exit(code)


emit("start", schema=1, installer="fake", mode="check" if check else "install")
if scenario == "nodetect":
    emit("detect", os="linux", os_name="Fake OS 1.0", platforms=[])
    end(1)
if scenario == "conflict":
    emit("error", stage="detect", reason="conflict", platform="",
         message="JELOS and Koriki are both detected here, and a machine runs one")
    end(1)
emit("detect", os="linux", os_name="Fake OS 1.0", platforms=[
    {"platform": "retroarch", "name": "RetroArch", "bios_dir": "/roms/bios"}])
if scenario == "offline":
    emit("error", stage="manifest", reason="network", platform="retroarch",
         message="the file list could not be fetched: [Errno 101] Network is unreachable")
    end(1)
done = scenario == "complete" or (state / "installed").exists()
if check:
    for system, name, files, present, missing, wrong, needed in (
        ("sys-a", "Alpha*", 2, 2 if done else 0, 0 if done else 1, 0 if done else 1,
         0 if done else 300),
        ("sys-b", "Bravo", 1, 1, 0, 0, 0),
    ):
        emit("system", platform="retroarch", system=system, name=name, files=files,
             present=present, missing=missing, wrong_hash=wrong, bytes_needed=needed)
    emit("check", platform="retroarch", name="RetroArch", bios_dir="/roms/bios", files=3,
         present=3 if done else 1, missing=0 if done else 1, wrong_hash=0 if done else 1,
         bytes_needed=0 if done else 300, data_missing=0, not_installable=1)
    emit("summary", mode="check", installed=0, up_to_date=3 if done else 1,
         pending=0 if done else 2, failed=[], skipped=[], left_out=[], kept=[],
         interrupted=False)
    end(0 if done else 1)
emit("download", platform="retroarch", files=2, bytes=300)
for n, (dest, size) in enumerate((("a.bin", 100), ("b.bin", 200)), 1):
    emit("downloaded", dest=dest, ok=True, reason="", size=size, files_done=n,
         files_total=2, bytes_done=100 if n == 1 else 300, bytes_total=300)
(state / "installed").write_text("")
emit("summary", mode="install", installed=2, up_to_date=1, pending=0, failed=[],
     skipped=[{"reason": "not_found", "label": "not found", "files": 1, "required": 1}],
     left_out=[], kept=[{"folder": "/roms/retrobios-backup/20261022-153000", "files": 1,
                         "bytes": 100}], interrupted=False)
end(0)
'''

# PortMasterDialog.txt replaced: every call is a trace line, fields split by
# \x1f, and each selection list is answered from the answers file.
DRIVER = r'''
trace() {
  printf '%s' "$1"
  shift
  local field
  for field in "$@"; do printf '\x1f%s' "$field"; done
  printf '\n'
} >> "$RB_TRACE"
PM_PID=""
PM_DONE="$FAKE_STATE/pm_done"
PortMasterDialogInit() { trace INIT "$@"; }
PortMasterDialogExit() { trace EXIT; }
PortMasterIPCheck() { [ -n "$FAKE_IP" ] && echo 192.168.0.1; }
PortMasterDialog() { trace CMD "$@"; }
PortMasterDialogResult() {
  trace ASK "$@"
  if [ "$1" = "check_runtime" ]; then
    echo "${FAKE_RUNTIME:-FAIL}"
    return
  fi
  local answer
  answer=$(head -n 1 "$RB_ANSWERS")
  sed -i 1d "$RB_ANSWERS"
  case "$answer" in
    "") echo CANCEL ;;
    WAIT:*) printf '%s' "${answer#WAIT:}" > "$PM_DONE"; echo WAIT ;;
    *) echo "$answer" ;;
  esac
}
source "$RB_SHARED/tui.txt"
source "$GAMEDIR/screens.txt"
if [ -n "$FAKE_ARCH" ]; then
  rb_arch() { echo "$FAKE_ARCH"; }
fi
rb_select_python
rb_main
trace STATUS "$?"
'''


class TheScreens(unittest.TestCase):
    """Which screens the port shows, scenario by scenario."""

    def run_port(self, scenario: str, answers: list[str], before=None, **env: str) -> list[tuple]:
        work = _tempdir(self)
        (work / "install.py").write_text(FAKE_INSTALL)
        (work / "driver.sh").write_text(DRIVER)
        (work / "answers").write_text("".join(f"{a}\n" for a in answers))
        bin_dir = work / "bin"
        bin_dir.mkdir()
        # The oldest Python install.py supports, where it is installed: the
        # event reader runs on whatever the device has.
        (bin_dir / "python3").symlink_to(shutil.which("python3.8") or sys.executable)
        # The network probe: 0 answers, 7 cannot connect.
        (bin_dir / "curl").write_text('#!/bin/sh\nexit "${FAKE_CURL:-0}"\n')
        (bin_dir / "curl").chmod(0o755)
        (work / "packs").mkdir()
        if before is not None:
            before(work)
        self.work = work
        full_env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(work),
            "GAMEDIR": str(PORT / "retrobios"),
            "RB_SHARED": str(SHARED),
            "RB_EVENTS": str(SHARED / "rbevents.py"),
            "RB_PACK_PATH": str(work / "packs"),
            "controlfolder": str(work / "PortMaster"),
            "ESUDO": "",
            "RB_STATE": str(work / "run"),
            "RB_LOG": str(work / "log.txt"),
            "RB_INSTALL": str(work / "install.py"),
            "RB_TRACE": str(work / "trace"),
            "RB_ANSWERS": str(work / "answers"),
            "FAKE_STATE": str(work),
            "FAKE_SCENARIO": scenario,
            "FAKE_KEYS": json.dumps(install.EVENT_KEYS),
            **env,
        }
        proc = subprocess.run(["bash", str(work / "driver.sh")], env=full_env,
                              capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        log = work / "log.txt"
        self.assertNotIn("Traceback", log.read_text() if log.exists() else "")
        return self._screens((work / "trace").read_text(encoding="utf-8"))

    def _screens(self, trace: str) -> list[tuple]:
        """INIT, EXIT, STATUS, each list shown with its entries, and the
        progress and message commands, in order."""
        registers: dict[str, dict[str, tuple[str, str]]] = {}
        shown: list[tuple] = []
        for line in trace.splitlines():
            kind, *fields = line.split("\x1f")
            for field in fields:
                self.assertNotRegex(field, r"[*?\[\]\t]", line)
            if kind == "CMD" and fields[0] == "register_clear":
                registers[fields[1]] = {}
            elif kind == "CMD" and fields[0] == "register_set_info":
                info = dict(item.split(":", 1) for item in fields[3:])
                registers.setdefault(fields[1], {})[fields[2]] = (
                    info["title"], info["description"])
            elif kind == "ASK" and fields[0] == "selection_list":
                self.assertIn("--want-cancel", fields)
                name = fields[1].split("=", 1)[1]
                shown.append(("list", name, dict(registers[name])))
            elif kind == "ASK":
                shown.append(("ask", *fields))
            elif kind == "CMD" and fields[0] in ("progress", "message"):
                shown.append(("cmd", *fields))
            elif kind in ("INIT", "EXIT", "STATUS"):
                shown.append((kind, *fields))
        for screen in shown:
            if screen[0] == "list":
                titles = [title for title, _desc in screen[2].values()]
                self.assertTrue({"Back", "Quit", "Back to the menu"} & set(titles),
                                f"{screen[1]} has no Back or Quit entry")
        return shown

    def lists(self, shown: list[tuple]) -> list[tuple[str, list[str]]]:
        return [(s[1], list(s[2])) for s in shown if s[0] == "list"]

    def calls(self) -> list[str]:
        return (self.work / "calls.txt").read_text().splitlines()

    def test_all_present(self):
        shown = self.run_port("complete", ["quit"])
        self.assertEqual(self.lists(shown), [("menu", ["status", "check", "quit"])])
        menu = shown[[s[0] for s in shown].index("list")][2]
        self.assertEqual(menu["status"][0], "Fake OS 1.0: all 3 BIOS files present")
        self.assertEqual(shown[0], ("INIT", "no-check"))
        self.assertEqual(shown[-2:], [("EXIT",), ("STATUS", "0")])
        self.assertEqual(self.calls(), ["--check --events"])

    def test_some_missing_update_everything(self):
        shown = self.run_port("missing", ["update", "back", "quit"])
        self.assertEqual(self.lists(shown), [
            ("menu", ["status", "update", "choose", "check", "quit"]),
            ("summary", ["info:result", "back", "quit", "info:kept:1",
                         "info:skipped:not found"]),
            ("menu", ["status", "check", "quit"]),
        ])
        menu = shown[[s[0] for s in shown].index("list")][2]
        self.assertEqual(menu["status"][0], "Fake OS 1.0: 1/3 BIOS files, 1 missing, 1 wrong hash")
        self.assertIn("Downloads 2 files, 300 B, to /roms/bios", menu["update"][1])
        progress = [s for s in shown if s[:2] == ("cmd", "progress")]
        self.assertEqual(progress, [
            ("cmd", "progress", "Starting", "0", "1"),
            ("cmd", "progress", "a.bin, 100 B of 300 B", "1", "2"),
            ("cmd", "progress", "b.bin, 300 B of 300 B", "2", "2"),
        ])
        summary = [s for s in shown if s[:2] == ("list", "summary")][0][2]
        self.assertEqual(summary["info:result"][0], "Installed: 2 files")
        self.assertEqual(summary["info:kept:1"][0], "Kept 1 file you had (100 B)")
        self.assertIn("/roms/retrobios-backup/20261022-153000", summary["info:kept:1"][1])
        self.assertEqual(self.calls(), [
            "--check --events",
            "--events --platform retroarch",
            "--check --events --platform retroarch",
        ])

    def test_some_missing_choose_systems(self):
        shown = self.run_port("missing", [
            "choose", "update", "sys:sys-a", "sys:sys-a", "sys:sys-a", "update", "quit"])
        systems = [s[2] for s in shown if s[:2] == ("list", "systems")]
        self.assertEqual(list(systems[0]), ["update", "back", "sys:sys-a"])
        self.assertEqual(systems[0]["sys:sys-a"][0], "Alpha")
        self.assertEqual(systems[1]["sys:sys-a"][0], "Alpha")
        self.assertEqual(systems[2]["sys:sys-a"][0], "Alpha (selected)")
        self.assertEqual(systems[2]["update"][0], "Update the 1 selected")
        self.assertIn("1 system complete, not listed", systems[0]["back"][1])
        self.assertEqual(self.calls()[1], "--events --platform retroarch --system sys-a")
        self.assertEqual(self.lists(shown)[-1][0], "summary")
        self.assertEqual(shown[-1], ("STATUS", "0"))

    def test_no_network(self):
        shown = self.run_port("offline", ["quit"])
        self.assertEqual(self.lists(shown), [("notice", ["info", "check", "quit"])])
        notice = shown[[s[0] for s in shown].index("list")][2]
        self.assertEqual(notice["info"][0], "No connection")
        self.assertIn("connect to Wi-Fi", notice["info"][1])
        self.assertIn("/roms/bios", notice["info"][1])
        # Where a pack goes, and which one.
        self.assertIn(f"copy it into {self.work / 'packs'} on the SD card", notice["info"][1])
        self.assertIn("whose name contains RetroArch", notice["info"][1])

    def test_offline_with_a_pack_on_the_card(self):
        pack = None

        def place(work: Path) -> None:
            nonlocal pack
            pack = work / "packs" / "RetroArch_Lakka_v1.22.2_BIOS_Pack.zip"
            pack.write_bytes(b"")

        shown = self.run_port("missing", ["update", "quit"], FAKE_CURL="7", before=place)
        self.assertEqual(self.calls()[:2], [
            f"--check --events --from-pack {pack}",
            f"--events --from-pack {pack} --platform retroarch",
        ])
        self.assertEqual(shown[-1], ("STATUS", "0"))

    def test_detection_failure(self):
        shown = self.run_port("nodetect", ["check", "quit"])
        self.assertEqual([name for name, _keys in self.lists(shown)], ["notice", "notice"])
        notice = shown[[s[0] for s in shown].index("list")][2]
        self.assertEqual(notice["info"][0], "No BIOS folder found")
        self.assertIn("Fake OS 1.0", notice["info"][1])
        self.assertIn("--dest", notice["info"][1])
        self.assertEqual(len(self.calls()), 2)

    def test_two_systems_found(self):
        shown = self.run_port("conflict", ["check", "quit"])
        notice = shown[[s[0] for s in shown].index("list")][2]
        self.assertEqual(notice["info"][0], "Two systems found")
        self.assertIn("JELOS and Koriki", notice["info"][1])
        self.assertIn("--dest", notice["info"][1])

    def test_python_too_old(self):
        for arch, env, words in (
            ("armv7l", {}, ["3.7.3", "aarch64 only", "armv7l", "--dest"]),
            ("aarch64", {}, ["3.7.3", "needs a connection", "--dest"]),
            ("aarch64", {"FAKE_IP": "1", "FAKE_RUNTIME": "FAIL"},
             ["3.7.3", "could not be installed", "--dest"]),
        ):
            with self.subTest(arch=arch, env=env):
                shown = self.run_old(arch, **env)
                lists = self.lists(shown)
                self.assertEqual(lists, [("notice", ["info", "quit"])])
                notice = [s for s in shown if s[0] == "list"][0][2]
                self.assertEqual(notice["info"][0], "Python 3.8 or newer is needed")
                for word in words:
                    self.assertIn(word, notice["info"][1])
                self.assertEqual(shown[-1], ("STATUS", "1"))
                self.assertFalse((self.work / "calls.txt").exists())
                asked_runtime = ("ask", "check_runtime", "python_3.11.squashfs") in shown
                self.assertEqual(asked_runtime, bool(env.get("FAKE_RUNTIME")))

    def run_old(self, arch: str, **env: str) -> list[tuple]:
        """A python3 on PATH that is 3.7.3, ahead of every other."""
        holder = _tempdir(self)
        fake = holder / "python3"
        fake.write_text('#!/bin/sh\n[ "$1" = "--version" ] && echo "Python 3.7.3"\nexit 1\n')
        fake.chmod(0o755)
        return self.run_port("complete", [], FAKE_ARCH=arch,
                             PATH=f"{holder}{os.pathsep}{os.environ['PATH']}", **env)

    def test_an_answer_after_the_old_30_second_wait(self):
        """2024.02.26 and 8.5.23 stop waiting after 30 s and answer WAIT:
        the port reads the answer pugwash writes later."""
        shown = self.run_port("complete", ["WAIT:quit"])
        self.assertEqual(shown[-1], ("STATUS", "0"))
        self.assertEqual(len(self.lists(shown)), 1)


if __name__ == "__main__":
    unittest.main()
