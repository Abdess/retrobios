"""The sandbox a demo recording runs in: the served checkout, the namespace and its variables."""

from __future__ import annotations

import functools
import http.server
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from core.paths import REPO_ROOT
from sitegen.democard import CARD_SIZE
from sitegen.demovariants import VARIANTS, Variant

# The boot splash title dArkOS is recognised by on the device
# (finishing_touches.sh:359-361, install.py _PLYMOUTH_TITLE), dated as its
# latest release, v08272026.
SPLASH = "/usr/share/plymouth/themes/text.plymouth"
SPLASH_TEXT = "[Plymouth Theme]\ntitle=dArkOS (08272026)\n"

# Where ArkOS keeps what the handheld recording needs: the Tools menu folder
# the launcher sits in (ports/tools/RetroBIOS.sh, RB_DIR), the user, and
# EASYROMS at /roms (install.py _OS_RULES, ArkOS).
ARK_HOME = "/home/ark"
ARK_TOOLS = "/opt/system/Tools"
ARK_INSTALLER = f"{ARK_TOOLS}/retrobios/install.py"


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass


@contextmanager
def served_repository() -> Iterator[str]:
    """The repository on a loopback port, the base URL install.py accepts
    without HTTPS."""
    handler = functools.partial(QuietHandler, directory=str(REPO_ROOT))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _write_rc(work: Path) -> Path:
    """The startup file of the shell the recording types into: the prompt,
    no history, and the site's address answered with the local bootstrap."""
    rc = work / "bashrc"
    rc.write_text(
        "PS1='$ '\n"
        "unset HISTFILE PROMPT_COMMAND\n"
        "curl() {\n"
        '  if [ "$*" = "-fsSL https://abdess.github.io/retrobios/i" ]; then\n'
        '    printf \'exec %s "$@"\\n\' "$RETROBIOS_DEMO_BOOTSTRAP"\n'
        "  else\n"
        '    command curl "$@"\n'
        "  fi\n"
        "}\n"
        "clear\n",
        encoding="utf-8",
    )
    return rc


def _computer_session(variant: Variant, work: Path, names: list[str]) -> str:
    rc = _write_rc(work)
    interactive = f'bash --noprofile --rcfile "{rc}" -i'
    mount = variant.mount
    return (
        "inner='set -eu\n"
        "mount -t tmpfs -o mode=0755 demo /media\n"
        "mount -t tmpfs -o mode=0755 demo /mnt\n"
        f"mkdir {mount}\n"
        f"mount -t tmpfs -o size={CARD_SIZE},mode=0755 EASYROMS {mount}\n"
        f'cp -a "$RETROBIOS_DEMO_CARD/." {mount}/\n'
        'cd "$HOME"\n'
        'exec unshare --user --map-user="$RETROBIOS_DEMO_UID" '
        '--map-group="$RETROBIOS_DEMO_GID" env -i '
        + " ".join(f'{name}="${name}"' for name in names) + ' "$@"\'\n'
        'if [ "$#" -eq 0 ]; then\n'
        f"  set -- {interactive}\n"
        "fi\n"
        'exec unshare --user --mount --map-root-user /bin/sh -c "$inner" sh "$@"\n'
    )


def _usr_binds() -> str:
    """This machine's /usr, entry by entry over a tmpfs, /usr/share too: a
    bind of the whole of /usr is read-only, and dArkOS's splash file goes in
    /usr/share/plymouth, which this machine does not have."""
    def bind(source: Path) -> str:
        return (f"--symlink {os.readlink(source)} {source}" if source.is_symlink()
                else f"--ro-bind {source} {source}")
    usr = Path("/usr")
    share = usr / "share"
    words = ["--tmpfs /usr"]
    words += [bind(entry) for entry in sorted(usr.iterdir()) if entry != share]
    words += [bind(entry) for entry in sorted(share.iterdir()) if entry.name != "plymouth"]
    words.append(f'--ro-bind "$RETROBIOS_DEMO_SPLASH" {SPLASH}')
    return " ".join(words)


def _device_session(names: list[str]) -> str:
    """dArkOS's own root, made of this machine's /usr and /etc: the user and
    the Tools menu folder ArkOS's line keeps, the boot splash title dArkOS
    is recognised by, EASYROMS at /roms, and the installer where the Tools
    menu launcher keeps it."""
    binds = " ".join(
        f"--symlink usr/{name} /{name}" for name in ("bin", "lib", "lib64", "sbin"))
    return (
        'if [ "$#" -eq 0 ]; then\n'
        f'  set -- python3 {ARK_INSTALLER} --tui\n'
        "fi\n"
        "exec bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-uts --hostname darkos "
        '--uid "$RETROBIOS_DEMO_UID" --gid "$RETROBIOS_DEMO_GID" '
        f"{_usr_binds()} {binds} --ro-bind /etc /etc --proc /proc --dev /dev "
        f"--tmpfs /tmp --dir {ARK_HOME} --dir /opt/inttools --dir {ARK_TOOLS} "
        f'--ro-bind "$RETROBIOS_DEMO_INSTALLER" {ARK_INSTALLER} '
        f'--ro-bind "$RETROBIOS_DEMO_CARD" /card --size 31138512896 --tmpfs /roms '
        f"--chdir {ARK_HOME} "
        "/bin/sh -c 'cp -a /card/. /roms/ && exec env -i \"$@\"' sh "
        + " ".join(f'{name}="${name}"' for name in names) + ' "$@"\n'
    )


def write_session(work: Path, names: list[str], variant: Variant = VARIANTS["default"]) -> Path:
    """The program the recording's shell becomes: the card mounted in a
    namespace of its own, then a clean interactive shell (or, on the
    device, the interface), or the command given as arguments, with only
    the variables names lists."""
    body = (_device_session(names) if variant.place == "device"
            else _computer_session(variant, work, names))
    session = work / f"session{variant.suffix}.sh"
    session.write_text("#!/bin/sh\n# Written by scripts/make_demo.py.\nset -eu\n" + body,
                       encoding="utf-8")
    session.chmod(0o755)
    return session


def _splash(work: Path) -> Path:
    """dArkOS's boot splash theme, bound at SPLASH on the device."""
    path = work / "text.plymouth"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SPLASH_TEXT, encoding="utf-8")
    return path


def session_env(base_url: str, work: Path, card: Path,
                variant: Variant = VARIANTS["default"]) -> dict[str, str]:
    """The variables of the run, and of nothing else: the namespace starts
    from an empty environment."""
    own = {
        "RETROBIOS_DEMO_CARD": str(card),
        "RETROBIOS_DEMO_UID": str(os.getuid()),
        "RETROBIOS_DEMO_GID": str(os.getgid()),
    }
    if variant.place == "device":
        return {
            **own,
            "HOME": ARK_HOME,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            # ArkOS's console (ports/tools/RetroBIOS.sh: console 1).
            "TERM": "linux",
            "RETROBIOS_OS": variant.os_type,
            "RETROBIOS_BASE_URL": base_url,
            # What ports/shared/tui.txt exports before the interface starts.
            "RETROBIOS_PAD": "gptokeyb",
            "RETROBIOS_IDLE_EXIT": "300",
            "RETROBIOS_DEMO_INSTALLER": str(REPO_ROOT / "install.py"),
            "RETROBIOS_DEMO_SPLASH": str(_splash(work)),
        }
    home = work / "home"
    home.mkdir(parents=True, exist_ok=True)
    return {
        **own,
        "HOME": str(home),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TERM": "xterm-256color",
        "TMPDIR": str(work / "scratch"),
        "RETROBIOS_OS": variant.os_type,
        "RETROBIOS_BASE_URL": base_url,
        # What the downloaded bootstrap sets: commands given back are
        # the one-line command, not a path to a temporary copy.
        "RETROBIOS_BOOTSTRAP": "sh",
        "RETROBIOS_DEMO_BOOTSTRAP": str(REPO_ROOT / "install.sh"),
    }
