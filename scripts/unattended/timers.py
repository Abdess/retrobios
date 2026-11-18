"""The systemd user units that run the jobs on their schedule."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

from unattended.jobs import AutorunError, FAILED, Job


# Timers


def render_units(
    jobs: dict[str, Job], repo: Path, python: str, push: bool = False
) -> dict[str, str]:
    """systemd user units: one service template and a timer per scheduled job."""
    flags = " --push" if push else ""
    units = {
        "retrobios@.service": (
            "[Unit]\n"
            "Description=retrobios automation job %i\n"
            "\n"
            "[Service]\n"
            "Type=oneshot\n"
            f"WorkingDirectory={repo}\n"
            "Environment=RETROBIOS_AUTO=1\n"
            f"ExecStart={python} {repo / 'scripts' / 'autorun.py'} run %i{flags}\n"
            "TimeoutStartSec=6h\n"
            "Nice=10\n"
            "IOSchedulingClass=idle\n"
            "SuccessExitStatus=75\n"
        )
    }
    for name, job in sorted(jobs.items()):
        if not job.schedule:
            continue
        units[f"retrobios-{name}.timer"] = (
            "[Unit]\n"
            f"Description=retrobios automation: {name}\n"
            "\n"
            "[Timer]\n"
            f"OnCalendar={job.schedule}\n"
            "Persistent=true\n"
            f"Unit=retrobios@{name}.service\n"
            "\n"
            "[Install]\n"
            "WantedBy=timers.target\n"
        )
    return units


def install_timers(
    unit_dir: Path,
    units: dict[str, str],
    enable: bool,
    systemctl: Callable[[list[str]], int] | None = None,
) -> list[str]:
    """Write the units, and enable the timers only when asked."""
    unit_dir.mkdir(parents=True, exist_ok=True)
    for name, text in units.items():
        (unit_dir / name).write_text(text, encoding="utf-8")
    timers = sorted(n for n in units if n.endswith(".timer"))
    if enable:
        call = systemctl or (lambda args: subprocess.run(
            ["systemctl", "--user", *args], check=False).returncode)
        for args in (["daemon-reload"], ["enable", "--now", *timers]):
            if call(args) != 0:
                raise AutorunError(FAILED, f"systemctl --user {' '.join(args)} failed")
    return timers
