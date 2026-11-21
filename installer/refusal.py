"""A refusal that ends the run, raised where it is decided and reported once by the command."""
from __future__ import annotations

import sys

from installer.events import EVENTS


class Refusal(SystemExit):
    """The run refused, with the error event a script reads and the lines a
    person reads. Each site printed its lines and chose on its own whether
    --events got the reason, and several did not: a script learned code 1
    and nothing else. message is the event's, by default the lines joined
    without their leading "Error: "."""

    def __init__(self, stage: str, reason: str, platform: str, *lines: str,
                 code: int = 1, message: str | None = None) -> None:
        super().__init__(code)
        self.stage, self.reason, self.platform = stage, reason, platform
        self.lines = lines
        if message is None:
            message = " ".join(line.strip() for line in lines)
            if message.startswith("Error: "):
                message = message[len("Error: "):]
        self.message = message
        self.reported = False

    def report(self) -> None:
        """The error event, then the lines on stderr, once."""
        if self.reported:
            return
        self.reported = True
        EVENTS.emit("error", stage=self.stage, reason=self.reason, platform=self.platform,
                    message=self.message)
        for line in self.lines:
            print(line, file=sys.stderr)
