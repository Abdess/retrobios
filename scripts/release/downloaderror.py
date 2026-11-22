"""The error a release download stops on, worded for the user who reads it."""

from __future__ import annotations


class DownloadError(ValueError):
    """A release download that cannot go on: its message is printed as is."""
