"""Which RetroPie scriptmodules a platform enables, as RetroPie-Setup decides."""

from __future__ import annotations

from collections.abc import Iterable

# scriptmodules/system.sh: set_platform_defaults starts each platform's flags
# with its own name and getconf LONG_BIT (`x86_64`, `64bit`), then the cpu_*
# and platform_* functions add theirs. A PC takes platform_native, which adds
# the x86 flag on i686 and x86_64. The video stacks are those of the images
# RetroPie ships: videocore and dispmanx on rpi1-3, kms with fkms dispmanx on
# rpi4 (buster), kms on rpi5.
PLATFORM_FLAGS: dict[str, set[str]] = {
    "rpi1": {"rpi1", "32bit", "arm", "armv6", "rpi", "gles", "videocore", "dispmanx"},
    "rpi2": {"rpi2", "32bit", "arm", "armv7", "neon", "rpi", "gles", "videocore",
             "dispmanx"},
    "rpi3": {"rpi3", "32bit", "arm", "armv8", "neon", "rpi", "gles", "videocore",
             "dispmanx"},
    "rpi4": {"rpi4", "32bit", "arm", "armv8", "neon", "rpi", "gles", "gles3", "gles31",
             "mesa", "kms", "dispmanx"},
    "rpi5": {"rpi5", "32bit", "arm", "armv8", "neon", "rpi", "gles", "gles3", "gles31",
             "mesa", "kms"},
    "x86": {"i686", "x86", "32bit", "gl", "vulkan", "x11"},
    "x86_64": {"x86_64", "x86", "64bit", "gl", "vulkan", "x11"},
}


def module_enabled(flags: Iterable[str], platform_flags: set[str]) -> bool:
    """Whether RetroPie enables a module whose rp_module_flags are `flags`.

    Port of rp_registerModule (scriptmodules/packages.sh): flags are read in
    order from an enabled default; !all disables, a flag the platform has
    enables, !flag disables when the platform has it. A flag the platform
    does not know (sdl1, nodistcc) changes nothing, and a comparison against
    the build host (:$__gcc_version:-lt:7) cannot be decided here, so it
    leaves the module as it was.
    """
    enabled = True
    for flag in flags:
        if flag == "!all":
            enabled = False
        elif flag in platform_flags:
            enabled = True
        elif flag.startswith("!") and flag[1:] in platform_flags:
            enabled = False
    return enabled
