"""FabFilter version cleanup — remove older plugin versions when newer ones exist.

Scans all plugin directories for FabFilter bundles and flags old versions
for removal when a newer version of the same plugin is installed.
E.g. Pro-Q 2 is removed if Pro-Q 3 is found (across all formats).
"""

from pathlib import Path

# Each sub-list is oldest → newest.  Only the highest installed version is kept;
# everything older is flagged for removal across all formats.
FABFILTER_FAMILIES: list[list[str]] = [
    ["FabFilter Pro-Q", "FabFilter Pro-Q 2", "FabFilter Pro-Q 3", "FabFilter Pro-Q 4"],
    ["FabFilter Pro-C", "FabFilter Pro-C 2", "FabFilter Pro-C 3"],
    ["FabFilter Pro-L", "FabFilter Pro-L 2"],
    ["FabFilter Pro-R", "FabFilter Pro-R 2"],
    ["FabFilter Saturn", "FabFilter Saturn 2"],
    ["FabFilter Timeless", "FabFilter Timeless 2", "FabFilter Timeless 3"],
    ["FabFilter Volcano", "FabFilter Volcano 2", "FabFilter Volcano 3"],
    ["FabFilter Twin", "FabFilter Twin 2", "FabFilter Twin 3"],
]

_PLUGIN_SUFFIXES = {".vst3", ".vst", ".component", ".aaxplugin", ".clap"}


def find_obsolete(plugin_dirs: list[Path]) -> list[Path]:
    """Return paths of FabFilter plugins superseded by a newer installed version.

    Args:
        plugin_dirs: All plugin directories to scan (system + user, all formats).

    Returns:
        Paths to remove (older versions only).
    """
    stem_to_paths: dict[str, list[Path]] = {}

    for folder in plugin_dirs:
        if not folder.is_dir():
            continue
        for item in folder.iterdir():
            if item.suffix.lower() in _PLUGIN_SUFFIXES:
                stem_to_paths.setdefault(item.stem.lower(), []).append(item)

    to_remove: list[Path] = []

    for family in FABFILTER_FAMILIES:
        highest = -1
        for idx, name in enumerate(family):
            if name.lower() in stem_to_paths:
                highest = idx

        if highest <= 0:
            continue

        for idx in range(highest):
            key = family[idx].lower()
            if key in stem_to_paths:
                to_remove.extend(stem_to_paths[key])

    return to_remove
