# vstcleaner

Removes duplicate macOS audio plugin formats when a VST3 version exists, strips redundant Waves mono sub-components, and removes non-production Waves plugins. Moves everything to `/tmp` instead of deleting, so nothing is lost.

## What It Does

Many plugin vendors install multiple formats (VST2, AU, AAX, CLAP) alongside VST3. Most DAWs prefer VST3, making the others clutter your plugin lists and waste disk space.

vstcleaner scans your system and user plugin directories, finds plugins that have a VST3 equivalent, and moves the redundant formats to `/tmp/removed_plugins/`.

### Formats removed (when a VST3 match exists)

| Format | System path | User path |
|---|---|---|
| VST2 (`.vst`) | `/Library/Audio/Plug-Ins/VST` | `~/Library/Audio/Plug-Ins/VST` |
| AU (`.component`) | `/Library/Audio/Plug-Ins/Components` | `~/Library/Audio/Plug-Ins/Components` |
| AAX (`.aaxplugin`) | `/Library/Application Support/Avid/Audio/Plug-Ins` | `~/Library/Application Support/Avid/Audio/Plug-Ins` |
| CLAP (`.clap`) | `/Library/Audio/Plug-Ins/CLAP` | `~/Library/Audio/Plug-Ins/CLAP` |

### Waves-specific handling

- **Old WaveShell versions** — Removes superseded WaveShell containers (e.g. 16.6 when 16.7 exists)
- **WaveShell AU format dupes** — The name-based matcher can't catch these (`WaveShell1-AU` vs `WaveShell1-VST3`), so they're hardcoded
- **Non-production plugins** — Removes 22 Waves plugins not relevant for stereo music production (surround/immersive, live sound, broadcast, networking, test utilities). See `specifics/waves.txt` for the full list and rationale.
- **Mono sub-component stripping** — Waves plugins register both mono `(m)` and stereo `(s)` variants inside the WaveShell. When a stereo version exists, the mono is redundant clutter. vstcleaner edits the ProcessXML files in each Waves plugin bundle to remove the mono definitions (177 mono entries across 134 plugins).

### Always kept

- **VST3** — never removed, always the preferred format
- Any plugin that does **not** have a VST3 counterpart
- Waves plugins that are mono-only (no stereo version available)

## Requirements

- macOS
- Python 3

## Usage

```bash
# Full clean — remove format dupes, non-production Waves plugins, strip mono
python3 vst_cleaner.py

# Keep AU/Components
python3 vst_cleaner.py skipau

# Skip Waves mono stripping
python3 vst_cleaner.py skipwavesmono
```

Sudo access is requested automatically when needed (system-level plugins require root). The password is cached in an encrypted `.cache` file tied to your machine for convenience on repeat runs.

## How It Works

1. Collects all VST3 plugin names from system and user VST3 directories
2. Scans VST2, AU, AAX, and CLAP directories (recursively, including subdirectories)
3. Matches plugins by base name (case-insensitive) against the VST3 list
4. Moves matched duplicates to `/tmp/removed_plugins/<format>/`
5. Removes old/duplicate Waves WaveShell containers
6. Moves non-production Waves plugin bundles (surround, broadcast, live, etc.)
7. Strips mono `<SubComponent>` entries from Waves ProcessXML when stereo exists
8. Prints a summary of what was moved/stripped and how much space was recovered

## Recovery

Moved plugins land in `/tmp/removed_plugins/` (organized by category). Move them back to restore. Note that `/tmp` is cleared on reboot.

Waves mono stripping modifies ProcessXML files in-place. Waves updates will restore the originals, so re-run the script after updating Waves.

## Vendor-specific docs

- [`specifics/waves.txt`](specifics/waves.txt) — Waves V16 handling details, non-production list, mono stripping internals

## License

MIT
