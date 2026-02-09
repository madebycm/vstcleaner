# vstcleaner

Removes duplicate macOS audio plugin formats when a VST3 version exists. Moves duplicates to `/tmp` instead of deleting them, so nothing is lost.

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

### Always kept

- **VST3** — never removed, always the preferred format
- Any plugin that does **not** have a VST3 counterpart

## Requirements

- macOS
- Python 3

## Usage

```bash
# Remove all duplicate formats (VST2, AU, AAX, CLAP)
python3 vst_cleaner.py

# Keep AU/Components, only remove VST2, AAX, and CLAP duplicates
python3 vst_cleaner.py skipau
```

Sudo access is requested automatically when needed (system-level plugins require root). The password is cached in an encrypted `.cache` file tied to your machine for convenience on repeat runs.

## How It Works

1. Collects all VST3 plugin names from system and user VST3 directories
2. Scans VST2, AU, AAX, and CLAP directories (recursively, including subdirectories)
3. Matches plugins by base name (case-insensitive) against the VST3 list
4. Moves matched duplicates to `/tmp/removed_plugins/<format>/`
5. Prints a summary of what was moved and how much space was recovered

## Recovery

Moved plugins land in `/tmp/removed_plugins/` (organized by format). To restore a plugin, move it back to its original directory. Note that `/tmp` is cleared on reboot, so recover before restarting if needed.

## License

MIT
