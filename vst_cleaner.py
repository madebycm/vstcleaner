#!/usr/bin/env python3
"""
Move duplicate plugin formats to /tmp (including nested subdirectories).
Defaults to /tmp/removed_plugins and falls back to /tmp/removed_plugins_<user>.

Removes (match by bundle base name, case-insensitive):
  - Non-VST3 bundles with a matching VST3 name (VST2, AAX, CLAP)
  - AU (.component) by default (skip with 'skipau' argument)

Keeps:
  - Any format that doesn't have a VST3 duplicate
  - VST3 bundles (always preferred)
  - AU plugins (only when 'skipau' is specified)
"""

import base64
import getpass
import hashlib
import hmac
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

CACHE_FILE = Path(__file__).resolve().parent / ".cache"
CACHE_VERSION = 1
PBKDF2_ITERATIONS = 200_000
_CACHED_PASSWORD: str | None = None
_CACHE_LOOKED_UP = False
_KEY_MATERIAL: bytes | None = None


def _int_env(name: str, default: int) -> int:
    """Parse integer from environment variable."""
    value = os.environ.get(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_key_material() -> bytes:
    """Derive stable machine-specific key material."""
    global _KEY_MATERIAL
    if _KEY_MATERIAL is None:
        parts = [
            "vst_cleaner",
            getpass.getuser(),
            str(Path.home()),
            platform.node(),
            hex(uuid.getnode()),
            sys.platform,
        ]
        _KEY_MATERIAL = "|".join(parts).encode("utf-8")
    return _KEY_MATERIAL


def _derive_master_key(salt: bytes) -> bytes:
    """Derive an encryption key from machine-specific material and salt."""
    return hashlib.pbkdf2_hmac("sha256", _get_key_material(), salt, PBKDF2_ITERATIONS, dklen=32)


def _hkdf_expand(key: bytes, info: bytes, length: int) -> bytes:
    """Minimal HKDF-Expand for fixed-length keys."""
    output = b""
    counter = 1
    prev = b""
    while len(output) < length:
        prev = hmac.new(key, prev + info + bytes([counter]), hashlib.sha256).digest()
        output += prev
        counter += 1
    return output[:length]


def _split_keys(master_key: bytes) -> tuple[bytes, bytes]:
    """Split master key into encryption and MAC keys."""
    enc_key = _hkdf_expand(master_key, b"enc", 32)
    mac_key = _hkdf_expand(master_key, b"mac", 32)
    return enc_key, mac_key


def _xor_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """XOR data with a keyed HMAC stream."""
    output = bytearray(len(data))
    counter = 0
    offset = 0
    while offset < len(data):
        counter_bytes = counter.to_bytes(8, "big")
        block = hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest()
        block_len = min(len(block), len(data) - offset)
        for idx in range(block_len):
            output[offset + idx] = data[offset + idx] ^ block[idx]
        offset += block_len
        counter += 1
    return bytes(output)


def encrypt_password(password: str) -> dict[str, str]:
    """Encrypt password into a JSON-serializable payload."""
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    master_key = _derive_master_key(salt)
    enc_key, mac_key = _split_keys(master_key)
    ciphertext = _xor_stream(password.encode("utf-8"), enc_key, nonce)
    mac = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return {
        "v": str(CACHE_VERSION),
        "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        "mac": base64.urlsafe_b64encode(mac).decode("ascii"),
    }


def decrypt_password(payload: dict[str, str]) -> str | None:
    """Decrypt password payload or return None on failure."""
    try:
        if str(payload.get("v")) != str(CACHE_VERSION):
            return None
        salt = base64.urlsafe_b64decode(payload["salt"])
        nonce = base64.urlsafe_b64decode(payload["nonce"])
        ciphertext = base64.urlsafe_b64decode(payload["ciphertext"])
        mac = base64.urlsafe_b64decode(payload["mac"])
    except (KeyError, ValueError, base64.binascii.Error):
        return None

    master_key = _derive_master_key(salt)
    enc_key, mac_key = _split_keys(master_key)
    expected_mac = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_mac, mac):
        return None
    plaintext = _xor_stream(ciphertext, enc_key, nonce)
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError:
        return None


def get_cached_password() -> str | None:
    """Retrieve password from encrypted cache file."""
    if not CACHE_FILE.exists():
        return None
    try:
        payload = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    password = decrypt_password(payload)
    if not password:
        try:
            CACHE_FILE.unlink()
        except OSError:
            pass
    return password


def save_password_to_cache(password: str) -> bool:
    """Save password to encrypted cache file."""
    payload = encrypt_password(password)
    try:
        CACHE_FILE.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(CACHE_FILE, 0o600)
        return True
    except OSError:
        return False


def run_with_sudo(
    cmd: list[str], password: str, timeout: int | None = None
) -> subprocess.CompletedProcess:
    """Run a command with sudo, passing password via stdin."""
    proc = subprocess.Popen(
        ["sudo", "-S"] + cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = proc.communicate(
            input=(password + "\n").encode(), timeout=timeout
        )
        return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        timeout_note = f"Command timed out after {timeout} seconds.".encode("utf-8")
        if stderr:
            stderr = stderr + b"\n" + timeout_note
        else:
            stderr = timeout_note
        return subprocess.CompletedProcess(cmd, 124, stdout, stderr)


def verify_sudo_password(password: str) -> bool:
    """Verify the password works with sudo."""
    # Kill any cached sudo credentials first to ensure we test the actual password
    subprocess.run(["sudo", "-k"], capture_output=True)
    result = run_with_sudo(["-v"], password)
    return result.returncode == 0


def cache_password(password: str) -> None:
    """Cache the password in memory for this run."""
    global _CACHED_PASSWORD, _CACHE_LOOKED_UP
    _CACHED_PASSWORD = password
    _CACHE_LOOKED_UP = True


def clear_cached_password(remove_file: bool = False) -> None:
    """Clear cached password, optionally removing the cache file."""
    global _CACHED_PASSWORD, _CACHE_LOOKED_UP
    _CACHED_PASSWORD = None
    _CACHE_LOOKED_UP = True
    if remove_file:
        try:
            CACHE_FILE.unlink()
        except OSError:
            pass


def prompt_for_password() -> str:
    """Prompt for sudo password and save it to the encrypted cache."""
    print("Root password required (will be stored encrypted in .cache)")
    for _ in range(3):
        password = getpass.getpass("Password: ")
        if verify_sudo_password(password):
            if save_password_to_cache(password):
                print("Password cached for future use.\n")
            cache_password(password)
            return password
        print("Incorrect password, try again.")

    raise SystemExit("Failed to authenticate after 3 attempts.")


def can_prompt_for_password() -> bool:
    """Check whether we can prompt for a password."""
    return sys.stdin.isatty() and sys.stderr.isatty()


def get_sudo_password() -> str | None:
    """Get sudo password from cache or prompt if missing."""
    global _CACHED_PASSWORD, _CACHE_LOOKED_UP
    if _CACHED_PASSWORD:
        return _CACHED_PASSWORD
    if not _CACHE_LOOKED_UP:
        _CACHED_PASSWORD = get_cached_password()
        _CACHE_LOOKED_UP = True
    if _CACHED_PASSWORD:
        return _CACHED_PASSWORD
    if not can_prompt_for_password():
        return None
    return prompt_for_password()


def is_auth_failure(result: subprocess.CompletedProcess) -> bool:
    """Check whether sudo failed due to authentication."""
    if result.returncode == 0:
        return False
    output = b""
    if result.stderr:
        output += result.stderr
    if result.stdout:
        output += result.stdout
    message = output.decode(errors="ignore").lower()
    return any(
        token in message
        for token in (
            "sorry, try again",
            "incorrect password",
            "password is required",
            "no password was provided",
            "authentication failure",
        )
    )


def run_with_sudo_retry(
    cmd: list[str], timeout: int | None = None
) -> tuple[bool, str | None]:
    """Run sudo command, prompting again if cached password is invalid."""
    password = get_sudo_password()
    if not password:
        return False, "sudo password unavailable"
    result = run_with_sudo(cmd, password, timeout=timeout)
    if result.returncode == 0:
        return True, None
    if is_auth_failure(result):
        clear_cached_password(remove_file=True)
        password = get_sudo_password()
        if not password:
            return False, "sudo password unavailable"
        result = run_with_sudo(cmd, password, timeout=timeout)
    if result.returncode == 0:
        return True, None
    output = b""
    if result.stderr:
        output += result.stderr
    if result.stdout:
        output += result.stdout
    message = output.decode(errors="ignore").strip()
    return False, message or "sudo failed"

# System-level plugin directories
SYSTEM_VST_PATH = Path("/Library/Audio/Plug-Ins/VST")
SYSTEM_COMPONENTS_PATH = Path("/Library/Audio/Plug-Ins/Components")
SYSTEM_AAX_PATH = Path("/Library/Application Support/Avid/Audio/Plug-Ins")
SYSTEM_CLAP_PATH = Path("/Library/Audio/Plug-Ins/CLAP")

# User-level plugin directories
USER_VST_PATH = Path.home() / "Library/Audio/Plug-Ins/VST"
USER_COMPONENTS_PATH = Path.home() / "Library/Audio/Plug-Ins/Components"
USER_AAX_PATH = Path.home() / "Library/Application Support/Avid/Audio/Plug-Ins"
USER_CLAP_PATH = Path.home() / "Library/Audio/Plug-Ins/CLAP"

# VST3 directories (for duplicate matching)
SYSTEM_VST3_PATH = Path("/Library/Audio/Plug-Ins/VST3")
USER_VST3_PATH = Path.home() / "Library/Audio/Plug-Ins/VST3"

DEFAULT_TMP_PATH = Path("/tmp/removed_plugins")

def list_bundles(folder: Path, suffix: str) -> list[Path]:
    """List bundle paths in folder matching suffix (case-insensitive, recursive)."""
    if not folder.exists() or not folder.is_dir():
        return []
    suffix = suffix.lower()
    matches: list[Path] = []
    for root, dirs, files in os.walk(folder):
        root_path = Path(root)
        keep_dirs = []
        for dirname in dirs:
            path = root_path / dirname
            if path.suffix.lower() == suffix:
                matches.append(path)
            else:
                keep_dirs.append(dirname)
        dirs[:] = keep_dirs
        for filename in files:
            if filename.lower().endswith(suffix):
                matches.append(root_path / filename)
    return matches


def plugin_base_name(path: Path) -> str:
    """Normalize plugin name for de-duping."""
    return path.stem.lower()


def get_vst3_names(folder: Path) -> set[str]:
    """Collect VST3 base names from folder."""
    return {plugin_base_name(item) for item in list_bundles(folder, ".vst3")}


def is_writable_dir(path: Path) -> bool:
    """Check whether directory is writable and searchable."""
    return os.access(path, os.W_OK | os.X_OK)


def can_create_dir(path: Path) -> bool:
    """Check whether directory exists and is writable, or can be created."""
    if path.exists():
        return is_writable_dir(path)
    parent = path.parent
    return parent.exists() and is_writable_dir(parent)


def resolve_tmp_base(base: Path) -> Path:
    """Pick a writable base path for removed plugins."""
    user = getpass.getuser()
    candidates = [
        base,
        Path(f"{base}_{user}"),
        Path(f"{base}_{user}_{os.getpid()}"),
    ]
    for candidate in candidates:
        if can_create_dir(candidate):
            return candidate
    return base


def get_size(path: Path) -> int:
    """Get total size of a file or directory in bytes."""
    if path.is_file() or path.is_symlink():
        return path.stat().st_size
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                pass
    return total


def human_size(num_bytes: int) -> str:
    """Convert bytes to human readable format."""
    for unit in ["B", "KB", "MB", "GB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"


def unique_dest_path(dest_dir: Path, src_name: str) -> Path:
    """Create a unique destination path to avoid collisions."""
    dest = dest_dir / src_name
    if not dest.exists():
        return dest
    stem = Path(src_name).stem
    suffix = Path(src_name).suffix
    for idx in range(1, 1000):
        candidate = dest_dir / f"{stem}__{idx}{suffix}"
        if not candidate.exists():
            return candidate
    return dest_dir / f"{stem}__{os.getpid()}{suffix}"


def move_path(path: Path, dest_dir: Path) -> tuple[bool, str | None]:
    """Move a file or directory to dest_dir, using sudo if needed."""
    dest = unique_dest_path(dest_dir, path.name)
    try:
        shutil.move(str(path), str(dest))
        return True, None
    except PermissionError as exc:
        ok, message = run_with_sudo_retry(["mv", str(path), str(dest)])
        return ok, message or str(exc)
    except OSError as exc:
        return False, str(exc)


def ensure_dir(dest_dir: Path) -> bool:
    """Create directory, using sudo if needed."""
    if dest_dir.exists():
        return True
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        return True
    except PermissionError:
        ok, _ = run_with_sudo_retry(["mkdir", "-p", str(dest_dir)])
        return ok

def remove_duplicates_by_vst3(
    folder: Path,
    dest_dir: Path,
    suffix: str,
    vst3_names: set[str],
    failures: list[str] | None = None,
) -> tuple[list[str], int]:
    """Move bundles whose base name matches a VST3 bundle."""
    moved = []
    bytes_moved = 0

    if not vst3_names or not folder.exists() or not folder.is_dir():
        return moved, bytes_moved

    if not ensure_dir(dest_dir):
        return moved, bytes_moved

    for item in list_bundles(folder, suffix):
        if plugin_base_name(item) not in vst3_names:
            continue
        size = get_size(item)
        ok, error = move_path(item, dest_dir)
        if ok:
            moved.append(item.name)
            bytes_moved += size
        elif failures is not None:
            failures.append(f"{item} -> {error}")

    return moved, bytes_moved


def main():
    args = {arg.lower() for arg in sys.argv[1:]}
    remove_au = "skipau" not in args

    tmp_base = resolve_tmp_base(DEFAULT_TMP_PATH)
    if tmp_base != DEFAULT_TMP_PATH:
        print(f"Using temp path {tmp_base} (default not writable).")

    failures: list[str] = []
    results = {}

    # Collect VST3 names for duplicate matching
    sys_vst3_names = get_vst3_names(SYSTEM_VST3_PATH)
    user_vst3_names = get_vst3_names(USER_VST3_PATH)
    all_vst3_names = sys_vst3_names | user_vst3_names

    # System-level plugin duplicates
    sys_vst_moved, sys_vst_bytes = remove_duplicates_by_vst3(
        SYSTEM_VST_PATH,
        tmp_base / "VST",
        ".vst",
        all_vst3_names,
        failures,
    )
    if remove_au:
        sys_comp_moved, sys_comp_bytes = remove_duplicates_by_vst3(
            SYSTEM_COMPONENTS_PATH,
            tmp_base / "Components",
            ".component",
            all_vst3_names,
            failures,
        )
    else:
        sys_comp_moved, sys_comp_bytes = [], 0
    sys_aax_moved, sys_aax_bytes = remove_duplicates_by_vst3(
        SYSTEM_AAX_PATH,
        tmp_base / "AAX",
        ".aaxplugin",
        all_vst3_names,
        failures,
    )
    sys_clap_moved, sys_clap_bytes = remove_duplicates_by_vst3(
        SYSTEM_CLAP_PATH,
        tmp_base / "CLAP",
        ".clap",
        all_vst3_names,
        failures,
    )

    # User-level plugin duplicates
    user_vst_moved, user_vst_bytes = remove_duplicates_by_vst3(
        USER_VST_PATH,
        tmp_base / "VST_User",
        ".vst",
        all_vst3_names,
        failures,
    )
    if remove_au:
        user_comp_moved, user_comp_bytes = remove_duplicates_by_vst3(
            USER_COMPONENTS_PATH,
            tmp_base / "Components_User",
            ".component",
            all_vst3_names,
            failures,
        )
    else:
        user_comp_moved, user_comp_bytes = [], 0
    user_aax_moved, user_aax_bytes = remove_duplicates_by_vst3(
        USER_AAX_PATH,
        tmp_base / "AAX_User",
        ".aaxplugin",
        all_vst3_names,
        failures,
    )
    user_clap_moved, user_clap_bytes = remove_duplicates_by_vst3(
        USER_CLAP_PATH,
        tmp_base / "CLAP_User",
        ".clap",
        all_vst3_names,
        failures,
    )

    # Combine results
    results["VST2 dupes (System)"] = (sys_vst_moved, sys_vst_bytes)
    results["VST2 dupes (User)"] = (user_vst_moved, user_vst_bytes)
    results["Components dupes (System)"] = (sys_comp_moved, sys_comp_bytes)
    results["Components dupes (User)"] = (user_comp_moved, user_comp_bytes)
    results["AAX dupes (System)"] = (sys_aax_moved, sys_aax_bytes)
    results["AAX dupes (User)"] = (user_aax_moved, user_aax_bytes)
    results["CLAP dupes (System)"] = (sys_clap_moved, sys_clap_bytes)
    results["CLAP dupes (User)"] = (user_clap_moved, user_clap_bytes)

    total_bytes = sum(b for _, b in results.values())
    total_count = sum(len(m) for m, _ in results.values())

    if total_count == 0:
        if failures:
            print(f"Found duplicates but failed to move {len(failures)} item(s).")
            for entry in failures:
                print(f"  - {entry}")
        else:
            print("Nothing to move. No duplicate formats found.")
    else:
        print(f"Moved {total_count} plugin(s) to {tmp_base} ({human_size(total_bytes)})\n")

        for category, (moved, _) in results.items():
            if moved:
                print(f"{category} ({len(moved)}):")
                for name in moved:
                    print(f"  - {name}")
                print()

        if failures:
            print(f"Failed to move {len(failures)} item(s):")
            for entry in failures:
                print(f"  - {entry}")
            print()

    if not remove_au:
        print("Skipping AU/Components removal ('skipau' was specified).")



if __name__ == "__main__":
    main()
