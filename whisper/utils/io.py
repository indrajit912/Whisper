import platform
import getpass
from pathlib import Path
import click
from whisper.utils.crypto import sha256_hash
from whisper.config import (
    FLASHDRIVE_SECRET_DIR_NAME, 
    PASSPHRASE_HASH_FILE, 
    FLASHDRIVE_PASSPHRASE_FILENAME,
    RSA_PRIVATE_KEY_FILE
)

def get_flashdrive_with_secret_dir(secret_dir_name=FLASHDRIVE_SECRET_DIR_NAME):
    """
    Scan mounted volumes to find a flashdrive containing the specified secret directory.

    Args:
        secret_dir_name (str): Name of the secret directory to look for.

    Returns:
        Path or None: Path to the matched flashdrive as a Path object, or None if not found.
    """
    system = platform.system()
    mount_points = []

    if system == 'Linux':
        username = getpass.getuser()
        mount_points = [
            Path(f'/media/{username}'),
            Path(f'/run/media/{username}')
        ]
    elif system == 'Darwin':
        mount_points = [Path('/Volumes')]
    elif system == 'Windows':
        from string import ascii_uppercase
        mount_points = [Path(f"{letter}:\\") for letter in ascii_uppercase]
    else:
        raise NotImplementedError(f"Unsupported platform: {system}")

    for base_path in mount_points:
        if not base_path.exists():
            continue

        try:
            entries = base_path.iterdir() if base_path.is_dir() else [base_path]
        except PermissionError:
            continue  # skip paths we can't access

        for entry in entries:
            if entry.is_dir():
                secret_path = entry / secret_dir_name
                if secret_path.is_dir():
                    return entry.resolve()  # return as Path

    return None

def _verify_passphrase_hash(passphrase: str, hash_file: Path):
    """
    Verifies that the SHA-256 hash of the given passphrase matches
    the stored hash in the specified hash file.

    Args:
        passphrase (str): The passphrase to verify.
        hash_file (Path): Path to the file containing the stored hash.

    Returns:
        bool: True if hash matches, False otherwise.
    """
    if not hash_file.exists():
        # Save the hash
        PASSPHRASE_HASH_FILE.write_text(sha256_hash(passphrase), encoding='utf-8')
        click.secho("[Info] Password hash saved for future use.\n", fg="blue")
        return True

    stored_hash = hash_file.read_text(encoding='utf-8').strip()
    computed_hash = sha256_hash(passphrase)

    return computed_hash == stored_hash


def _load_passphrase_from_flashdrive():
    secret_dir_name = FLASHDRIVE_SECRET_DIR_NAME
    passphrase_file_name = FLASHDRIVE_PASSPHRASE_FILENAME
    flashdrive_path = get_flashdrive_with_secret_dir()
    
    passphrase = secret_dir = passphrase_file = None

    if flashdrive_path:
        secret_dir = Path(flashdrive_path) / secret_dir_name
        passphrase_file = secret_dir / passphrase_file_name

        if passphrase_file.is_file():
            try:
                passphrase = passphrase_file.read_text(encoding='utf-8').strip()

                # Check whether this is valid passphrase or not
                if not _verify_passphrase_hash(passphrase, PASSPHRASE_HASH_FILE):
                    passphrase = None
                else:
                    click.secho("[Info] Passphrase loaded from flashdrive.\n", fg="blue")
            except Exception as e:
                click.secho(f"[Warning] Could not read passphrase file: {e}", fg="yellow", bold=True)
    
    return passphrase, flashdrive_path, secret_dir, passphrase_file


def _cleanup_key(key_path):
    if key_path is None:
        # Try to remove the default rsa_private_key.pem file
        RSA_PRIVATE_KEY_FILE.unlink(missing_ok=True)
        click.secho("[✓] Decrypted private key removed from disk.", fg="green", bold=True)
        return
    try:
        key_path.unlink()
        click.secho("[✓] Decrypted private key removed from disk.", fg="green", bold=True)
    except Exception as e:
        click.secho(f"[!] Warning: Failed to delete decrypted private key: {e}", fg="yellow", bold=True)
