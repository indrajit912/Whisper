import sys
import subprocess
import getpass
from pathlib import Path

import click

from whisper.utils.crypto import decrypt_file_with_private_key, decrypt_with_private_key, sha256_hash
from whisper.utils.io import (
    get_flashdrive_with_secret_dir,
    _verify_passphrase_hash,
    _load_passphrase_from_flashdrive
)
from whisper.utils.prompts import _prompt_passphrase_with_confirmation
from whisper.config import (
    PASSPHRASE_HASH_FILE,
    DEFAULT_KEYS_DIR,
    FLASHDRIVE_SECRET_DIR_NAME,
    FLASHDRIVE_PASSPHRASE_FILENAME
)

def _prompt_passphrase_from_user_and_get_keypath(encrypted_key_path):
    """
    Attempt to load the passphrase for Whisper messages.
    
    If a USB drive named 'Indrajit' is connected and contains the file
    `.secret_keys/.whisper_passphrase`, load the passphrase from it.
    Otherwise, prompt the user to enter the passphrase manually.

    If the flashdrive is connected but the passphrase is not saved,
    offer to save it securely for future use.

    Parameters:
        encrypted_key_path (str or Path): Path to the encrypted private key.

    Returns:
        Path: Path to the decrypted private key.

    Exits the program if decryption fails.
    """
    print("-" * 30 + " Decryption " + "-" * 30)

    passphrase, flashdrive_path, secret_dir, passphrase_file = _load_passphrase_from_flashdrive()

    if not passphrase:
        # Either there is no saved passphrase found at the flashdrive or the passphrase is invalid.
        click.secho(
            "Warning: Either there is no saved passphrase found at the flashdrive or the passphrase is invalid.",
            fg="yellow",
            bold=True
        )
        
        # Prompt user for passphrase
        passphrase = getpass.getpass("\nEnter passphrase to decrypt the private key: ").strip()

        # Check the passphrase hash
        if not _verify_passphrase_hash(passphrase=passphrase, hash_file=PASSPHRASE_HASH_FILE):
            click.secho("[Error] Wrong passphrase!", fg="red", bold=True)
            sys.exit(1)

        # Offer to save to flashdrive if connected
        if flashdrive_path:
            save_choice = input("Do you want to save this passphrase to your flashdrive for future use? [y/N]: ").strip().lower()
            if save_choice == 'y':
                try:
                    secret_dir.mkdir(parents=True, exist_ok=True)
                    passphrase_file.write_text(passphrase, encoding='utf-8')
                    print(f"[Info] Passphrase saved to: {passphrase_file}\n\n")
                except Exception as e:
                    print(f"[Error] Failed to save passphrase to flashdrive: {e}")

    decrypted_key_path = _decrypt_private_key_with_gpg(encrypted_key_path, passphrase)

    if not decrypted_key_path:
        print("\n[Error] Failed to decrypt the private key.")
        sys.exit(1)

    return decrypted_key_path

def _get_encrypted_key_path():
    if not DEFAULT_KEYS_DIR.exists():
        DEFAULT_KEYS_DIR.mkdir()
    
    encrypted_key_path = DEFAULT_KEYS_DIR / "rsa_private_key.pem.gpg"
    
    if not encrypted_key_path.exists():
        print(f"\n[Info] No encrypted RSA key found at: {encrypted_key_path}")
        
        private_key_path_input = input("Enter the path to your RSA private key (.pem): ").strip()
        private_key_path = Path(private_key_path_input).expanduser()
        
        if not private_key_path.exists():
            print(f"[Error] Private key file not found at: {private_key_path}")
            sys.exit(1)
        
        passphrase = _prompt_passphrase_with_confirmation("Enter passphrase to encrypt the private key", "Confirm passphrase")
        
        encrypted_key_path = _encrypt_private_key_with_gpg(private_key_path, passphrase)
        
        if not encrypted_key_path:
            print("[Error] Encryption failed.")
            sys.exit(1)
        
        print(f"\nPrivate key has been encrypted and stored at: {encrypted_key_path}")
        print("Remember this passphrase for future use!")

    return encrypted_key_path


def _encrypt_private_key_with_gpg(private_key_path, passphrase):
    """
    Encrypts the given RSA private key file using GPG with AES256 encryption.

    Args:
        private_key_path (Path): Path to the RSA private key file.
        passphrase (str): Passphrase used for encryption.

    Returns:
        Path or None: Path to the encrypted key file if successful, else None.
    """
    encrypted_key_path = Path.home() / ".keys" / "rsa_private_key.pem.gpg"
    
    try:
        subprocess.run(
            [
                'gpg', '--batch', '--yes', '--passphrase', passphrase,
                '--symmetric', '--cipher-algo', 'AES256',
                '--output', str(encrypted_key_path), str(private_key_path)
            ],
            check=True
        )
        print(f"Private key encrypted and saved to: {encrypted_key_path}")

        # Save the passphrase hash
        PASSPHRASE_HASH_FILE.write_text(sha256_hash(passphrase), encoding='utf-8')

        # Save the passphrase to the flashdrive if connected
        secret_dir_name = FLASHDRIVE_SECRET_DIR_NAME
        passphrase_file_name = FLASHDRIVE_PASSPHRASE_FILENAME
        flashdrive_path = get_flashdrive_with_secret_dir()

        if flashdrive_path:
            secret_dir = Path(flashdrive_path) / secret_dir_name
            passphrase_file = secret_dir / passphrase_file_name

            passphrase_file.write_text(passphrase, encoding='utf-8')
            print(f"[Info] Passphrase saved to: {passphrase_file}\n\n")


        return encrypted_key_path
    except subprocess.CalledProcessError as e:
        print(f"[Error] Failed to encrypt private key: {e}")
        return None

def _decrypt_private_key_with_gpg(encrypted_key_path, passphrase):
    """
    Decrypts the given encrypted RSA private key file using GPG.

    Before decryption, verifies that the SHA-256 hash of the given passphrase
    matches the one stored in PASSPHRASE_HASH_FILE. If not, exits with an error.

    Args:
        encrypted_key_path (Path): Path to the encrypted private key file (.gpg).
        passphrase (str): Passphrase used for decryption.

    Returns:
        Path or None: Path to the decrypted private key file if successful, else None.
    """
    # --- Step 1: Verify passphrase hash ---
    if not _verify_passphrase_hash(passphrase, PASSPHRASE_HASH_FILE):
        print("[Error] Passphrase verification failed: hash mismatch.")
        sys.exit(1)

    # --- Step 2: Decrypt using GPG ---
    decrypted_key_path = encrypted_key_path.with_suffix('')
    
    try:
        subprocess.run(
            [
                'gpg', '--batch', '--yes', '--passphrase', passphrase,
                '--output', str(decrypted_key_path), '--decrypt', str(encrypted_key_path)
            ],
            check=True
        )
        print(f"Private key decrypted and saved to: {decrypted_key_path}")
        return decrypted_key_path
    except subprocess.CalledProcessError as e:
        print(f"Failed to decrypt private key with GPG: {e}")
        return None

def decrypt_message(encrypted_key_path):
    print("\nPaste the content of the message.json file (end with an empty line):")
    b64_blob = ""
    while True:
        line = input()
        if not line.strip():
            break
        b64_blob += line.strip()

    try:
        # Get the key_path
        key_path = _prompt_passphrase_from_user_and_get_keypath(encrypted_key_path)
        decrypted_text = decrypt_with_private_key(str(key_path), b64_blob)
        print("\n\nDecrypted message:")
        print(decrypted_text)
        return key_path

    except Exception as e:
        print(f"\n[Decryption Failed] {e}")

def decrypt_attachment(encrypted_key_path, encrypted_file_path=None):
    try:
        # Get the key_path
        key_path = _prompt_passphrase_from_user_and_get_keypath(encrypted_key_path)

        decrypted_file_path = decrypt_file_with_private_key(
            private_key_path=str(key_path), 
            encrypted_file_path=encrypted_file_path,
            output_dir=encrypted_file_path.parent
        )
        print(f"\nDecrypted file saved as: {decrypted_file_path}")

        return key_path

    except Exception as e:
        print(f"\n[Decryption Failed] {e}")
