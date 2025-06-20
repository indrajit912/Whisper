import sys
import getpass
from .decrypt import _decrypt_private_key_with_gpg, _encrypt_private_key_with_gpg
from whisper.utils.io import _load_passphrase_from_flashdrive, _verify_passphrase_hash
from whisper.utils.prompts import _prompt_passphrase_with_confirmation
from whisper.config import DEFAULT_KEYS_DIR, PASSPHRASE_HASH_FILE

def change_passphrase():
    """
    Allows the user to change the passphrase protecting the encrypted private key.
    """
    encrypted_key_path = DEFAULT_KEYS_DIR / "rsa_private_key.pem.gpg"

    if not encrypted_key_path.exists():
        print(f"[Error] Encrypted private key not found at {encrypted_key_path}")
        sys.exit(1)

    # Step 1: Get current passphrase and verify hash
    # If the flashdrive is connected check it first
    current_passphrase, _, _, _ = _load_passphrase_from_flashdrive()
    
    if current_passphrase is None:
        current_passphrase = getpass.getpass("Enter current passphrase: ").strip()

    if not _verify_passphrase_hash(current_passphrase, PASSPHRASE_HASH_FILE):
        print("[Error] Incorrect current passphrase.")
        sys.exit(1)
    
    # Step 2: Prompt for new passphrase
    new_passphrase = _prompt_passphrase_with_confirmation("Enter new passphrase", "Confirm new passphrase")

    # Step 3: Decrypt the private key
    decrypted_key_path = _decrypt_private_key_with_gpg(encrypted_key_path, current_passphrase)

    if not decrypted_key_path or not decrypted_key_path.exists():
        print("[Error] Failed to decrypt the private key.")
        sys.exit(1)

    # Step 4: Re-encrypt the private key using the new passphrase
    encrypted_path = _encrypt_private_key_with_gpg(decrypted_key_path, new_passphrase)

    if not encrypted_path:
        print("[Error] Failed to re-encrypt private key.")
        sys.exit(1)

    print("[Success] Passphrase changed successfully.")
    return decrypted_key_path