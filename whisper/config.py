from pathlib import Path

DEFAULT_KEYS_DIR = Path.home() / ".keys"
RSA_PRIVATE_KEY_FILE = DEFAULT_KEYS_DIR / "rsa_private_key.pem"
PASSPHRASE_HASH_FILE = DEFAULT_KEYS_DIR / "passphrase_hash"
FLASHDRIVE_SECRET_DIR_NAME = ".secret_keys"
FLASHDRIVE_PASSPHRASE_FILENAME = ".whisper_passphrase"
