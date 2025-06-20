import hashlib
import base64
import json
import os
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def sha256_hash(raw_text):
    """Hash the given text using SHA-256 algorithm.

    Args:
        raw_text (str): The input text to be hashed.

    Returns:
        str: The hexadecimal representation of the hashed value.

    Example:
        >>> sha256_hash('my_secret_password')
        'e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4'
    """
    hashed = hashlib.sha256(raw_text.encode()).hexdigest()
    return hashed


def decrypt_with_private_key(private_key_path: str, raw_json: str, password: bytes = None):
    """
    Decrypts a JSON string containing:
        - 'encrypted_key': RSA-encrypted AES key
        - 'iv': AES IV
        - 'ciphertext': AES-encrypted and padded + compressed message

    Returns:
        Decrypted plaintext (str)
    """

    # Step 1: Parse the JSON string
    try:
        encrypted_data = json.loads(raw_json)
    except Exception as e:
        raise ValueError(f"Failed to parse JSON: {e}")

    # Step 2: Decode base64 fields
    try:
        encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    except Exception as e:
        raise ValueError(f"Failed to base64-decode fields: {e}")

    # Step 3: Load private RSA key
    with open(os.path.expanduser(private_key_path), 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )

    # Step 4: Decrypt AES key using RSA
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 5: Decrypt ciphertext using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_compressed_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Step 6: Remove PKCS#7 padding
    pad_len = padded_compressed_data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding.")
    compressed_data = padded_compressed_data[:-pad_len]

    # Step 7: Decompress to get the original plaintext
    try:
        plaintext_bytes = zlib.decompress(compressed_data)
    except Exception as e:
        raise ValueError(f"Failed to decompress data: {e}")

    return plaintext_bytes.decode('utf-8')


def decrypt_file_with_private_key(private_key_path: str, encrypted_file_path: str, output_dir: str, password: bytes = None):
    # Load encrypted data
    with open(encrypted_file_path, 'r') as f:
        data = json.load(f)

    # Decrypt filename and content
    decrypted_filename = decrypt_with_private_key(private_key_path, data['encrypted_filename'], password)
    decrypted_content = decrypt_with_private_key(private_key_path, data['encrypted_content'], password)

    # Save to output
    output_path = os.path.join(output_dir, decrypted_filename)
    with open(output_path, 'wb') as f:
        f.write(decrypted_content.encode('latin1'))

    return output_path
