"""
🔐 Whisper Message Decryption Utility
=======================================

This script provides a secure mechanism to handle RSA private keys used to 
decrypt Whisper messages or attachments. It encrypts the RSA private key using 
GPG symmetric encryption (AES256) with a user-defined passphrase and stores the 
encrypted key in the user's home directory (`~/.keys/`). The passphrase is stored 
securely as a SHA-256 hash for verification purposes. Optionally, the passphrase 
can also be saved to a connected USB drive for easier retrieval.

Author:
-------
Indrajit Ghosh  
Created on: April 21, 2025
Modified on: Jun 19, 2025

Commands:
---------
  decrypt -m    Decrypt a message
  decrypt -a    Decrypt a file attachment
  change-passphrase    Change your passphrase
  help                 Show command list and usage


Features:
---------
1. **Secure Key Storage**:
   - Encrypts the RSA private key (`.pem`) using GPG with AES256.
   - Stores the encrypted key as `~/.keys/rsa_private_key.pem.gpg`.
   - Stores a hashed version of the passphrase locally to verify future entries.

2. **Decryption of Messages or Files**:
   - Prompts the user to provide a passphrase to decrypt the stored private key.
   - Supports decryption of encrypted message JSON (base64) or encrypted file attachments.
   - Uses utility functions (`decrypt_with_private_key`, `decrypt_file_with_private_key`) for actual decryption logic.

3. **Passphrase Management**:
   - Provides functionality to change the passphrase used to protect the RSA key.
   - Uses `getpass` to securely collect user input without echoing it to the terminal.
   - Verifies passphrase integrity using SHA-256 hashing.
   - Optionally saves the passphrase to a USB flashdrive (e.g., `/media/<user>/Indrajit/.secret_keys/.whisper_passphrase`) 
   for automatic loading.

4. **USB flashdrive Integration**:
   - If a flashdrive labeled `Indrajit` is connected, the script checks for an existing saved passphrase.
   - If found, the passphrase is automatically loaded and validated.

Usage:
------
1. On first use, the user will be prompted to provide their RSA private key and a passphrase.
2. The private key is then encrypted and stored securely.
3. On subsequent uses, the user can decrypt a Whisper message or attachment by:
   - Providing the passphrase manually, or
   - Allowing the script to retrieve it from a connected flashdrive.
4. The script offers to decrypt either a JSON-based message or a file attachment.
"""
from pathlib import Path
import click
from .decrypt import decrypt_message, decrypt_attachment, _get_encrypted_key_path
from .passphrase import change_passphrase
from whisper.utils.io import get_flashdrive_with_secret_dir, _cleanup_key
from whisper import __version__

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """
    🔐 Whisper Message Decryption Utility

    Developed by: Indrajit Ghosh
    """

    click.clear()

    click.secho("=" * 60, fg="cyan", bold=True)
    click.secho("🔐 Whisper Message Decryption Utility", fg="cyan", bold=True)
    click.secho("=" * 60, fg="cyan", bold=True)
    click.echo()

    click.secho("Copyright © 2025 Indrajit Ghosh", fg="magenta")
    click.secho("All rights reserved.", fg="magenta")
    click.echo()

    click.secho(f"Version: {__version__}", fg="yellow")
    click.secho("Created on: April 21, 2025", fg="yellow")
    click.secho("Last Modified: June 20, 2025", fg="yellow")
    click.echo()

    if ctx.invoked_subcommand is None:
        click.secho("Available Commands:", fg="blue", bold=True)
        click.echo("  decrypt -m            Decrypt a message")
        click.echo("  decrypt -a            Decrypt a file attachment")
        click.echo("  change-passphrase     Change your passphrase")
        click.echo("  help                  Show command list and usage")
        click.echo()
        click.secho("Use --help after any command for more information.", fg="green")


@cli.command()
@click.option('-m', 'mode_message', is_flag=True, help='Decrypt a message.')
@click.option('-a', 'mode_attachment', is_flag=True, help='Decrypt an attachment.')
def decrypt(mode_message, mode_attachment):
    """Decrypt a whisper message or attachment."""
    if mode_message and mode_attachment:
        raise click.UsageError("Use only one of -m or -a at a time.")
    elif not mode_message and not mode_attachment:
        raise click.UsageError("You must provide either -m or -a.")
    
    encrypted_key_path = _get_encrypted_key_path()

    if mode_message:
        key_path = decrypt_message(encrypted_key_path)
    elif mode_attachment:
        while True:
            raw_path = click.prompt("Enter the path to the encrypted file (e.g. ~/instance/encrypted_attachments/xyz.enc)")
            file_path = Path(raw_path).expanduser()
            if file_path.exists() and file_path.is_file():
                break
            click.secho("❌ Invalid file path. Please try again.", fg="red")

        key_path = decrypt_attachment(
            encrypted_key_path=encrypted_key_path,
            encrypted_file_path=file_path
        )

    _cleanup_key(key_path=key_path)

@cli.command()
def change_passphrase_cmd():
    """Change your secret passphrase."""
    key_path = change_passphrase()
    _cleanup_key(key_path)

@cli.command()
def dev():
    """Dev tests."""
    flashdrive = get_flashdrive_with_secret_dir()
    print(flashdrive)

if __name__ == "__main__":
    cli()
