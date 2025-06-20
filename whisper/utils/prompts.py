import sys
import getpass

def _prompt_passphrase_with_confirmation(prompt="Enter passphrase", confirm_prompt="Confirm passphrase"):
    """
    Prompts the user to enter and confirm a passphrase securely.

    Args:
        prompt (str): The initial prompt for the passphrase.
        confirm_prompt (str): The prompt for passphrase confirmation.

    Returns:
        str: The confirmed passphrase entered by the user.

    Raises:
        SystemExit: If the passphrases do not match after 3 attempts.
    """
    max_attempts = 3
    for attempt in range(max_attempts):
        passphrase = getpass.getpass(f"{prompt}: ").strip()
        confirm = getpass.getpass(f"{confirm_prompt}: ").strip()
        if passphrase == confirm:
            return passphrase
        else:
            print("[Error] Passphrases do not match. Please try again.")
    print("[Error] Maximum attempts reached. Exiting.")
    sys.exit(1)