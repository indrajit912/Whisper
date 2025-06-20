# Whisper

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)


**Whisper** is a command-line application for decrypting confidential messages and attachments encrypted by my website's "Whisper" system. It also allows secure passphrase management.

---

## 🧑‍💻 Author

**[Indrajit Ghosh](https://indrajitghosh.onrender.com)** <br>
Indian Statistical Institute, Bangalore

---

## 🔧 Features

- 🔐 Decrypt encrypted whisper messages
- 📎 Decrypt encrypted whisper attachments (e.g., files)
- 🔑 Change the passphrase used for decryption

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/indrajit912/Whisper.git
cd Whisper
````

### 2. Install the CLI tool

You can install it in editable mode using pip:

```bash
pip install -e .
```

This will make the `whisper` command available globally in your terminal.

---

## 🚀 Usage

Once installed, you can use the `whisper` command as follows:

### 🔓 Decrypt a message

```bash
whisper decrypt -m
```

### 📂 Decrypt an attachment

```bash
whisper decrypt -a
```

### 🔑 Change your passphrase

```bash
whisper change-passphrase
```

---

## ⚙️ Constants and Paths

The following predefined constants are used internally:

| Constant                  | Description                             |
| ------------------------- | --------------------------------------- |
| `~/.keys`                 | Default directory for storing secrets   |
| `~/.keys/passphrase_hash` | Encrypted passphrase hash file          |
| `.secret_keys`            | Directory on a flash drive (or similar) |
| `.whisper_passphrase`     | File storing passphrase on flash drive  |

---

## 🧪 Testing

To be added later. You can start by adding tests under the `tests/` directory using `pytest` or any framework of your choice.

---

## 🛡️ License


This project is licensed under the terms of the [MIT License](LICENSE).

