# Omni-Gen: The Summit (v1.0)

**Omni-Gen** is a zero-dependency, military-grade data generator and secure password vault. It combines an infinite-scaling entropy engine with a proprietary "Ironclad" encryption protocol, all wrapped in a custom "Aegis" borderless UI.

## 🚀 Core Modules

### 🛡️ Ironclad Security Engine
* **Custom CTR-Mode Cipher:** Utilizes `HMAC-SHA512` as a pseudo-random function to generate a non-repeating keystream, ensuring mathematical security superior to standard XOR loops.
* **Scrypt Key Derivation:** Memory-hard hashing protects against GPU/ASIC brute-force attacks.
* **Two-Factor Authentication (2FA):** Built-in TOTP engine compatible with Google Authenticator, Authy, and Microsoft Authenticator.
* **Sentinel Protocol:** Active security monitor that handles auto-logout, clipboard self-destruction (30s timer), and cross-tab security interception.

### ⚡ Infinite-Scale Generator
* **Massive Output:** Capable of streaming data from Bytes to Yottabytes (YB) directly to disk.
* **Quantum Entropy Matrix:** Full Unicode support including:
    * Mathematical Operators (∀∑)
    * Box Drawing (▓╗)
    * CJK Unified Ideographs (汉字)
    * Emojis (😊)
* **Dual Formats:**
    * `.txt`: Standard plain text.
    * `.omni`: A compressed, binary-obfuscated proprietary format.

### 🔐 Secure Vault
* **Encrypted Storage:** All data (Usernames, Passwords, Notes, URLs) is encrypted at rest using the Ironclad engine.
* **Quantum Editor:** A paginated, lightweight text editor capable of handling massive text data without memory crashes.
* **Drag-and-Drop Organization:** Visually reorganize your vault entries.
* **Interoperability:** Full Import/Export support for CSV standards (Bitwarden/Excel compatible).

## 🛠️ Installation

Omni-Gen requires **Python 3.10+**. It is designed to be **Zero-Dependency**, meaning you do **not** need to install any external libraries.

1.  **Download** the source code.
2.  **Run** the launcher:

```bash
python OmniGen.py

```

*On first launch, you will be prompted to create a Master PIN and set up 2FA.*

## 📂 File Structure

* `OmniGen.py` - Application launcher.
* `omni_ui.py` - Frontend logic (Aegis UI, Window Management, Quantum Editor).
* `omni_core.py` - Backend logic (Crypto Engine, SQLite Manager, File Streaming).
* `aegis_vault_v3.db` - Encrypted database (Auto-generated).
* `omni_config.json` - User preferences (Auto-generated).

## ⚠️ Security Notice

This application uses a custom cryptographic implementation. If you lose your **Master PIN** or **2FA Secret**, your data is mathematically unrecoverable.

Use the **"Credential Rotation"** feature in *Settings* if you need to change your keys while logged in.

## 📜 License

Proprietary / Closed Source (AEGIS PROTOCOL)