\# Omni-Gen: The Summit Edition (v24.1)



\*\*Omni-Gen\*\* is a high-performance, military-grade data generator and secure password vault. It features a custom "Aegis" borderless UI, an infinite-scaling entropy engine capable of generating Yottabytes of data, and a proprietary encryption protocol designed for zero-dependency security.



\## 🚀 Key Features



\### 🛡️ Ironclad Security Core

\* \*\*Custom CTR-Mode Cipher:\*\* Uses `HMAC-SHA512` as a pseudo-random function to generate a non-repeating keystream, offering security superior to standard XOR loops.

\* \*\*Scrypt Key Derivation:\*\* Memory-hard key derivation prevents GPU brute-force attacks.

\* \*\*Two-Factor Authentication (2FA):\*\* Built-in TOTP engine compatible with Google Authenticator/Authy.

\* \*\*Sentinel Intercept:\*\* Cross-tab security that intercepts sensitive actions (like saving to a locked vault) and demands authentication on the fly.

\* \*\*Secure Clipboard:\*\* Copied passwords verify self-destruct from the clipboard after 30 seconds.



\### ⚡ Infinite-Scale Generator

\* \*\*Massive Output:\*\* Supports generation sizes from Bytes to Yottabytes (YB).

\* \*\*Stream Engine:\*\* Writes data directly to disk in chunks, allowing for files larger than available RAM.

\* \*\*Entropy Matrix:\*\* Full Unicode support including:

&nbsp;   \* Mathematical Symbols (∀∑)

&nbsp;   \* Box Drawing (▓╗)

&nbsp;   \* CJK Unified Ideographs (汉字)

&nbsp;   \* Emojis (😊)

&nbsp;   \* Custom Injection Pool

\* \*\*Proprietary Format:\*\* Generates standard `.txt` or compressed/obfuscated `.omni` files.



\### 🔐 Secure Vault

\* \*\*Encrypted Storage:\*\* All sensitive data (Usernames, Passwords, Notes) is encrypted at rest using the Ironclad engine.

\* \*\*Drag-and-Drop Organization:\*\* Reorder your vault entries visually.

\* \*\*Interoperability:\*\* Import/Export via CSV (with safety warnings).

\* \*\*Auto-Logout:\*\* Configurable inactivity timer with a "Keep Unlocked" override.



\## 🛠️ Installation



Omni-Gen is designed to be \*\*Zero-Dependency\*\*. It requires \*\*Python 3.10+\*\* but does not require `pip install` for any external libraries.



1\.  \*\*Clone or Download\*\* this repository.

2\.  Ensure you have Python installed.

3\.  Run the application:



```bash

python OmniGen.py



```



\## 📂 Project Structure



\* `OmniGen.py` - The application entry point / launcher.

\* `omni\_ui.py` - Handles the "Aegis" borderless UI, window management, and user interactions.

\* `omni\_core.py` - The cryptographic engine, database management (SQLite), and file streaming logic.

\* `aegis\_vault\_v3.db` - (Generated on first run) The encrypted database file.

\* `omni\_config.json` - (Generated on first run) Stores user preferences (timeouts, default formats).



\## ⚠️ Security Notice



If you lose your \*\*Master PIN\*\* or \*\*2FA Secret\*\*, your data is cryptographically unrecoverable. Use the "Credential Rotation" feature in Settings if you need to change your keys while logged in.



\## 📜 License



Proprietary / Closed Source (AEGIS PROTOCOL)

