# Certificate Signature Verification 🛡️

A Python project that demonstrates the fundamental cryptographic process of verifying a digital certificate's signature. This script simulates how a system validates the authenticity of a certificate using the issuer's public key. It serves as a practical example of the principles that secure web communications (SSL/TLS) and validate transactions in blockchain technology.

This project was developed for a course in Cryptography and Network Security.

***

## Features ✨

* **Self-Contained:** No external files or keys needed. The script generates all necessary components on-the-fly.
* **Key Generation:** Creates RSA key pairs for a mock Certificate Authority (CA) and a Subject.
* **Certificate Creation:** Builds and signs an X.509 certificate.
* **Successful Verification:** Demonstrates a successful signature validation using the correct CA public key.
* **Failed Verification:** Proves the security model by showing a failed validation when using an incorrect public key.

***

## How It Works

The verification process relies on **asymmetric cryptography** (also known as public-key cryptography).

1.  **Signing:** The Certificate Authority (CA) signs a certificate by creating a hash of its content (the subject's name, public key, etc.) and encrypting that hash with its own **private key**. This encrypted hash is the digital signature.
2.  **Verifying:** Anyone with the CA's **public key** can decrypt the signature to reveal the original hash. They then compute a new hash of the certificate's content themselves. If the two hashes match, the signature is authentic and the certificate has not been tampered with.

This same sign/verify mechanism is what allows blockchain networks to confirm that a transaction was authorized by the owner of a wallet.

***

## Requirements 📋

* Python 3.7+
* `cryptography` library

***

## Setup and Installation ⚙️

1.  **Clone the repository or download the `cert_verifier.py` file.**

2.  **Navigate to the project directory:**
    ```bash
    cd path/to/your/project
    ```

3.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    ```

4.  **Activate the virtual environment:**
    * **On Windows (PowerShell):**
        ```powershell
        .\venv\Scripts\Activate.ps1
        ```
    * **On macOS/Linux:**
        ```bash
        source venv/bin/activate
        ```

5.  **Install the required dependency:**
    ```bash
    python -m pip install cryptography
    ```

***

## Usage ▶️

Run the script from your terminal.

```bash
python cert_verifier.py
