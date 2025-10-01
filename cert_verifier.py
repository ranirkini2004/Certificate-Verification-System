# ==============================================================================
# Project: Certificate Signature Verification
# Author: Rani R Kini
# Course: Cryptography and Network Security
# ==============================================================================

# --- Import necessary modules from the cryptography library ---
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    Encoding,
    PrivateFormat,
    NoEncryption,
    PublicFormat
)
from cryptography.exceptions import InvalidSignature

# ==============================================================================
# CORE FUNCTION TO VERIFY THE CERTIFICATE
# ==============================================================================

def verify_certificate_signature(cert_pem: bytes, issuer_public_key_pem: bytes) -> bool:
    """
    Verifies the signature of a certificate using the issuer's public key.

    This function is the core of the project. It simulates how a system
    checks if a certificate is authentic and was actually issued by the
    claimed authority. This is a foundational concept for SSL/TLS and blockchain.

    Args:
        cert_pem: The certificate to verify, in PEM format (as bytes).
        issuer_public_key_pem: The issuer's public key, in PEM format (as bytes).

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        # Step A: Load the certificate from its PEM-encoded string into a usable object.
        cert = x509.load_pem_x509_certificate(cert_pem)
        
        # Step B: Load the issuer's public key from its PEM-encoded string.
        # This is the public key of the Certificate Authority (CA) that we trust.
        issuer_public_key = load_pem_public_key(issuer_public_key_pem)

        # Step C: Perform the verification.
        # This is the most critical step. The library internally performs the following:
        # 1. Decrypts the certificate's signature using the issuer's public key.
        #    The result is the original hash calculated by the issuer.
        # 2. Calculates a new hash of the certificate's main content (the TBS section).
        # 3. Compares the two hashes. If they match, the signature is authentic.
        #
        # This verification step is the same principle that secures blockchain transactions.
        # Every transaction is signed, and network nodes verify it just like this.
        issuer_public_key.verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm
        )
        
        # If verify() completes without raising an exception, the signature is valid.
        return True
        
    except InvalidSignature:
        # If the signature does not match, the library raises InvalidSignature.
        # This means the certificate is either fake or has been tampered with.
        return False
    except Exception as e:
        # Handle other potential errors, e.g., malformed certificate or key.
        print(f"An unexpected error occurred: {e}")
        return False

# ==============================================================================
# DEMONSTRATION SCRIPT
# This part of the code sets up a scenario to test our function.
# ==============================================================================

if __name__ == "__main__":
    
    # --- 1. Generate a Key Pair for a fake "Issuer" (Certificate Authority) ---
    # In the real world, the CA's keys are highly protected.
    print("Step 1: Generating a key pair for our fake Certificate Authority (CA)...")
    issuer_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer_public_key = issuer_private_key.public_key()
    print("Done.\n")

    # --- 2. Generate a Key Pair for the "Subject" (the website or user) ---
    print("Step 2: Generating a key pair for the subject (e.g., example.com)...")
    subject_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject_public_key = subject_private_key.public_key()
    print("Done.\n")

    # --- 3. Build and Sign the Certificate ---
    # The issuer (CA) creates a certificate for the subject and signs it with its own PRIVATE key.
    print("Step 3: The CA is creating and signing a certificate for the subject...")
    
    builder = x509.CertificateBuilder()
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'My Fake CA')]))
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'example.com')]))
    builder = builder.public_key(subject_public_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
    
    # Sign the certificate using the issuer's private key.
    certificate = builder.sign(private_key=issuer_private_key, algorithm=hashes.SHA256())
    print("Certificate created and signed successfully.\n")

    # --- 4. Prepare Data for Verification ---
    # We need the certificate and the issuer's public key in PEM format (a standard text format).
    cert_pem = certificate.public_bytes(Encoding.PEM)
    issuer_public_key_pem = issuer_public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    # ==========================================================================
    # --- DEMO CASE 1: Successful Verification ---
    # We verify the certificate using the CORRECT issuer's public key.
    # ==========================================================================
    print("--- DEMO 1: Verifying with the CORRECT issuer public key ---")
    is_valid = verify_certificate_signature(cert_pem, issuer_public_key_pem)
    
    if is_valid:
        print("✅ RESULT: Signature is VALID. The certificate is authentic.\n")
    else:
        print("❌ RESULT: Signature is INVALID.\n")

    # ==========================================================================
    # --- DEMO CASE 2: Failed Verification ---
    # To prove our system works, we try to verify with the WRONG key.
    # This simulates an attacker trying to use a fake CA key.
    # ==========================================================================
    print("--- DEMO 2: Verifying with the WRONG issuer public key ---")
    
    # Generate a completely different key pair for a "fake" issuer.
    fake_issuer_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fake_issuer_public_key = fake_issuer_private_key.public_key()
    fake_issuer_public_key_pem = fake_issuer_public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    is_valid_fake = verify_certificate_signature(cert_pem, fake_issuer_public_key_pem)

    if is_valid_fake:
        print("✅ RESULT: Signature is VALID.\n")
    else:
        print("❌ RESULT: Signature is INVALID. The system correctly rejected the fake key.\n")