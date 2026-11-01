
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# STEP 1: Vendor generates RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

# STEP 2: Vendor prepares tender document
message = b"""
Government E-Procurement Tender
Vendor: ABC Technologies
Tender ID: TENDER2026
Amount: Rs. 500000
"""

print("Original Tender Document:")
print(message.decode())

# STEP 3: Vendor digitally signs the document using RSA-PSS
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("\nDigital Signature Generated Successfully!")
print("Signature:", signature.hex())

# STEP 4: Government portal verifies the signature
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("\nSignature Verification: SUCCESS")
    print("Authentication: Vendor's signature is valid.")
    print("Integrity: Document has not been modified.")
    print("Non-repudiation: Signature provides evidence of signing.")

except InvalidSignature:
    print("\nSignature Verification: FAILED")

# STEP 5: Attacker modifies the tender amount
modified_message = b"""
Government E-Procurement Tender
Vendor: ABC Technologies
Tender ID: TENDER2026
Amount: Rs. 900000
"""

print("\n--- Testing Modified Document ---")

try:
    public_key.verify(
        signature,
        modified_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("Signature Verification: SUCCESS")

except InvalidSignature:
    print("Signature Verification: FAILED")
    print("Integrity Check: Document has been modified!")
    print("Tender Rejected by Government Portal.")

