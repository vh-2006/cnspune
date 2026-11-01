
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os

# Receiver generates RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048
)
public_key = private_key.public_key()

# Sender reads image
with open("input.jpg", "rb") as f:
    image = f.read()

# Encrypt image using AES-256-GCM
aes_key = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)

aesgcm = AESGCM(aes_key)
encrypted_image = aesgcm.encrypt(nonce, image, None)

# Encrypt AES key using receiver's RSA public key
encrypted_key = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Transmit encrypted image, encrypted AES key and nonce
transmitted_data = (encrypted_image, encrypted_key, nonce)

print("Image and encrypted AES key sent successfully!")

# Receiver receives all three items
received_image, received_key, received_nonce = transmitted_data

# Decrypt AES key using RSA private key
aes_key = private_key.decrypt(
    received_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypt image and automatically verify authentication tag
aesgcm = AESGCM(aes_key)

try:
    original_image = aesgcm.decrypt(
        received_nonce, received_image, None
    )

    # Authentication tag is verified automatically by AES-GCM
    print("Authentication tag verified successfully!")
    print("Image integrity verified!")

    with open("received.jpg", "wb") as f:
        f.write(original_image)

    print("Image received successfully!")

except InvalidTag:
    print("Authentication failed! Image has been modified or tampered with.")
