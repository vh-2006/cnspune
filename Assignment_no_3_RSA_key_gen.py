import time

from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes


# RSA key sizes
key_sizes = [2048,3072,4096]

message_sizes = [64,256,512,1024,2048]

# Number of repetitions
KEY_REPEATS = 3
OP_REPEATS = 10

# RSA encryption padding

def get_padding() : 
    return padding.OAEP (
        mgf = padding.MGF1(algorithm=hashes.SHA256()),
        algorithm= hashes.SHA256(),
        label=None
    ) 

# Generate message of specified bit length
def genrate_message(bits) : 
    return b'A' * (bits //8)


# Split message into RSA-compatible chunks
def split_message(message,max_size) : 
    return [
        message[i:i + max_size] 
        for i in range(0,len(message),max_size)
    ]

def encrypt_message(public_key,message,max_size) : 
    chunks =split_message(message,max_size)
    ciphertext = []
    for chunk in chunks : 
        encrypted = public_key.encrypt(
            chunk,
            get_padding()
        )
        ciphertext.append(encrypted)
    return ciphertext

def decrypt_message(private_key,ciphertext) : 
    decrypted = []
    for chunk in ciphertext : 
        orginal = private_key.decrypt(
            chunk,
            get_padding()
        )
        decrypted.append(orginal)
    return b''.join(decrypted)


print("========== RSA PERFORMANCE ANALYSIS ==========")
for key_size in key_sizes : 
    print(f"RSA KEY sizes : {key_size} bits")

    # ---------------------------------
    # 1. Key Generation Time
    # ---------------------------------


    key_times = []
    for _ in range(KEY_REPEATS)   : 
        start = time.perf_counter()

        private_key = rsa.generate_private_key(
            public_exponent= 65537,
            key_size=key_size
        )
        end = time.perf_counter()
        key_times.append(end - start)

    avg_key_time = sum(key_times) / KEY_REPEATS
    public_key = private_key.public_key()

    print("Average Key genration time : ",avg_key_time * 1000,"ms")
        
    # Maximum plaintext bytes per OAEP block
    max_size = (key_size//8) -2*32 -2 


    # ---------------------------------
    # 2. Encryption and Decryption Time
    # ---------------------------------

    print("\n Message size | Encrpytion(ms) | Decryption(ms)")

    for bits in message_sizes  :
        message  = genrate_message(bits)

        encryption_times = []
        decryption_times = []

        ciphertext = None

        for _ in range(OP_REPEATS)  :
            # Encryption timing
            start = time.perf_counter()

            ciphertext = encrypt_message(
                public_key,message,max_size
            )
            end = time.perf_counter()
            encryption_times.append(end - start)


            # Decryption timing
            start =  time.perf_counter()
            
            decrypted = decrypt_message(
                private_key,ciphertext
            ) 

            end = time.perf_counter()

            decryption_times.append(end - start)

            assert decrypted == message

        avg_encrypt = sum(encryption_times)/OP_REPEATS
        avg_decrypt = sum(decryption_times)/OP_REPEATS

        print(
             f"{bits:>12} | "
            f"{avg_encrypt * 1000:>14.3f} | "
            f"{avg_decrypt * 1000:>13.3f}"
        )

print("\nAll encryption and decryption tests passed!")