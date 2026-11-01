

p = 23
g=5

#private keys
alice_private = 6
bob_private = 15

#public values
alice_public = pow(g,alice_private,p)
bob_public = pow(g,bob_private,p)

print("====Normal diffile-hellman======")
print("Alice public value : ",alice_public)
print("Bob public value : ",bob_public)

alice_key = pow(bob_public,alice_private,p)
bob_key = pow(alice_public,bob_private,p)

print("Alice Shared Secret : ",alice_key)
print("Bob Shared Secret ",bob_key)
print("Key Match : ",alice_key == bob_key)


#MITM

eve_private_for_alice = 7
eve_private_for_bob = 10

eve_public_for_alice = pow(g,eve_private_for_alice,p)
eve_public_for_bob = pow(g,eve_private_for_bob,p)

print("\n=== MITM Attack ===")

# Eve replaces Bob's public value with her own
alice_attacked_key = pow(eve_public_for_alice,alice_private,p)

# Eve replaces Alice's public value with her own
bob_attacked_key = pow(eve_public_for_bob,bob_private,p)

# Eve independently computes both shared secrets

eve_key_with_alice = pow(alice_public,eve_private_for_alice,p)

eve_key_with_bob = pow(bob_public,eve_private_for_bob,p)

print("fake value sent to alice : ",eve_public_for_alice)
print("fake value sent to bob : ",eve_public_for_bob)

print("Alice secret with eve : ",alice_attacked_key)
print("Bob secret with eve : ",bob_attacked_key)

print("Eve's Secret with alice : ",eve_key_with_alice)
print("Eve's Secret with Bob : ",eve_key_with_bob)

print("Eve Knows Alice key ",alice_attacked_key== eve_key_with_alice)
print("Eve knows Bob key ",bob_attacked_key == eve_key_with_bob)



# 5. Solutions to prevent the MITM attack
# 1. Digital signatures: Alice and Bob digitally sign their Diffie–Hellman public values. The receiver verifies the signature to ensure the values have not been substituted by Eve.
# 2. Digital certificates: Use certificates issued by a trusted Certificate Authority (CA) to verify the identities of Alice and Bob.
# 3. Authenticated key exchange: Use established protocols such as TLS 1.3, which authenticate the server and securely establish session keys. Client authentication can also be configured when required.
# 4. Message Authentication Code (MAC): Use a MAC with a securely established secret key to detect unauthorized modification of messages. A MAC alone does not authenticate the initial DH exchange unless the key and identities are securely bound to the exchange.
# 5. Public-key verification: Verify the other party's public key through a trusted channel or a previously established fingerprint