# https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples
from hashlib import sha512
from Crypto.PublicKey import RSA

# Generate a 1024-bit RSA key-pair
keyPair = RSA.generate(bits=1024)
print("Generating 1024-bit RSA keypair")
print(f"Public key: (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
print()
print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")

# Now, let's sign a message using the RSA private key {n, d}.
# Calculate its hash and raise the hash to the power d modulo n
# (encrypt the hash by the private key). We shall use SHA-512 hash.
# It will fit in the current RSA key size (1024).
# In Python we have modular exponentiation as built in function pow(x, y, n):
console_msg = b'A message for signing'
print()
print("Signing message - <", console_msg.decode("utf-8"), "> with private key")
hashed_msg_int = int.from_bytes(sha512(console_msg).digest(), byteorder='big')

# The obtained digital signature is an integer in the range of the RSA key length [0...n).
# For the above private key and the above message, the obtained signature looks like this:
signature = pow(hashed_msg_int, keyPair.d, keyPair.n)
print()
print("Signature =>", hex(signature))
print("Length =", signature.bit_length())

# Now, let's verify the signature, by decrypting the signature using the public key
# (raise the signature to power e modulo n).
# Comparing the obtained hash from the signature
# to the hash of the originally signed message.
console_msg = b'A message for signing'
print()
print("Verifying the signature by decrypting with public key")
hashed_msg_int = int.from_bytes(sha512(console_msg).digest(), byteorder='big')
hashFromSignature = pow(signature, keyPair.e, keyPair.n)

# The output will show True, because the signature will be valid:
print()
print("Signature valid:", hashed_msg_int == hashFromSignature)
print()

input("Press <ENTER> to continue")

# **********************************************************************
# Now, let's try to tamper the public key before verifying the signature
# **********************************************************************
console_msg = b'A message for signing'
print()
print("****************************************************************")
print("Verifying the signature by decrypting with a tampered public key")
print("****************************************************************")
hashed_msg_int = int.from_bytes(sha512(console_msg).digest(), byteorder='big')
# Create a tampered public key by XOR-ing original public with (itself x 2)
tampered_publickey = (keyPair.e ^ (keyPair.e * 2))
print("Tampered public key -", hex(tampered_publickey))
hashFromSignature = pow(signature, tampered_publickey, keyPair.n)

# The output will be False, because the hash from signature will be different:
print()
print("Signature valid:", hashed_msg_int == hashFromSignature)
print()

input("Press <ENTER> to continue")

# *******************************************************************
# Now, let's try to tamper the message and verify the signature again
# *******************************************************************
console_msg = b'Different message'
print("***********************************************************************")
print("Verifying the signature with a tampered message - <", console_msg.decode("utf-8"), ">")
print("***********************************************************************")
hashed_msg_int = int.from_bytes(sha512(console_msg).digest(), byteorder='big')
hashFromSignature = pow(signature, keyPair.e, keyPair.n)

# Now, the signature will be invalid and the output from the above code will be False.
print("Signature valid (tampered):", hashed_msg_int == hashFromSignature)
