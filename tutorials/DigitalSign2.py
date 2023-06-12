# https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples
# This sample code demonstrates RSA Signature using PKCS#1
# Real world application should use 3172 or longer keypair bit length
import binascii
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256


RSA_KEY_LENGTH_IN_BIT = 1024

# Generate RSA key pair (private + public key)
print("Generating RSA keypair of length =", RSA_KEY_LENGTH_IN_BIT, "bits")
print()
keyPair = RSA.generate(bits=RSA_KEY_LENGTH_IN_BIT)
pubKey = keyPair.publickey()

# Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
msg = b'Message for RSA signing'
hashed_msg = SHA256.new(msg)
signer = PKCS115_SigScheme(keyPair)
signature = signer.sign(hashed_msg)
print("Signature:", binascii.hexlify(signature))
print("Length = ", len(signature)*8)
print()

# Verify valid PKCS#1 v1.5 signature (RSAVP1)
print("*******************")
print("Verifying signature")
print("*******************")
msg = b'Message for RSA signing'
hashed_msg = SHA256.new(msg)
verifier = PKCS115_SigScheme(pubKey)
try:
    verifier.verify(hashed_msg, signature)
    print("Signature is valid.")
except:
    print("Signature is invalid.")

# Verify invalid PKCS#1 v1.5 signature (RSAVP1)
print()
print("*******************************************")
print("Verifying signature with a tampered message")
print("*******************************************")
msg = b'A tampered message'
hashed_msg = SHA256.new(msg)
verifier = PKCS115_SigScheme(pubKey)
try:
    verifier.verify(hashed_msg, signature)
    print("Signature is valid.")
except:
    print("Signature is invalid.")
