'''
    Entry point for server application.
'''

import binascii
import os
import datetime
import socket
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from crypto_utils import x509Util
from crypto_utils import ecdh_x25519
from crypto_utils import aes256_cbc
from crypto_utils import chacha20_poly1305

# Networking Settings
SERVER = 'localhost'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
BUFFER_SIZE = 4096 # Big Buffer size since I'm not familiar with Python Socket Programming
CONSOLE_SPEED = 5 # Number of seconds the console screen will pause if time.sleep() is uncommented

# X25519 File Storage Settings
OUTPUT_DIR = 'client_output'
X25519_PRIVATE_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'client-x25519.key')
X25519_PUBLIC_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'client-x25519.pub')
X25519_PRIVATE_KEY_PASSPHRASE = b'password'

# X509 File Storage Settings
X509_PRIVATE_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'client-id-rsa.key')
X509_PUBLIC_CERT_FILEPATH = os.path.join(OUTPUT_DIR, 'client-id.x509')
X509_PRIVATE_KEY_PASSPHRASE = b'password'
TRUSTED_SERVER_X509_PUBLIC_CERT_FILEPATH = os.path.join(
    'server_output', 'server-id.x509')


def connect(server_ip_address, port, pki_public_key,
            ecdh_private_key, ecdh_public_key):
    '''
       Attempt to establish a secure connection to the server and
       communicate using encrypted messaging
    '''

    # Convert PKI public key to bytes for sending over socket connection
    pki_public_key_bytes = pki_public_key.public_bytes(
        encoding=serialization.Encoding.PEM)

    # Convert ECDH public key to bytes for sending over socket connection
    x25519_public_key_bytes = ecdh_public_key.public_bytes_raw()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        
        print(f'1. Connecting to server: {server_ip_address}:{port}')
        s.connect((server_ip_address, port))
        print(f'2. Connected to server: {server_ip_address}:{port}')

        # send server X509 public cert for authentication
        s.sendall(pki_public_key_bytes)

        print(
            '3-1. Sent client X509 public key to server for authentication:\n' +
            f'{pki_public_key_bytes.decode()}')

        # time.sleep(CONSOLE_SPEED)

        # Wait for server to send their PKI public cert for authentication
        server_pki_public_cert_bytes = s.recv(BUFFER_SIZE)

        print(
            '4-1. Received server X509 public key for authentication:\n' +
            f'{server_pki_public_cert_bytes.decode()}')

        # time.sleep(CONSOLE_SPEED)

        # Usually the X509 certificate is issued and renewed after expiry.
        # For a consistent demo experience,
        # server.py will generate a new x509 certificate after each run,
        # We'll simulate accquiring a trusted fingerprint from a trusted certstore.
        # This fingerprint will be used for authenticating the server later.
        trusted_server_fingerprint = x509Util.cert_fingerprint_from_file(
            TRUSTED_SERVER_X509_PUBLIC_CERT_FILEPATH, hashes.SHA256())

        # Get fingerprint from trusted storage and from the server
        untrusted_fingerprint = x509Util.cert_fingerprint_from_bytes(
            server_pki_public_cert_bytes)

        # Compare the untrusted server fingerprint from connect against the trusted store
        # Halt the program if fingerprint does not match
        if untrusted_fingerprint != trusted_server_fingerprint:
            raise Exception(
                "4-2. Fingerprint from TCP stream does not match with fingerprint from trusted storage.")

        print(
            '4-2. Fingerprint from TCP stream matched with fingerprint from trusted storage')

        # Send client x25519 public key for ECDH handshake
        s.sendall(x25519_public_key_bytes)

        print(
            f'5. Sent client x25519 public key to server:\n {binascii.hexlify(x25519_public_key_bytes).decode()}')

        # time.sleep(CONSOLE_SPEED)

        # wait for server to send its x25519 public cert for ECDH handshake
        server_x25519_public_key_data = s.recv(BUFFER_SIZE)
        print(
            '6. Received server x25519 public key for ecdh key exchange:\n' +
            f'{binascii.hexlify(server_x25519_public_key_data).decode()}')

        # time.sleep(CONSOLE_SPEED)

        # Deserialize X25519 public key
        server_x25519_public_key = x25519.X25519PublicKey.from_public_bytes(
            server_x25519_public_key_data)

        # Use client x25519 private key and server x25519 pub key to derive shared key
        shared_key = ecdh_x25519.generate_derived_key(
            private_key=ecdh_private_key,
            peer_public_key=server_x25519_public_key,
            agreed_algorithm=hashes.SHA256(),
            agreed_length=32,
            agreed_info=b'handshake data')

        # The client should derive a shared key with the same value as the server
        print(
            f'7. Client derived shared key: {binascii.hexlify(shared_key).decode()}')

        # time.sleep(CONSOLE_SPEED)

        # Client's plaintext to be encrypted and sent to server for decryption
        plaintext = b'secret message from client.'

        # sign the message
        signature = x509Util.sign_message(x509_private_key, plaintext)
        print(f'8-1. Digitally sign the message using x509 private key\n: {signature}')

        # note that cbc mode is used, a random iv must be used for each message.
        # the helper function aes256.encrypt() abstracted padding and random iv generation.
        (iv, ciphertext) = aes256_cbc.encrypt(
            diffie_hellman_shared_key=shared_key,
            message=plaintext+signature
        )

        print(f'8-2. Encrypted {plaintext} with its signature using block cipher AES256 in CBC mode')


        # prepend the iv to the ciphertext, the iv can be public but must be random
        s.sendall(iv+ciphertext)

        print('8-3. Sent client data:\n' +
              f'random iv: {binascii.hexlify(iv).decode()}\n' +
              f'ciphertext: {binascii.hexlify(ciphertext).decode()}')

        # time.sleep(CONSOLE_SPEED)

        # Waiting for client's command/inputs
        server_message = s.recv(BUFFER_SIZE)

        # slice the first 12 bytes that represents the nonce
        nonce = server_message[:12]

        # slice the remainding bytes that represents our ciphertext that needs decryption
        ciphertext2 = server_message[12:]

        print('9-1. Received server data:\n' +
              f'nonce: {binascii.hexlify(nonce).decode()}\n' +
              f'ciphertext: {binascii.hexlify(ciphertext2).decode()}')

        # Decrypt the cipher text using the trusted fingerprint of the server's x.509 certificate
        plaintext2 = chacha20_poly1305.decrypt(shared_key, nonce, ciphertext2, trusted_server_fingerprint)
        print(f'9-2. Decrypted {plaintext2} using stream cipher aead chacha20-poly1305')

        # we assume both client and server uses the same key size.
        # because we are not using a messaging protocol to define how to splice the data
        server_message = plaintext2[:-x509_private_key.key_size // 8]
        server_message_signature = plaintext2[-x509_private_key.key_size // 8:]

        print('8-3. Verifying the digital signature of the message using the client x.509 cert public key.')
        x509Util.verify_message(server_pki_public_cert_bytes, server_message_signature, server_message)
        print(f'Message: {server_message} is verified to be sent from Server.')


if __name__ == '__main__':

    # Setup for X509 PKI
    x509_private_key = x509Util.generate_private_key(
        public_exponent=65537, key_size=2048)
    x509Util.write_private_key_to_file(
        private_key=x509_private_key,
        filepath=X509_PRIVATE_KEY_FILEPATH,
        passphase=X509_PRIVATE_KEY_PASSPHRASE)

    x509_public_cert = x509Util.generate_public_cert(
        private_key=x509_private_key,
        country='SG',
        state='SG',
        locality='SG',
        organization='Swdev Ninja',
        common_name='client.localhost',
        validity=datetime.timedelta(days=30),
        dns_name='localhost',
        hash_function=hashes.SHA256())

    x509Util.write_public_key_to_file(
        x509_public_cert, X509_PUBLIC_CERT_FILEPATH)

    # Setup for Diffie-Hellman key exchange
    ephermal_key_pair = ecdh_x25519.generate_keys()
    # save ephermal keys to file for visual inspection
    ecdh_x25519.write_private_key_to_file(
        private_key=ephermal_key_pair[0],
        filepath=X25519_PRIVATE_KEY_FILEPATH,
        passphrase=X25519_PRIVATE_KEY_PASSPHRASE)
    ecdh_x25519.write_public_key_to_file(
        public_key=ephermal_key_pair[1],
        filepath=X25519_PUBLIC_KEY_FILEPATH)

    connect(SERVER, PORT, x509_public_cert,
            ephermal_key_pair[0], ephermal_key_pair[1])
