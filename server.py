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
from crypto_utils import aes256

# Networking Settings
HOST = 'localhost'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
BUFFER_SIZE = 4096
CONSOLE_SPEED = 5

# X25519 File Storage Settings
OUTPUT_DIR = 'server_output'
X25519_PRIVATE_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'server-x25519.key')
X25519_PUBLIC_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'server-x25519.pub')
X25519_PRIVATE_KEY_PASSPHRASE = b'password'

# X509 File Storage Settings
X509_PRIVATE_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'server-id-rsa.key')
X509_PUBLIC_CERT_FILEPATH = os.path.join(OUTPUT_DIR, 'server-id.x509')
X509_PRIVATE_KEY_PASSPHRASE = b'password'
TRUSTED_CLIENT_X509_PUBLIC_CERT_FILEPATH = os.path.join(
    'client_output', 'client-id.x509')


def listen(ip_address, port, pki_public_key,
           ecdh_private_key, ecdh_public_key):
    '''
        Attempts to listens for a single client connection and
        communicate using encrypted messaging
    '''

    pki_public_key_bytes = pki_public_key.public_bytes(
        encoding=serialization.Encoding.PEM)

    x25519_public_key_bytes = ecdh_public_key.public_bytes_raw()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        s.bind((ip_address, port))
        s.listen()
        print(f'1. Opened and listening for connection on {ip_address}:{port}')

        conn, addr = s.accept()
        with conn:
            print(f'2. {addr} has connected to this server')

            client_pki_public_cert_bytes = conn.recv(BUFFER_SIZE)

            # time.sleep(CONSOLE_SPEED)

            # Since the client.py will always generate a new x509 certificate after execution,
            # We'll simulate accquiring a trusted fingerprint from a trusted certstore.
            # This fingerprint will be used for authenticating the client later.
            trusted_client_fingerprint = x509Util.cert_fingerprint_from_file(
                TRUSTED_CLIENT_X509_PUBLIC_CERT_FILEPATH, hashes.SHA256())

            # compare fingerprint from trusted storage and from the server
            untrusted_fingerprint = x509Util.cert_fingerprint_from_bytes(
                client_pki_public_cert_bytes)
            if untrusted_fingerprint != trusted_client_fingerprint:
                raise Exception(
                    "3-2. Fingerprint from TCP stream does not match with fingerprint from trusted storage.")

            print(
                '3-2. Fingerprint from TCP stream matched with fingerprint from trusted storage')

            print(
                '4-1. Sending host public key to client for authentication:\n' +
                f'{pki_public_key_bytes.decode()}')

            # send server pki public cert for authentication
            conn.sendall(pki_public_key_bytes)

            print(
                '4-2. Sent host public key to client for authentication:\n' +
                f'{pki_public_key_bytes.decode()}')

            # time.sleep(CONSOLE_SPEED)

            # Send client x25519 public key for ECDH handshake
            conn.sendall(x25519_public_key_bytes)
            print(
                f'Sent client x25519 public key to server: {len(x25519_public_key_bytes)} bytes.')

            # time.sleep(CONSOLE_SPEED)

            # wait for client to send its x25519 public cert for ECDH handshake
            client_x25519_public_key_data = conn.recv(BUFFER_SIZE)

            print(
                '5. Received client x25519 public key for diffie-hellman key exchange:\n' +
                f'{len(client_x25519_public_key_data)} bytes')

            # time.sleep(CONSOLE_SPEED)

            client_x25519_public_key = x25519.X25519PublicKey.from_public_bytes(
                client_x25519_public_key_data)

            print(
                f'6. Sent server X25519 public key to client for diffie-hellman key exchange: {len(x25519_public_key_bytes)} bytes.')
            conn.sendall(x25519_public_key_bytes)

            # time.sleep(CONSOLE_SPEED)

            # use server x25519 private key and client x25519 pub key to derive shared key
            shared_key = ecdh_x25519.generate_derived_key(
                private_key=ecdh_private_key,
                peer_public_key=client_x25519_public_key,
                agreed_algorithm=hashes.SHA256(),
                agreed_length=32,
                agreed_info=b'handshake data')

            print(
                f'7. Server derived shared key: {binascii.hexlify(shared_key).decode()}')

            # time.sleep(CONSOLE_SPEED)

            # Waiting for client's command/inputs
            client_message = conn.recv(BUFFER_SIZE)
            iv = client_message[:16]
            ciphertext = client_message[16:]
            print('8-1. Received client data:\n' +
                  f'random iv: {binascii.hexlify(iv).decode()}\n' +
                  f'ciphertext: {binascii.hexlify(ciphertext).decode()}')

            plaintext = aes256.decrypt(iv, ciphertext, shared_key)
            print(f'8-2. Decrypted {plaintext} using AES256 in CBC mode')

            # time.sleep(CONSOLE_SPEED)

            # plaintext2 = b'Acknowledged by server.'
            # print(f'9-1. Encrypting {plaintext2} using AES256 in CBC mode')
            # # note that cbc mode is used, a random iv must be used for each message
            # (iv2, ciphertext2) = aes256.encrypt(
            #     diffie_hellman_shared_key=shared_key,
            #     message=plaintext2
            # )

            # prepend the iv to the ciphertext
            # conn.sendall(iv2+ciphertext2)

            # print('9-2. Sent server data:\n' +
            #       f'random iv: {binascii.hexlify(iv2).decode()}\n' +
            #       f'ciphertext: {binascii.hexlify(ciphertext2).decode()}')


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
        common_name='server.localhost',
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

    listen(HOST, PORT, x509_public_cert,
           ephermal_key_pair[0], ephermal_key_pair[1])
