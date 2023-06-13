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
BUFFER_SIZE = 2048

# X25519 File Storage Settings
OUTPUT_DIR = 'server_output'
X25519_PRIVATE_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'server-x25519.key')
X25519_PUBLIC_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'server-x25519.pub')
X25519_PRIVATE_KEY_PASSPHRASE = b'password'

# X509 File Storage Settings
X509_PRIVATE_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'server-id-rsa.key')
X509_PUBLIC_CERT_FILEPATH = os.path.join(OUTPUT_DIR, 'server-id.x509')
X509_PRIVATE_KEY_PASSPHRASE = b'password'


def listen(ip_address, port, pki_public_key, ecdh_private_key, ecdh_public_key):
    '''
        1. Opens an insecure TCP communication channel.
        2. Reads and sends host's PKI public certificate to client for authentication.
        3. Waits for client to send its x25519 public key as peer_public_key
        4. Calculate the shared key to create the cipher for symmetric encryption
        5. Prompt user for message input
        6. Sends the encrypted message to client
        7. Wait to receive encrypted message from client
        8. Decrypt and print decrypted message from client
    '''

    pki_public_key_bytes = pki_public_key.public_bytes(
        encoding=serialization.Encoding.PEM)
    
    x25519_public_key_bytes = ecdh_public_key.public_bytes_raw()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((ip_address, port))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f'{addr} has connected to this server')

            print(
                'Sending host public key to client for authentication:\n' +
                f'{pki_public_key_bytes.decode()}')

            # send server pki public cert for authentication
            conn.sendall(pki_public_key_bytes)

            print(
                'Sent host public key to client for authentication:\n' +
                f'{pki_public_key_bytes.decode()}')
            
            time.sleep(3)

            # wait for client to send its x25519 public cert for ECDH handshake
            client_x25519_public_key_data = conn.recv(BUFFER_SIZE)
            
            print(
            'Received client x25519 public key for diffie-hellman key exchange:\n' +
            f'{len(client_x25519_public_key_data)} bytes')

            time.sleep(3)

            client_x25519_public_key = x25519.X25519PublicKey.from_public_bytes(client_x25519_public_key_data)

            print(f'Sent server X25519 public key to client for diffie-hellman key exchange: {len(x25519_public_key_bytes)} bytes.')
            conn.sendall(x25519_public_key_bytes)

            time.sleep(3)

            # use server x25519 private key and client x25519 pub key to derive shared key
            shared_key = ecdh_x25519.generate_derived_key(
                private_key=ecdh_private_key,
                peer_public_key=client_x25519_public_key,
                agreed_algorithm=hashes.SHA256(),
                agreed_length=32,
                agreed_info=b'handshake data')

            print(f'Server derived shared key: {binascii.hexlify(shared_key).decode()}')

            time.sleep(3)

            # Waiting for client's command/inputs
            client_message = conn.recv(BUFFER_SIZE)
            iv = client_message[:16]
            ciphertext = client_message[16:]
            plaintext = aes256.decrypt(iv, ciphertext, shared_key)
            print('Received:', plaintext)


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
