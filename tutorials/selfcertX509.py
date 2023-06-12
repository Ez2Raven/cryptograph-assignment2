# -*- coding: utf-8 -*-
"""
Implements the OpenSSL library.
Documentation at:
    https://www.pyopenssl.org/en/stable/api.html 

@author: ad3629
"""

#https://stackoverflow.com/questions/27164354/create-a-self-signed-x509-certificate-in-python

from OpenSSL import crypto
from socket import gethostname
#from pprint import pprint
#from time import gmtime, mktime

CERT_FILE = "selfsigned.crt"
KEY_FILE = "private.key"

def create_self_signed_cert():

    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)


    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "UK"
    cert.get_subject().ST = "London"
    cert.get_subject().L = "London"
    cert.get_subject().O = "Dummy Company Ltd"
    cert.get_subject().CN = gethostname()
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60) #Amended..
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

#serialise (write to files) in your working directory.
    open(CERT_FILE, "wt").write(
         str(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)))
    open(KEY_FILE, "wt").write(
         str(crypto.dump_privatekey(crypto.FILETYPE_PEM, k)))
    print ("Done")
    
if __name__ == '__main__':
    create_self_signed_cert()