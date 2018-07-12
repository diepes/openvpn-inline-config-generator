#!/usr/bin/env python3
import os
import socket
from OpenSSL import crypto, SSL
import datetime
import subprocess
import random

''' PES clone 2018-07-12
'''
# OpenVPN is fairly simple since it works on OpenSSL. The OpenVPN server contains
# a root certificate authority that can sign sub-certificates. The certificates
# have very little or no information on who they belong to besides a filename
# and any required information. Everything else is omitted or blank.
# The client certificate and private key are inserted into the .ovpn file
# which contains some settins as well and the entire thing is then ready for
# the user.

# EasyRSA generates a standard unsigned certificate, certificate request, and private key.
# It then signs the certificate against the CA then dumps the certificate request in the trash.
# The now signed certificate and private key are returned.

# Create a new keypair of specified algorithm and number of bits.
def make_keypair(algorithm=crypto.TYPE_RSA, numbits=2048):
    pkey = crypto.PKey()
    pkey.generate_key(algorithm, numbits)
    return pkey

# Creates a certificate signing request (CSR) given the specified subject attributes.
def make_csr(pkey, CN, C=None, ST=None, L=None, O=None, OU=None, emailAddress=None, hashalgorithm='sha256WithRSAEncryption'):
    req = crypto.X509Req()
    req.get_subject()
    subj  = req.get_subject()

    if C:
        subj.C = C
    if ST:
        subj.ST = ST
    if L:
        subj.L = L
    if O:
        subj.O = O
    if OU:
        subj.OU = OU
    if CN:
        subj.CN = CN
    if emailAddress:
        subj.emailAddress = certemailAddress

    req.set_pubkey(pkey)
    req.sign(pkey, hashalgorithm)
    return req

# Create a certificate authority (if we need one)
def create_ca(CN, C="", ST="", L="", O="", OU="", emailAddress="", hashalgorithm='sha256WithRSAEncryption'):
    cakey = make_keypair()
    careq = make_csr(cakey, CN=CN)
    cacert = crypto.X509()
    cacert.set_serial_number(0)
    cacert.gmtime_adj_notBefore(0)
    cacert.gmtime_adj_notAfter(60*60*24*365*10) # 10 yrs - hard to beat this kind of cert!
    cacert.set_issuer(careq.get_subject())
    cacert.set_subject(careq.get_subject())
    cacert.set_pubkey(careq.get_pubkey())
    cacert.set_version(2)

    # Set the extensions in two passes
    cacert.add_extensions([
        crypto.X509Extension(b'basicConstraints', True,b'CA:TRUE'),
        crypto.X509Extension(b'subjectKeyIdentifier' , True , b'hash', subject=cacert)
    ])

    # ... now we can set the authority key since it depends on the subject key
    cacert.add_extensions([
        crypto.X509Extension(b'authorityKeyIdentifier' , False, b'issuer:always, keyid:always', issuer=cacert, subject=cacert)
    ])

    cacert.sign(cakey, hashalgorithm)
    return (cacert, cakey)

# Create a new slave cert.
def create_slave_certificate(csr, cakey, cacert, serial, is_server):
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60*60*24*365*10) # 10 yrs - hard to beat this kind of cert!
    cert.set_issuer(cacert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.set_version(2)

    extensions = []
    extensions.append(crypto.X509Extension(b'basicConstraints', False ,b'CA:FALSE'))
    extensions.append(crypto.X509Extension(b'subjectKeyIdentifier' , False , b'hash', subject=cert))
    extensions.append(crypto.X509Extension(b'authorityKeyIdentifier' , False, b'keyid:always,issuer:always', subject=cacert, issuer=cacert))
    
    if is_server:
        extensions.append(crypto.X509Extension(b"keyUsage", False, b"digitalSignature,keyEncipherment"))
        extensions.append(crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"))
        extensions.append(crypto.X509Extension(b"nsCertType", False, b"server"))
    else:
        extensions.append(crypto.X509Extension(b"keyUsage", False, b"digitalSignature"))
        extensions.append(crypto.X509Extension(b"extendedKeyUsage", False, b"clientAuth"))
        extensions.append(crypto.X509Extension(b"nsCertType", False, b"client"))

    cert.add_extensions(extensions)
    cert.sign(cakey, 'sha256WithRSAEncryption')

    return cert



# Dumps content to a string
def dump_file_in_mem(material, format=crypto.FILETYPE_PEM):
    dump_func = None
    if isinstance(material, crypto.X509):
        dump_func = crypto.dump_certificate
    elif isinstance(material, crypto.PKey):
        dump_func = crypto.dump_privatekey
    elif isinstance(material, crypto.X509Req):
        dump_func = crypto.dump_certificate_request
    else:
        raise Exception("Don't know how to dump content type to file: %s (%r)" % (type(material), material))

    return dump_func(format, material)


# Loads the file into the appropriate openssl object type.
def load_from_file(materialfile, objtype, format=crypto.FILETYPE_PEM):
    if objtype is crypto.X509:
        load_func = crypto.load_certificate
    elif objtype is crypto.X509Req:
        load_func = crypto.load_certificate_request
    elif objtype is crypto.PKey:
        load_func = crypto.load_privatekey
    else:
        raise Exception("Unsupported material type: %s" % (objtype,))

    with open(materialfile, 'r') as fp:
        buf = fp.read()

    material = load_func(format, buf)
    return material

def retrieve_key_from_file(keyfile):
    return load_from_file(keyfile, crypto.PKey)

def retrieve_csr_from_file(csrfile):
    return load_from_file(csrfile, crypto.X509Req)

def retrieve_cert_from_file(certfile):
    return load_from_file(certfile, crypto.X509)


def make_new_ovpn_file(ca_cert, ca_key, tlsauth_key, CN, serial, commonoptspath, filepath, is_server=False):

    # Read our common options file first
    f = open(commonoptspath, 'r')
    common = f.read()
    f.close()

    cacert = retrieve_cert_from_file(ca_cert)
    cakey  = retrieve_key_from_file(ca_key)

    # Generate a new private key pair for a new certificate.
    key = make_keypair()
    # Generate a certificate request
    csr = make_csr(key, CN)
    # Sign the certificate with the new csr
    crt = create_slave_certificate(csr, cakey, cacert, serial, is_server=is_server)

    # Now we have a successfully signed certificate. We must now
    # create a .ovpn file and then dump it somewhere.
    clientkey  = dump_file_in_mem(key)
    clientcert = dump_file_in_mem(crt)
    cacertdump = dump_file_in_mem(cacert)
    #ovpn = "%s<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n" % (common, cacertdump.decode('ascii'), clientcert.decode('ascii'), clientkey.decode('ascii'))
    ovpn = f"{common}\n" + \
           f"\n<ca>\n{cacertdump.decode('ascii')}</ca>\n" + \
           f"\n<cert>\n{clientcert.decode('ascii')}</cert>\n" + \
           f"\n<key>\n{clientkey.decode('ascii')}</key>\n" + \
           f"\n<tls-auth>\n{tlsauth_key}</tls-auth>\n\n"

    # Write our file.
    f = open(filepath, 'wt')
    f.write(ovpn)
    f.close()


def create_ca_if_missing(ca_name="ca"):
    #create_ca(CN, C="", ST="", L="", O="", OU="", emailAddress="", hashalgorithm='sha256WithRSAEncryption'):
    cacert, cakey = create_ca(CN=f"{ca_name}")
    open(f"./{ca_name}.crt", "wb").write(dump_file_in_mem(cacert))
    open(f"./{ca_name}.key", "wb").write(dump_file_in_mem(cakey))


def gen_tlsauth_key():
    """Generate an openvpn secret key by calling openvpn. Returns a string."""
    cmd = ['openvpn', '--genkey', '--secret', 'ta.tmp']
    ret = subprocess.check_call(cmd)
    with open('ta.tmp') as key:
        key = key.read()
    os.remove('ta.tmp')
    return key

if __name__ == "__main__":
    name="test"
    count = 3

    tn = datetime.datetime.now().strftime("%Y%m%d_%Hh%M")
    ca_name=f"{name}_ca_{tn}"
    create_ca_if_missing(ca_name=ca_name)
    tlsauth_key=gen_tlsauth_key()
    
    for c in range(1,3): #create 2 server certs
        make_new_ovpn_file(is_server=True,
                       ca_cert=f"{ca_name}.crt", ca_key=f"{ca_name}.key",
                       tlsauth_key=tlsauth_key,
                       CN=f"{name}_server_{tn}_{c}", serial=random.randint(1, 99),
                       commonoptspath="ovpn-common.txt",  filepath=f"{name}_server_{tn}_{c}.ovpn")

    for c in range(1,1+count):
        make_new_ovpn_file(ca_cert=f"{ca_name}.crt", ca_key=f"{ca_name}.key",
                           tlsauth_key=tlsauth_key,
                           CN=f"{name}_client_{tn}_{c}", serial=random.randint(100, 99999999),
                           commonoptspath="ovpn-common.txt",  filepath=f"{name}_client_{tn}_{c}.ovpn")
    print("Done")


