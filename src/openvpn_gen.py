#!/usr/bin/env python3
import os
import errno
import socket
from OpenSSL import crypto, SSL
import datetime
import subprocess
import random
import jinja2
import ipaddress
#
import argparse, logging, sys
#
import yaml
import re
# logging level set with -v flag
logging.basicConfig(level=logging.INFO,format='[%(levelname)-7s:%(lineno)3d:%(funcName)s()] %(message)s')
logging.warning("Start!")
#
'''
   PES 2019-10 Bac
   PES clone 2018-07-12
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
    logging.debug(f"   algorithm={algorithm} , numbits={numbits}")
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
def create_ca(CN, C="", ST="", L="", O="", OU="", emailAddress="", hashalgorithm='sha256WithRSAEncryption', keysize=2048 ):
    cakey = make_keypair(numbits=keysize)
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
    #PES change critical flag True->False for subjectKeyIdentifier
    cacert.add_extensions([
        crypto.X509Extension(b'basicConstraints', True,b'CA:TRUE'),
        crypto.X509Extension(b'subjectKeyIdentifier' , False , b'hash', subject=cacert)
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
        extensions.append(crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth")) #openvpn remote-cert-tls server
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

#######################################################################
def make_new_ovpn_file(ca_cert, ca_key, tlsauth_key, dh, CN, serial
                       , commonoptspath, filepath
                       , keysize=2048
                       , is_server=False
                       , vpn_servers=None, this_server=None
                       , vpn_clients=None, this_client=None
                       , tap_interface_name="tap_az"):
    ''' Make config template '''
    ## Read our common options file first
    #f = open(commonoptspath, 'r')
    #common = f.read()
    #f.close()

    #ca_cert = retrieve_cert_from_file(ca_cert)
    #ca_key  = retrieve_key_from_file(ca_key)

    # Generate a new private key pair for a new certificate.
    key = make_keypair(numbits=keysize)
    # Generate a certificate request
    csr = make_csr(key, CN)
    # Sign the certificate with the new csr
    crt = create_slave_certificate(csr, ca_key, ca_cert, serial, is_server=is_server)

    # Now we have a successfully signed certificate. We must now
    # create a .ovpn file and then dump it somewhere.
    clientkey  = dump_file_in_mem(key)
    clientcert = dump_file_in_mem(crt)
    cacertdump = dump_file_in_mem(ca_cert)
    logging.debug(f"is_server={is_server} this_server={this_server} this_client={this_client}")

    logging.debug(f" jinja2 path:{ os.path.dirname(os.path.abspath(__file__)) }  commonoptspath:{commonoptspath}")
    j2_env = jinja2.Environment(
                loader=jinja2.FileSystemLoader( os.path.dirname(os.path.abspath(__file__)) )
                , trim_blocks=True )

    #template default="openvpn_common.jinja2"
    ovpn = j2_env.get_template(commonoptspath).render(
        title='Hello Github openvpn gen',
        is_server=is_server,
        CN=CN,
        cacert=cacertdump.decode('ascii').strip(),
        clientcert=clientcert.decode('ascii').strip(),
        clientkey=clientkey.decode('ascii').strip(),
        tlsauth_key=tlsauth_key.strip(),
        dh=dh.strip(),
        vpn_servers=vpn_servers,
        vpn_clients=vpn_clients,
        this_server=this_server,
        this_client=this_client,
        tap_interface_name=tap_interface_name
    )
    # Write our file.
    f = open(filepath, 'wt')
    f.write(ovpn)
    f.close()


def create_ca_if_missing(ca_name="ca",keysize=2048 ):
    '''not used '''
    exit(1)
    #create_ca(CN, C="", ST="", L="", O="", OU="", emailAddress="", hashalgorithm='sha256WithRSAEncryption'):
    cacert, cakey = create_ca(CN=f"{ca_name}", C="New Zealand", ST="Auckland", O="NSP", OU="IT", keysize=keysize)
    open(f"./{ca_name}.crt", "wb").write(dump_file_in_mem(cacert))
    open(f"./{ca_name}.key", "wb").write(dump_file_in_mem(cakey))


def gen_tlsauth_key():
    """Generate an openvpn secret key by calling openvpn. Returns a string."""
    cmd = ['/usr/sbin/openvpn', '--genkey', 'secret', 'ta.tmp']
    ret = subprocess.check_call(cmd)
    with open('ta.tmp') as key:
        key = key.read()
    os.remove('ta.tmp')
    return key

def gen_dhparam_dh(filename='openvpn_dh4096.dh'):
    """Generate an diffie hellman key by calling openssl. Returns a string."""
    if not os.path.isfile(filename):
        #cmd = [rf'/usr/bin/openssl dhparam -out {filename} 4096 2>/dev/null']
        cmd = ['/usr/bin/openssl', 'dhparam', '-out', filename, '4096', '2>/dev/null']
        ret = subprocess.check_call(cmd)
    with open(filename) as key:
        key = key.read()
    #os.remove('dh4096.tmp')
    return key


def get_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-c", "--config", dest="config", type=str,
                        default="openvpn_sample.conf.yaml",
                        help="set config in yaml file"
                        )

    parser.add_argument("-v", "--verbose", dest="verbose", action="count",
                        default=0,
                        help="increase output verbosity"
                        )
    parser.add_argument("--template", dest="template", nargs='?', type=str,
                        default="openvpn_common.jinja2",
                        help="template to deploy on azure."
                        )
    parser.add_argument("-p", "--prefix", dest="prefix", type=str,
                        help="prefix name for openvpn configs."
                        ) #, nargs='?'
    parser.add_argument("--keysize", dest="keysize", nargs='?', type=int,
                        default=2048, choices =[ 2048, 4096 ],
                        help="rsa key size. 2048 fine, 4096 possible."
                        )

    parser.add_argument("--count-client", dest="count_client", nargs='?', type=int,
                        default=3,
                        help="number of client templates."
                        )
    parser.add_argument("--count-server", dest="count_server", nargs='?', type=int,
                        default=2,
                        help="number of server templates."
                        )

    args = parser.parse_args()

    if args.verbose == 1:
        log=logging.getLogger()
        log.setLevel(logging.INFO)
        logging.info(f"set logging.level to INFO verbose={args.verbose}")
    if args.verbose > 1:
        log=logging.getLogger()
        log.setLevel(logging.DEBUG)
        logging.debug(f"set logging.level to DEBUG verbose={args.verbose}")

    logging.debug(f"sys.argv[0]={sys.argv[0]}  ,args={args}")

    if os.path.isfile(args.config):
        with open(args.config, 'r') as ymlfile:
            cfg = yaml.load(ymlfile, Loader=yaml.SafeLoader)
            logging.info(f"loaded config from {args.config}")
            logging.debug(f"config from {args.config} is: {cfg}")
            #if cfg has prefix, but none passed in args, prevent prefix=None
            if ( 'prefix' in cfg ) and ( not args.prefix ): args.prefix = cfg['prefix']
    else:
        logging.warn(f"missing config file {args.config}")
        cfg = dict()

    # To do check for class C minimum
    cfg['network']=ipaddress.ip_network(re.sub( r'\s+','/', cfg['vpn_config']['ip_subnet'].strip() ))
    cfg['tap_interface_name']=cfg.get('tap_interface_name','tap_vpn')
    #Note: vars changes the namespace to a dict,  **x, **y merge dicts
    return { **cfg , **vars(args) }

def calc_ServerInfo(args):
    for index,server in enumerate(args['vpn_servers']): #create 2 server certs
        c = index + 1
        args['vpn_servers'][index]['server']['count'] = c
        args['vpn_servers'][index]['server']['vpn_ip'] = args['network'].network_address +c
        args['vpn_servers'][index]['server']['vpn_mask']= args['network'].netmask
        #remove illegal chars from file name.
        name=re.sub( r'\s+|\\|/|:|_','', server['server']['name'] ).lower()
        if name != server['server']['name']:
            logging.warning(f" update {server['server']['name']} to {name}")
            args['vpn_servers'][index]['server']['name'] = name
        logging.debug(f"... creating server config c={c} {name} server={server['server']}")
        if (len(server['server']['connect'].split(" ")) != 3):
            logging.warn(f"WARN: connect string for server {server['name']} suspect value:{server['connect']}")
    return args


def calc_ClientInfo(args):
    for index, client in enumerate(args['vpn_clients']):
        c = index + 1
        args['vpn_clients'][index]['client']['count'] = c
        args['vpn_clients'][index]['client']['vpn_ip']  = args['network'].network_address +10 +c #Start @11
        args['vpn_clients'][index]['client']['vpn_mask']= args['network'].netmask
        #remove illegal chars from file name.
        name=re.sub( r'\s+|\\|/|:|_','', client['client']['name'] ).lower()
        if name != client['client']['name']:
            logging.warning(f" update {client['client']['name']} to {name}")
            args['vpn_clients'][index]['client']['name'] = name
    return args

def main():
    args = get_args()

    logging.debug(f"__main___ args={args}")
    args = calc_ServerInfo(args)
    args = calc_ClientInfo(args)
    #commonoptspath=args["template"]
    tn = datetime.datetime.now().strftime("%Y%m%dt%Hh%M")

    filedir=f"confGen-{args['prefix']}-{tn}"
    if not os.path.exists(filedir):
        try:
            logging.info(f"mkdir for configs {filedir}")
            os.makedirs(filedir)
        except OSError as exc: # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise
    else:
        logging.error(f"config dir already exists wait one minure {filedir}")
        sys.exit(1)

    ca_name=f"{args['prefix']}_{tn}_ca"
    #create_ca_if_missing(ca_name=ca_name)
    ca_cert, ca_key = create_ca( CN=f"{ca_name}"
                                ,C="New Zealand"
                                ,ST="Auckland"
                                ,O="NSP"
                                ,OU="IT"
                                ,keysize=args['keysize'] )
    tlsauth_key=gen_tlsauth_key()
    dh=gen_dhparam_dh()
    #1st create client configs to get count
    if not "vpn_clients" in args.keys():
        args['vpn_clients']=[ {'client': {'name':'DummyClient'} }, ]
        logging.info("no clients found in config creating a dummy config.")

    for client in args['vpn_clients']:
        c = client['client']['count']
        name = client['client']['name']
        make_new_ovpn_file(ca_cert=ca_cert, ca_key=ca_key,
                           tlsauth_key=tlsauth_key, dh=dh,
                           CN=f"{args['prefix']}_{tn}_client_{c}_{name}", serial=random.randint(100, 99999999),
                           commonoptspath=args['template'],
                           filepath=f"{filedir}/{args['prefix']}-{tn}-c{c}-{name}.conf",
                           vpn_servers=args['vpn_servers'],
                           vpn_clients=args['vpn_clients'],
                           this_client=client['client'],
                           this_server={ 'vpn_ip' : args['network'].network_address +c },
                           tap_interface_name=args['tap_interface_name']
                           )

    #2nd create server configs.
    if not "vpn_servers" in args.keys():
        args['vpn_servers']=[ {'server': {'name':'Dummy', 'connect': '10.0.0.1 1194 udp' , 'ip_pool' : 'N.A'}}, ]
        logging.info("no servers found in config creating a dummy config.")

    for server in args['vpn_servers']:
        logging.debug(f"{server['server']=}")
        c = server['server']['count']
        name = server['server']['name']
        make_new_ovpn_file(is_server=True,
                       ca_cert=ca_cert, ca_key=ca_key,
                       tlsauth_key=tlsauth_key, dh=dh,
                       CN=f"{args['prefix']}_{tn}_server_{c}_{name}", serial=random.randint(1, 99),
                       commonoptspath=args['template'],
                       filepath=f"{filedir}/{args['prefix']}-{tn}-s{c}-{name}.conf",
                       vpn_servers=args['vpn_servers'],
                       vpn_clients=args['vpn_clients'],
                       this_server=server['server'],
                       tap_interface_name=args['tap_interface_name']
                       )
    return filedir


if __name__ == "__main__":
    filedir = main()
    print(f"Done - configs in ./{filedir}")


