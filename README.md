
## Overview of OpenVPN templates.

Define openvpn clients/pc's and servers in conf.yaml e.g. openvpn_sample.conf.yaml.
The script generates a new CA and certificates for all the machines.
It then creates a single self contained openvpn config for each machine.

The client configs contain the server routes.
The servers contain the client subnets that each client allows.

Servers must have reachable IP's, normaly this means public IP's.

https://github.com/diepes/openvpn-inline-config-generator 

1. New CA Certificate (Only public key used to validate pvt signature) private can be destroyed.
2. New Cert and Key for each host/server. (all in single config file)
3. TLS-AUTH psk key used for initial packet auth and ddos mitigation
4. Static routing for all subnets specified for each client.
5. Round robin client to server connections if more than one server.

---
To add a server of client update the conf.yaml file and re-generate new configs for all devices.
This is a way to rotate all keys.

## Software required
 1. python > 3.8
 1. python pip modules , see requirements.yml
 1. openvpn $ sudo apt install openvpn

 # example
 ./src/openvpn_gen.py

## Usage.

1. Edit or create a new openvpn_XXX_conf.yaml.  (See existing for examples)
2. Run generation script ./openvpn-inline-config-generator/openvpn_gen.py -c  openvpn_XXX_conf.yaml
.
