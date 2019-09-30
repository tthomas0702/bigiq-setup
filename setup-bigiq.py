#!/usr/bin/python3

'''
File name: setup-bigiq.py
Author: Tim Thomas
Date created: 4/28/2018
Date last modified: 4/29/2018
Python Version: 3.6.5
version:
    0.0.6
    0.0.7 fix auth token, removed  'loginProviderName': 'local'  
    0.0.8 added cidr example to -mgmt help 

Example:
./setup-bigiq.py \
    --address 192.0.2.100 \
    --name bigiq-bed1.example.com \
    --route 192.0.2.254 \
    --role big_iq \
    --mgmt 192.0.2.100/24 \
    --self 192.0.2.100/24 \
    --key passExample-ou812 \
    --new-admin-pass fakepass \
    --current-root-pass fakepass \
    --new-root newpass



'''

import argparse
import json
import http.client
import re
import sys
from pprint import pprint
# disable ssl cert verfiy
import ssl
ssl._create_default_https_context = ssl._create_unverified_context


parser = argparse.ArgumentParser(
        description='Script to deploy iApp for NAT repros to PD')

parser.add_argument('-d',
                    '--debug',
                    action="store_true",
                    default=False,
                    help='enable debug')

parser.add_argument('-a',
                    '--address',
                    action="store",
                    dest="address",
                    help='IP address of BIG-IQ to be setup')

parser.add_argument('-u',
                    '--username',
                    action="store",
                    dest="username",
                    default='admin',
                    help='username for auth to BIG-IQ')

parser.add_argument('-p',
                    '--password',
                    action="store",
                    dest="password",
                    default='admin',
                    help='password for auth to BIG-IQ')

parser.add_argument('-P',
                    '--new-admin-pass',
                    action="store",
                    dest="newAdminPass",
                    #default='admin',
                    help='New admin password to set')

parser.add_argument('-n',
                    '--name',
                    action="store",
                    dest="name",
                    help='fully qualified hostname to set for BIG-IQ')

parser.add_argument('-m',
                    '--mgmt',
                    action="store",
                    dest="mgmt",
                    help='Management-ip  to set on BIG-IQ x.x.x.x/cidr')

parser.add_argument('-r',
                    '--role',
                    action="store",
                    dest="role",
                    default='big_iq',
                    help='Set BIG-IQ role to be big_iq or logging_node')

parser.add_argument('-s',
                    '--self',
                    action="store",
                    dest="self",
                    help='set selfIP/mask and set it as \
                            discovery address 192.0.2.100/24')

parser.add_argument('-R',
                    '--route',
                    action="store",
                    dest="route",
                    help='management-route to set on BIG-IQ')

parser.add_argument('-N',
                    '--ntp',
                    action="store",
                    dest="ntp",
                    default='172.23.241.134',
                    help='ntp server')

parser.add_argument('-D',
                    '--dns',
                    action="store",
                    dest="dns",
                    default='10.3.254.53',
                    help='IP address DNS server')

parser.add_argument('-k',
                    '--key',
                    action="store",
                    dest="key",
                    #default="Big-iq12345678910",
                    help='Masterkey passphrase string')

parser.add_argument('-cr',
                    '--current-root-pass',
                    action="store",
                    dest="currentRoot",
                    help='current root password when setting new root \
                            password')

parser.add_argument('-nr',
                    '--new-root',
                    action="store",
                    dest="newrootPass",
                    help='New root pass when setting root password')


opt = parser.parse_args()

# required opts
if opt.name is None:
    parser.error("-n fqdn required")

if opt.address is None:
    parser.error("-a target BIG-IQ address is required")

if opt.route is None:
    parser.error("-R mgmt route required")

if opt.mgmt is None:
    parser.error("-m managmet-ip is required, x.x.x.x/cidr")


# root old and new pass required together
if opt.currentRoot or opt.newrootPass is not None:
    if opt.currentRoot is None or opt.newrootPass is None:
        print("Both --current-root and --new-root are required when setting \
                new root password")
        sys.exit()


if opt.debug is True:
    print(opt)

# make sure -n value is FQDN
def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

if is_valid_hostname(opt.name) is False:
    parser.error("-n value provided does not conform to FQDN standards")



def get(address, url, auth_token):
    headers = {'Content-type': 'application/json',
               'X-F5-Auth-Token': auth_token}
    try:
        connection = http.client.HTTPSConnection(address)
        connection.request('GET', url, headers=headers)
    except ConnectionError:
        print('ConnectionError')
        sys.exit(0)
    except:
        raise
        sys.exit(0)
    r1 = connection.getresponse()
    data1 = r1.read()
    return data1.decode("utf-8")


def delete(address, url, auth_token):
    headers = {'Content-type': 'application/json',
               'X-F5-Auth-Token': auth_token}
    try:
        connection = http.client.HTTPSConnection(address)
        connection.request('DELETE', url, headers=headers)
    except ConnectionError:
        print('ConnectionError')
        sys.exit(0)
    except:
        raise
        sys.exit(0)
    r1 = connection.getresponse()
    data1 = r1.read()
    return data1.decode("utf-8")


def get_auth_token(username, password, address):
    headers = {'Content-type': 'application/json'}
    post_dict = {"username": username,
                 "password": password}
    post_json = json.dumps(post_dict)
    try:
        connection = http.client.HTTPSConnection(opt.address)
        connection.request(
                'POST',
                '/mgmt/shared/authn/login',
                post_json,
                headers=headers)
    except ConnectionError:
        print('ConnectionError')
        sys.exit(0)
    except:
        raise
        sys.exit(0)
    r1 = connection.getresponse()
    data1 = r1.read()
    data_dict = json.loads(data1.decode("utf-8"))
    token = data_dict['token']['token']
    return token


def post(address, url, auth_token, post_data):
    headers = {'Content-type': 'application/json',
               'X-F5-Auth-Token': auth_token}
    post_json = json.dumps(post_data)
    try:
        connection = http.client.HTTPSConnection(address)
        connection.request('POST', url, post_json, headers)
    except ConnectionError:
        print('ConnectionError')
        sys.exit(0)
    except:
        raise
        sys.exit(0)
    r1 = connection.getresponse()
    if opt.debug:
        print(r1.status)
        print(r1.reason)
    if r1.status != 200:
        print(r1.status)
        print(r1.reason)
        #sys.exit(1)
    data1 = r1.read()
    return data1.decode("utf-8")


def patch(address, url, auth_token, patch_data):
    headers = {'Content-type': 'application/json',
               'X-F5-Auth-Token': auth_token}
    patch_json = json.dumps(patch_data)
    try:
        connection = http.client.HTTPSConnection(address)
        connection.request('PATCH', url, patch_json, headers)
    except ConnectionError:
        print('ConnectionError')
        sys.exit(0)
    except:
        raise
        sys.exit(0)
    r1 = connection.getresponse()
    if opt.debug:
        print(r1.status)
        print(r1.reason)
    if r1.status != 200:
        print(r1.status)
        print(r1.reason)
        sys.exit(1)
    data1 = r1.read()
    return data1.decode("utf-8")


def put(address, url, auth_token, put_data):
    headers = {'Content-type': 'application/json',
               'X-F5-Auth-Token': auth_token}
    put_json = json.dumps(put_data)
    try:
        connection = http.client.HTTPSConnection(address)
        connection.request('PUT', url, put_json, headers)
    except ConnectionError:
        print('ConnectionError')
        sys.exit(0)
    except:
        raise
        sys.exit(0)
    r1 = connection.getresponse()
    if opt.debug:
        print(r1.status)
        print(r1.reason)
    if r1.status != 200:
        print(r1.status)
        print(r1.reason)
        sys.exit(1)
    data1 = r1.read()
    return data1.decode("utf-8")


# get auth_token, need thisd for every operation
auth_token = get_auth_token(opt.username, opt.password, opt.address)


# set personality
data = {"systemPersonality": opt.role}
print("setting ", data)
url = '/mgmt/cm/system/provisioning'
set_personality = post(
                        opt.address,
                        url,
                        auth_token,
                        data)


# easy-setup
if opt.self:
    discovery = opt.self.split('/')[0]
    selfIp = opt.self
else:
    selfIp = None

data = {
        "hostname": opt.name,
        "managementIpAddress": opt.mgmt,
        "managementRouteAddress": opt.route,
        "internalSelfIpAddresses": [selfIp],
        "ntpServerAddresses": [opt.ntp],
        "dnsServerAddresses": [opt.dns],
        "dnsSearchDomains": ["localhost"]
        }

if opt.self is None:
    data["internalSelfIpAddresses"] = []

url = '/mgmt/shared/system/easy-setup'
print("Doing easy-setup")
pprint(data)
easy_result = patch(opt.address, url, auth_token, data)

# set discovery
try:
    if discovery:
        print("Setting discovery ", discovery)
        url = '/mgmt/shared/identified-devices/config/discovery'
        data = {"discoveryAddress": discovery}
        set_discovery = put(
                            opt.address,
                            url,
                            auth_token,
                            data)
except NameError:
    print("Not setting discovery address")

# check if masterkey set
url = '/mgmt/cm/shared/secure-storage/masterkey'
mk_result = json.loads(get(opt.address, url, auth_token))
mk_set_status = mk_result["isMkSet"]
print("isMkSet is:", mk_set_status)
# set master key if not net
if mk_set_status is False:
    if opt.key is None:
        print("Masterkey is not set yet, -k <passphrase is required")
        sys.exit()
    else:
        print("Setting Masterkey")
        url = '/mgmt/cm/shared/secure-storage/masterkey'
        data = {"passphrase": opt.key}
        master_set_result = post(
                        opt.address,
                        url,
                        auth_token,
                        data)
else:
    if opt.key is not None:
        print("Masterkey can only be set once, not setting")


# admin password PUT
if opt.newAdminPass:
    print("Setting admin password")
    url = '/mgmt/shared/authz/users'
    data = {
            "name": "admin",
            "displayName": "Admin User",
            "oldPassword": opt.password,
            "password": opt.newAdminPass,
            "password2": opt.newAdminPass
            }
    set_admin_pass = json.loads(put(opt.address, url, auth_token, data))


# POST root pass
if opt.newrootPass:
    url = '/mgmt/shared/authn/root'
    data = {"oldPassword": opt.currentRoot, "newPassword": opt.newrootPass}

    set_result = json.loads(post(opt.address, url, auth_token, data))
    try:
        if set_result['code'] == 400:
            print("Error setting root password, not setting")
            print(set_result["message"])
    except:
        print("Setting new root password")

# PATCH {"isSystemSetup":true}
print("Setup finished")
url = '/mgmt/shared/system/setup'
data = {"isSystemSetup": True}
setup_done = patch(opt.address, url, auth_token, data)


#  PATCH {"restart":true}
print("restarting system...")
url = '/mgmt/shared/failover-state'
t = 'true'
data = {"restart": t}
restart_result = patch(opt.address, url, auth_token, data)
