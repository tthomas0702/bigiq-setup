#!/usr/bin/python3

# Tim Thomas 2018
# Ver 0.0.4

import argparse
import json
import http.client
# import urllib
import ast
import sys
from pprint import pprint

# disable ssl cert verfiy
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

parser = argparse.ArgumentParser(
        description='Script to deploy iApp for NAT repros to PD')

parser.add_argument('-l',
                    '--list',
                    action="store_true",
                    default=False,
                    help='list currently deployed nats')

parser.add_argument('-d',
                    '--debug',
                    action="store_true",
                    default=False,
                    help='enable debug')

parser.add_argument('-a',
                    '--address',
                    action="store",
                    dest="address",
                    default='10.154.164.129',
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

parser.add_argument('-c',
                    '--create',
                    action="store",
                    dest="create",
                    help='Create and deploy nat Iapp, take name as arg and \
                            requires --nat and --managmenet-ip')

parser.add_argument('-n',
                    '--name',
                    action="store",
                    dest="name",
                    help='fully qualified hostname')

parser.add_argument('-m',
                    '--mgmt',
                    action="store",
                    dest="mgmt",
                    help='Management-ip of BIG-IQ')

parser.add_argument('-r',
                    '--role',
                    action="store",
                    dest="role",
                    default='big_iq',
                    help='Set to be big_iq or logging_node')

parser.add_argument('-s',
                    '--self',
                    action="store",
                    dest="self",
                    help='selfIP/mask and set it as \
                            discovery address 10.1.212.100/16')

parser.add_argument('-R',
                    '--route',
                    action="store",
                    dest="route",
                    help='management-route')

parser.add_argument('-N',
                    '--ntp',
                    action="store",
                    dest="ntp",
                    default='192.168.11.168',
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

if opt.debug is True:
    print(opt)


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
                 "password": password,
                 "loginProviderName": "tmos"}
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

# master key POST
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


# skipping admin pass for now

# skipping root pass for now

# PATCH {"isSystemSetup":true}
print("Setting setup finished")
url = '/mgmt/shared/system/setup'
data = {"isSystemSetup": True}
setup_done = patch(opt.address, url, auth_token, data)


#  PATCH {"restart":true}
print("restarting system")
url = '/mgmt/shared/failover-state'
t = 'true'
data = {"restart":t}
restart_result = patch(opt.address, url, auth_token, data)


# test command
# setup-bigiq.py -a 10.3.212.100 -n bigiq-bed1.hiep.piv -R 10.3.254.254 -r big_iq -m 10.3.212.100/16 -s 10.1.212.100/16 -k Big-iq12345678910


