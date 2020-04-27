This script is only valid for 7.0 and bleow. 

************* For version 7.1 *************

There is now an Ansible playbook which can be used to onboard BIG-IQ easily.

https://github.com/f5devcentral/f5-big-iq-onboarding

using the following galaxy roles:

note: role work with 6.x, 7.0 and 7.1

https://galaxy.ansible.com/f5devcentral/bigiq_onboard 
https://galaxy.ansible.com/f5devcentral/register_dcd 

*********************************************


setup-bigiq.y usage:

setup-bigiq.py -h
usage: setup-bigiq.py [-h] [-d] [-a ADDRESS] [-u USERNAME] [-p PASSWORD]
                      [-P NEWADMINPASS] [-n NAME] [-m MGMT] [-r ROLE]
                      [-s SELF] [-R ROUTE] [-N NTP] [-D DNS] [-k KEY]
                      [-cr CURRENTROOT] [-nr NEWROOTPASS]

Script to deploy iApp for NAT repros to PD

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           enable debug
  -a ADDRESS, --address ADDRESS
                        IP address of BIG-IQ to be setup
  -u USERNAME, --username USERNAME
                        username for auth to BIG-IQ
  -p PASSWORD, --password PASSWORD
                        password for auth to BIG-IQ
  -P NEWADMINPASS, --new-admin-pass NEWADMINPASS
                        New admin password to set
  -n NAME, --name NAME  fully qualified hostname to set for BIG-IQ
  -m MGMT, --mgmt MGMT  Management-ip to set on BIG-IQ x.x.x.x/cidr
  -r ROLE, --role ROLE  Set BIG-IQ role to be big_iq or logging_node
  -s SELF, --self SELF  set selfIP/mask and set it as discovery address
                        192.0.2.100/24
  -R ROUTE, --route ROUTE
                        management-route to set on BIG-IQ
  -N NTP, --ntp NTP     ntp server
  -D DNS, --dns DNS     IP address DNS server
  -k KEY, --key KEY     Masterkey passphrase string
  -cr CURRENTROOT, --current-root-pass CURRENTROOT
                        current root password when setting new root password
  -nr NEWROOTPASS, --new-root NEWROOTPASS
                        New root pass when setting root password
