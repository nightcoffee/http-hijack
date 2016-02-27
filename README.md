# http-hijack

Http hijack(redirect to other website) implemented by Golang + gopacket + libpcap

# Requirement
* libpcap
* Switch with port mirroring or Hub

# Use
1. Config switch mirror all traffic to HIJACK computer.
2. Run this application
3. All http response will be replaced with 'Stupid' :)
