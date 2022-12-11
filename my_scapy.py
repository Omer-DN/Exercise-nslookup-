# Omer dayan - 312409386

from scapy.all import *
import sys
from scapy.layers.dns import IP, UDP, DNS, DNSRR, DNSQR

qtype_from_user = sys.argv[1]
domain_or_ip = sys.argv[2]

if qtype_from_user == 'PTR':
    query_list = domain_or_ip.split('.')  # split the ip into a list for reversing.
    reverse_query_list = query_list[::-1]  # getting a reverse list for the ip.
    ip_address = '.'.join(reverse_query_list)  # the reversed ip address.
    ip_address += ".in-addr.arpa"  # ip like the protocol
    packet = IP(dst='8.8.8.8') / UDP(sport=26662, dport=53) / DNS(qdcount=1, rd=1) / DNSQR(qtype=qtype_from_user,
                                                                                           qname=ip_address)
    ans = sr1(packet)
    final_rsp = ans[DNSRR].rdata.decode()  # changing the answer's type from byte to string.
    print(final_rsp)

elif qtype_from_user == 'A':
    packet = IP(dst='8.8.8.8') / UDP(sport=26662, dport=53) / DNS(qdcount=1, rd=1) / DNSQR(qtype=qtype_from_user,
                                                                                           qname=domain_or_ip)
    ans = sr1(packet)
    amount = ans[DNS].ancount  # can be many
    for i in range(amount):  # if there is a canonical name - print it also.
        rsp = ans[DNSRR][i].rdata
        if isinstance(rsp, bytes):  # if the answer's type is byte - change it to string.
            rsp = rsp.decode()
        print(rsp)
