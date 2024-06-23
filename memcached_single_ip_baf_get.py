from scapy.all import *

def valid_memcached_response(packet, ip):
    valid_memcached = (IP in packet and packet[IP].src == ip and UDP in packet and packet[UDP].sport == 11211
                 and packet[UDP].dport == 11211)
    return valid_memcached

ip = '' #Ip to be tested for BAF
query_packet = IP(dst=ip) / UDP(dport=11211, sport=11211) / Raw(load="\x00\x00\x00\x00\x00\x01\x00\x00get \r\n") #Write the key to be rethrieved after get
send(query_packet, verbose=0)
responses = sniff(lfilter=lambda x: valid_memcached_response(x, ip), timeout=2)

responses[0].show()

response_payload_size = sum(len(resp[UDP].payload) for resp in responses)

if responses:
    # Calculate request payload size
    request_payload_size = len(query_packet[UDP].payload)

    # Calculate BAF
    baf = response_payload_size / request_payload_size



print(response_payload_size)
print(request_payload_size)
print(baf)
