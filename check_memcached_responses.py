import csv
import threading
from scapy.all import *

def valid_memcached_response(packet, ip):
    valid_memcached = (IP in packet and packet[IP].src == ip and UDP in packet and packet[UDP].sport == 11211
                 and len(packet) >= 48 and packet[UDP].dport == 11211)
    return valid_memcached

def send_query(ip):
    dns_servers = ip  # Destination IP address for the DNS server
    query_packet = IP(dst=dns_servers) / UDP(dport=11211, sport=11211) / Raw(load="\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n")

    send(query_packet, verbose=0)
    responses = sniff(lfilter=lambda x: valid_memcached_response(x, ip), timeout=2)
    if responses:
        return True
    else:
        return False

def process_rows(rows, writer):
    for row in rows:
        if send_query(row['ip']):
            writer.writerow(row)

# Read IP addresses from CSV file and send queries
with open('', 'r') as csvfile: #Input file path
    reader = csv.DictReader(csvfile)
    rows = list(reader)
    headers = reader.fieldnames

    # Write to a new CSV file with response status
    with open('', 'w', newline='') as new_csvfile: #Output file path
        writer = csv.DictWriter(new_csvfile, fieldnames=headers)
        writer.writeheader()

        num_threads = 10
        chunk_size = len(rows) // num_threads
        chunks = [rows[i:i+chunk_size] for i in range(0, len(rows), chunk_size)]

        threads = []
        for chunk in chunks:
            thread = threading.Thread(target=process_rows, args=(chunk, writer))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()