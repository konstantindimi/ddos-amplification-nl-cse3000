import csv
import threading
from scapy.all import *

def send_query(ip):
    ntp_servers = ip
    query_packet = IP(dst=ntp_servers) / UDP(dport=123) / NTPPrivate(mode=7, implementation="XNTPD", request_code="REQ_MON_GETLIST_1")

    response = sr1(query_packet, timeout=2, verbose=False)
    if response:
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
