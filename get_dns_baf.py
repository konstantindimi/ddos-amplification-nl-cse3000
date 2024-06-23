from scapy.all import *
import csv
import threading

# Filter for valid responses
def valid_dns_response(packet, ip, query_type_code):
    valid_dns = (IP in packet and packet[IP].src == ip and UDP in packet and packet[UDP].sport == 53 and DNS in packet
                 and packet[DNS].qr == 1 and packet[DNS].rcode in {0, 3, 4, 5})
    if query_type_code != 255:
        return valid_dns
    else:
        return valid_dns or (IP in packet and packet[IP].src == ip and UDP in packet and packet[UDP].sport == 53
                             and Raw in packet and len(packet[Raw].load))
def process_csv_rows(reader, writer):
    for row in reader:
        domain = row['Domain']
        ip = row['Authoritative Name Server IP']
        print(domain)
        print(ip)

        try:
            # Craft DNS request
            dns_request = IP(dst=ip)/UDP(dport=53)/DNS(ad=1, qd=DNSQR(qname=domain, qtype=255), ar=DNSRROPT(z=1, rclass=4096))
            print(dns_request[UDP].show())

            # Send DNS request and receive responses
            send(dns_request, verbose=0)
            responses = sniff(lfilter=lambda x: valid_dns_response(x, ip, 48), timeout=2)

            response_payload_size = sum(len(resp[UDP].payload) for resp in responses)

            if responses:
                # Calculate request payload size
                request_payload_size = len(dns_request[UDP].payload)

                # Calculate BAF
                baf = response_payload_size / request_payload_size

                writer.writerow([domain, ip, request_payload_size, response_payload_size, baf])
            else:
                writer.writerow([domain, ip, 'Error: No response', '', ''])

        except Exception as e:
            # If there's any error, record it in the output file
            writer.writerow([domain, ip, 'Error', str(e), ''])

    print("Thread execution completed.")

def send_dns_requests(input_file, output_file):
    threads = []
    with open(input_file, 'r') as csvfile, open(output_file, 'w', newline='') as outfile:
        reader = csv.DictReader(csvfile)
        writer = csv.writer(outfile)
        writer.writerow(['Domain', 'IP', 'Request Payload Size', 'Response Payload Size', 'BAF'])

        # Split the CSV processing across 10 threads
        for _ in range(10):
            thread = threading.Thread(target=process_csv_rows, args=(reader, writer))
            thread.start()
            threads.append(thread)

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

    print(f"DNS requests completed. Results saved to {output_file}")

# Input and output file paths
input_file = ''  # Replace with your input file path
output_file = ''  # Replace with your desired output file path

# Call the function to send DNS requests
send_dns_requests(input_file, output_file)
