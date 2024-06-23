import csv
import dns.resolver

def find_authoritative_ns_ips(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        ns_servers = [str(rdata) for rdata in answers]
        ns_ips = []
        for ns_server in ns_servers:
            ns_ips.extend([str(ip) for ip in dns.resolver.resolve(ns_server, 'A')])
            time.sleep(2)
        return ns_ips
    except dns.resolver.NoAnswer:
        print(f"No authoritative name servers found for {domain}")
        return []
    except dns.resolver.NXDOMAIN:
        print(f"Domain {domain} does not exist")
        return []
    except Exception as e:
        print(f"Error finding authoritative name servers for {domain}: {e}")
        return []
def find_authoritative_ips(input_file, output_file):
    with open(input_file, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        with open(output_file, 'w', newline='') as output_csvfile:
            fieldnames = ['Domain', 'Authoritative Name Server IPs']
            writer = csv.DictWriter(output_csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for row in reader:

                domain = row['Domain']
                authoritative_ns_ips = find_authoritative_ns_ips(domain)
                writer.writerow({'Domain': domain, 'Authoritative Name Server IPs': ', '.join(authoritative_ns_ips)})

        print(f"Authoritative name server IPs for the first 10 domains saved to {output_file}")



# Input and output file paths
input_file = ''
output_file = ''

find_authoritative_ips(input_file, output_file)