import pandas as pd
from ipwhois import IPWhois
from concurrent.futures import ThreadPoolExecutor

# Load the CSV file
df = pd.read_csv('') #Input file path

# Function to get ASN for an IP
def get_asn(ip):
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        print(result['asn'])
        return result['asn']
    except Exception as e:
        print(f"Error fetching ASN for {ip}: {e}")
        return None

def process_ips(row):
    row['ASN'] = get_asn(row['ip'])
    return row

with ThreadPoolExecutor(max_workers=10) as executor:
    df = list(executor.map(process_ips, df.to_dict(orient='records')))

df = pd.DataFrame(df) #Output file path

df.to_csv('', index=False)

