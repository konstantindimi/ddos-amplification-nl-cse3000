import csv

# Function to filter .nl domains
def filter_nl_domains(input_file, output_file):
    with open(input_file, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        nl_domains = [row for row in reader if row['Domain'].endswith('.nl')]

    if nl_domains:
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['Rank', 'Domain', 'Open Page Rank']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            writer.writerows(nl_domains)
        print(f".nl domains filtered and saved to {output_file}")
    else:
        print("No .nl domains found in the input file.")

# Input and output file paths
input_file = '' #Input file path
output_file = '' #Output file path

filter_nl_domains(input_file, output_file)