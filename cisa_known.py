import json
import argparse
from termcolor import colored
import requests
import os
from collections import Counter

def update_local_file():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url)
    online_data = json.loads(response.text)

    if os.path.isfile(local_file):
        with open(local_file) as f:
            data = json.load(f)
    else:
        data = online_data
        with open(local_file, 'w') as f:
            json.dump(online_data, f)
        print("Latest version downloaded.")

    if online_data["catalogVersion"] != data["catalogVersion"] or online_data["dateReleased"] != data["dateReleased"]:
        answer = input("Newer version found online. Update? (yes/no)")
        if answer == "yes":
            # Download the most recent version
            with open(local_file, "w") as f:
                json.dump(online_data, f)
            print("Latest version downloaded.")
            data = online_data
        else:
            print("Using the local version.")
    else:
        print("Local version is up-to-date.")
    return data

def search_product(data, search_string):
    results = []
    for vulnerability in data['vulnerabilities']:
        if search_string in vulnerability['product']:
            results.append(vulnerability)

    if not results:
        print(colored("No results found for the product: " + search_string, 'red'))
    else:
        print("CVEs found: " + colored(str(len(results)), 'green'), )
        for result in results:
            print("\n")
            print("CVE ID:\t", result['cveID'])
            print("Product:", result['product'].replace(search_string, colored(search_string, 'green')))
            print("Vendor:\t", result['vendorProject'])
            print("Name:\t", result['vulnerabilityName'])
            print("Date:\t", result['dateAdded'])
            print("URL:\t https://nvd.nist.gov/vuln/detail/" + result['cveID'])
            print("Info:\t", result['shortDescription'])
            

def search_vendor(data, search_string):
    results = []
    for vulnerability in data['vulnerabilities']:
        if search_string in vulnerability['vendorProject']:
            results.append(vulnerability)

    if not results:
        print(colored("No results found for the vendor: " + search_string, 'red'))
    else:
        print("CVEs found: " + colored(str(len(results)), 'green'), )
        for result in results:
            print("\n")
            print("CVE ID:\t", result['cveID'])
            print("Product:", result['product'])
            print("Vendor:\t", result['vendorProject'].replace(search_string, colored(search_string, 'green')))
            print("Name:\t", result['vulnerabilityName'])
            print("Date:\t", result['dateAdded'])
            print("Info:\t", result['shortDescription'])
            

def search_all(data, search_string):
    results = []
    for vulnerability in data['vulnerabilities']:
        if search_string in vulnerability['product'] or search_string in vulnerability['vendorProject']:
            results.append(vulnerability)

    if not results:
        print(colored("No results found for the string: " + search_string, 'red'))
    else:
        print("CVEs found: " + colored(str(len(results)), 'green'), )
        for result in results:
            print("\n")
            print("CVE ID:\t", result['cveID'])
            print("Product:", result['product'])
            print("Vendor:\t", result['vendorProject'])
            print("Name:\t", result['vulnerabilityName'])
            print("Date:\t", result['dateAdded'])
            print("Info:\t", result['shortDescription'])

def print_local_info(data):
    print('')
    print('_________ .___  _________   _____    _________         __         .__                 ')
    print('\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____  ')
    print('/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \\   __ \__  \ |  |  /  _ \ / ___\ ')
    print('\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >')
    print(' \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  / ')
    print('        \/            \/         \/          \/     \/          \/           /_____/  ')
    print('Alexander Hagenah / ah@primepage.de / @xaitax / v.1')
    print('')
    print("Title:\t", data['title'])
    print("Version:", data['catalogVersion'])
    print("Total Vulnerabilities:", data['count'])
    print("URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog")

def print_stats(data):
    vendor_projects = [vulnerability['vendorProject'] for vulnerability in data['vulnerabilities']]
    vendor_count = Counter(vendor_projects)
    top_10_vendors = dict(vendor_count.most_common(10))
    print("Top 10 Vendors:")
    for vendor, count in top_10_vendors.items():
        print(vendor + ": " + str(count))
    
    date_added = [vulnerability['dateAdded'][:7] for vulnerability in data['vulnerabilities']]
    date_count = Counter(date_added)
    top_10_months = dict(date_count.most_common(10))
    print("\nTop 10 Months:")
    for month, count in top_10_months.items():
        print(month + ": " + str(count))

parser = argparse.ArgumentParser(description='Search for a specific product/vendor in the CISA Catalog.')
parser.add_argument('-p', '--product', type=str, help='The product to search for')
parser.add_argument('-v', '--vendor', type=str, help='The vendor to search for')
parser.add_argument('-a', '--all', type=str, help='Search for both product and vendor in the CISA Catalog')
parser.add_argument('-u', '--update', action='store_true', help='Check for updates and download the most recent version')
parser.add_argument('-i', '--info', action='store_true', help='Print information about the CISA Catalog')
parser.add_argument('-s', '--stats', action='store_true', help='Print statistics about the CISA Catalog')
args = parser.parse_args()

local_file = 'known_exploited_vulnerabilities.json'

if args.update:
    data = update_local_file()
else:
    if os.path.isfile(local_file):
        with open(local_file) as f:
            data = json.load(f)
    else:
        print("No local version of the JSON file found. Please run the script with the '-u' option to download the latest version.")
        exit()

if args.stats:
    print_stats(data)
elif args.info:
    print_local_info(data)
elif args.product is not None:
    search_string = args.product
    search_product(data, search_string)
elif args.vendor is not None:
    search_string = args.vendor
    search_vendor(data, search_string)
elif args.all is not None:
    search_string = args.all
    search_all(data, search_string)
else:
    print_local_info(data)

