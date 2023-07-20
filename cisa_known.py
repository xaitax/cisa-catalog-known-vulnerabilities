import json
import argparse
import os
import requests
import pandas as pd
import seaborn as sns
import aiohttp
import asyncio
from jinja2 import Environment, FileSystemLoader
from termcolor import colored
from collections import Counter
from tqdm import tqdm
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter

class CisaCatalog:
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    LOCAL_FILE = 'known_exploited_vulnerabilities.json'
    ENRICHED_FOLDER = 'cve_details'
    CVE_URL_TEMPLATE = "https://cve.circl.lu/api/cve/{}"
    SEMAPHORE_LIMIT = 10

    def __init__(self):
        '''Initializes the CisaCatalog object by loading the data from a local file or downloading the latest version.'''
        if os.path.isfile(self.LOCAL_FILE):
            with open(self.LOCAL_FILE) as f:
                self.data = json.load(f)
        else:
            print("No local version of the JSON file found. Fetching the latest version...")
            self.download_latest_version()
            with open(self.LOCAL_FILE) as f:
                self.data = json.load(f)


    def print_local_info(self):
        '''Prints information about this program and the local CISA Catalog.'''
        print('')
        print('_________ .___  _________   _____    _________         __         .__                 ')
        print('\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____  ')
        print('/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \\   __ \__  \ |  |  /  _ \ / ___\ ')
        print('\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >')
        print(' \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  / ')
        print('        \/            \/         \/          \/     \/          \/           /_____/  ')
        print('Alexander Hagenah / ah@primepage.de / @xaitax / v 0.5')
        print('')
        print("Title:\t", self.data['title'])
        print("Version:", self.data['catalogVersion'])
        print("Total:\t", self.data['count'], "vulnerabilities")
        print("URL:\t https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
        print("\n")

    def download_latest_version(self):
        '''Downloads the latest version of the CISA Catalog and updates the local file.'''
        try:
            response = requests.get(self.URL)
            response.raise_for_status()
            online_data = json.loads(response.text)
        except requests.exceptions.RequestException as e:
            print("Error while downloading the latest version:", e)
            return

        if not os.path.isfile(self.LOCAL_FILE) or online_data["catalogVersion"] != self.data["catalogVersion"] or online_data["dateReleased"] != self.data["dateReleased"]:
            if not os.path.exists(self.ENRICHED_FOLDER):
                os.makedirs(self.ENRICHED_FOLDER)
            with open(self.LOCAL_FILE, "w") as f:
                json.dump(online_data, f)
            print("Latest CISA database downloaded.")
            asyncio.run(self.download_all_enriched_data(online_data['vulnerabilities']))
            self.data = online_data
        else:
            print("Local version is up-to-date.")

    async def download_enriched_data(self, session, vulnerability, semaphore, progress_bar):
        async with semaphore:
            cve_id = vulnerability['cveID']
            cve_file = f"{self.ENRICHED_FOLDER}/{cve_id}.json"
            if not os.path.exists(cve_file):
                cve_url = self.CVE_URL_TEMPLATE.format(cve_id)
                async with session.get(cve_url) as resp:
                    cve_data = await resp.text()
                with open(cve_file, "w") as f:
                    f.write(cve_data)
            progress_bar.update()

    async def download_all_enriched_data(self, vulnerabilities):
        if not os.path.exists(self.ENRICHED_FOLDER):
            os.makedirs(self.ENRICHED_FOLDER)

        print("Downloading enriched CVE information.")
        semaphore = asyncio.Semaphore(10)
        progress_bar = tqdm(total=len(vulnerabilities))
        async with aiohttp.ClientSession() as session:
            tasks = []
            for vulnerability in vulnerabilities:
                tasks.append(self.download_enriched_data(session, vulnerability, semaphore, progress_bar))
            await asyncio.gather(*tasks)
        progress_bar.close()

    def search(self, field, search_string):
        results = [v for v in self.data['vulnerabilities'] if search_string in v[field]]

        if not results:
            print(colored(f"No results found for the {field}: " + search_string, 'red'))
        else:
            self.print_search_results(results, field, search_string)

    def print_search_results(self, results, field, search_string):
        print("CVEs found: " + colored(str(len(results)), 'green'), )
        for result in results:
            result[field] = result[field].replace(search_string, colored(search_string, 'green'))
            self.print_vulnerability(result)

    def print_vulnerability(self, vulnerability):
        print("\n")
        print("CVE ID:\t", vulnerability['cveID'])
        print("Product:", vulnerability['product'])
        print("Vendor:\t", vulnerability['vendorProject'])
        print("Name:\t", vulnerability['vulnerabilityName'])
        print("Date:\t", vulnerability['dateAdded'])
        print("URL:\t https://nvd.nist.gov/vuln/detail/" + vulnerability['cveID'])
        print("Info:\t", vulnerability['shortDescription'])

    def display_enriched_info(self, cveID):
        enriched_file = f"{self.ENRICHED_FOLDER}/{cveID}.json"
        if os.path.exists(enriched_file):
            with open(enriched_file) as f:
                cve_data = json.load(f)
            json_str = json.dumps(cve_data, indent=4)
            print(highlight(json_str, JsonLexer(), TerminalFormatter()))
        else:
            print(f"{cveID} does not exist in the enriched folder.")

    def display_recent_vulnerabilities(self):
        vulnerabilities = sorted(self.data['vulnerabilities'], key=lambda x: x['dateAdded'], reverse=True)
        print("5 Most Recently Added Vulnerabilities:")
        for i in range(5):
            self.print_vulnerability(vulnerabilities[i])

    def export_data(self):

        df = pd.DataFrame(self.data['vulnerabilities'])

        df['dateAdded'] = pd.to_datetime(df['dateAdded'])

        vendor_counts = df['vendorProject'].value_counts().to_dict()
        product_counts = df['product'].value_counts().to_dict()

        vendor_data = [{"id": k, "name": k, "value": v} for k, v in vendor_counts.items()]
        product_data = [{"name": k, "value": v} for k, v in product_counts.items()]

        date_counts = df['dateAdded'].dt.date.value_counts().sort_index().to_dict()
        date_data = [{"x": pd.Timestamp(k).value // 10**6, "y": v} for k, v in date_counts.items()]

        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('template.html')

        html = template.render(
            vendor_data=vendor_data,
            product_data=product_data,
            date_data=date_data
        )

        with open('export_chart.html', 'w') as f:
            f.write(html)

        print(f"Graph was successfully exported to file 'export_chart.html' in the directory '{os.getcwd()}'.")


    def normalize(self, value, min_value, max_value):
        return (value - min_value) / (max_value - min_value)

    def print_stats(self):
        vendor_projects = [v['vendorProject'] for v in self.data['vulnerabilities']]
        vendor_count = Counter(vendor_projects)
        top_10_vendors = dict(vendor_count.most_common(10))
        print("Top 10 Vendors:")
        for vendor, count in top_10_vendors.items():
            print(vendor + ": " + str(count))

        date_added = [v['dateAdded'][:7] for v in self.data['vulnerabilities']]
        date_count = Counter(date_added)
        top_10_months = dict(date_count.most_common(10))
        print("\nTop 10 Months:")
        for month, count in top_10_months.items():
            print(month + ": " + str(count))

parser = argparse.ArgumentParser(description='Search for a specific product/vendor in the CISA Catalog.')
subparsers = parser.add_subparsers(dest='command')

parser_update = subparsers.add_parser('update', help='Check for updates and download the most recent version')
parser_info = subparsers.add_parser('info', help='Print information about the CISA Catalog')
parser_recent = subparsers.add_parser('recent', help='Show 5 most recent additions to the CISA Catalog')
parser_stats = subparsers.add_parser('stats', help='Print statistics about the CISA Catalog')

parser_product = subparsers.add_parser('product', help='Search for a specific product in the CISA Catalog')
parser_product.add_argument('product', type=str, help='The product to search for')

parser_vendor = subparsers.add_parser('vendor', help='Search for a specific vendor in the CISA Catalog')
parser_vendor.add_argument('vendor', type=str, help='The vendor to search for')

parser_all = subparsers.add_parser('all', help='Search for both product and vendor in the CISA Catalog')
parser_all.add_argument('search_string', type=str, help='The string to search for in both product and vendor')

parser_enriched = subparsers.add_parser('enriched', help='Display detailed information about a CVE')
parser_enriched.add_argument('cveID', type=str, help='The CVE ID to display enriched info for')

parser_export = subparsers.add_parser('export', help='Export the data basic highcharts graphs')

args = parser.parse_args()

if args.command is None:
    parser.print_help()
    exit()

catalog = CisaCatalog()

if args.command == 'update':
    catalog.print_local_info()
    catalog.download_latest_version()
elif args.command == 'info':
    catalog.print_local_info()
elif args.command == 'product':
    catalog.print_local_info()
    catalog.search('product', args.product)
elif args.command == 'vendor':
    catalog.print_local_info()
    catalog.search('vendorProject', args.vendor)
elif args.command == 'all':
    catalog.print_local_info()
    catalog.search('product', args.search_string)
    catalog.search('vendorProject', args.search_string)
elif args.command == 'enriched':
    catalog.print_local_info()
    catalog.display_enriched_info(args.cveID)
elif args.command == 'recent':
    catalog.print_local_info()
    catalog.display_recent_vulnerabilities()
elif args.command == 'stats':
    catalog.print_local_info()
    catalog.print_stats()
elif args.command == 'export':
    catalog.print_local_info()
    catalog.export_data()
else:
    catalog.print_local_info()
