#!/usr/bin/env python3
"""
CISA Known Exploited Vulnerabilities Catalog Tool
Alexander Hagenah / ah@primepage.de / @xaitax
"""

import argparse
import asyncio
import json
import os
from collections import Counter
from typing import Any, Dict, List, Optional

import aiohttp
import pandas as pd
import requests
from jinja2 import Environment, FileSystemLoader
from pygments import highlight
from pygments.formatters import TerminalFormatter
from pygments.lexers import JsonLexer
from termcolor import colored
from tqdm import tqdm


class CisaCatalog:
    URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    LOCAL_FILE: str = "known_exploited_vulnerabilities.json"
    ENRICHED_FOLDER: str = "cve_details"
    CVE_URL_TEMPLATE: str = "https://cve.circl.lu/api/cve/{}"
    SEMAPHORE_LIMIT: int = 10

    def __init__(self) -> None:
        if os.path.isfile(self.LOCAL_FILE):
            try:
                with open(self.LOCAL_FILE, "r") as f:
                    self.data: Dict[str, Any] = json.load(f)
            except Exception as e:
                print(colored(f"Error reading {self.LOCAL_FILE}: {e}", "red"))
                self.data = {}
        else:
            self.data = {}
            print(colored("No local version found. Please run the 'update' command to download the latest version.", "yellow"))

    def print_local_info(self) -> None:
        print("")
        print("_________ .___  _________   _____    _________         __         .__                 ")
        print(r"\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____  ")
        print(r"/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \\   __ \__  \ |  |  /  _ \ / ___\ ")
        print(r"\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >")
        print(r" \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  / ")
        print(r"        \/            \/         \/          \/     \/          \/           /_____/  ")
        print("Alexander Hagenah / ah@primepage.de / @xaitax / v 0.5")
        print("")

        title = self.data.get("title", "N/A")
        version = self.data.get("catalogVersion", "N/A")
        count = self.data.get("count", "N/A")
        print("Title:\t", title)
        print("Version:", version)
        print("Total:\t", count, "vulnerabilities")
        print("URL:\t https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
        print("\n")

    def fetch_online_data(self) -> Optional[Dict[str, Any]]:
        try:
            response = requests.get(self.URL, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(colored(f"Error fetching online data: {e}", "red"))
            return None

    def download_latest_version(self) -> None:
        online_data = self.fetch_online_data()
        if online_data is None:
            print(colored("Failed to fetch online data. Update aborted.", "red"))
            return

        update_needed = False
        if not os.path.exists(self.LOCAL_FILE) or not self.data:
            update_needed = True
        else:
            local_version = self.data.get("catalogVersion")
            local_date = self.data.get("dateReleased")
            online_version = online_data.get("catalogVersion")
            online_date = online_data.get("dateReleased")
            if online_version != local_version or online_date != local_date:
                update_needed = True

        if update_needed:
            if not os.path.exists(self.ENRICHED_FOLDER):
                os.makedirs(self.ENRICHED_FOLDER)
            try:
                with open(self.LOCAL_FILE, "w") as f:
                    json.dump(online_data, f, indent=2)
                print(colored("Latest CISA database downloaded.", "green"))
            except Exception as e:
                print(colored(f"Error writing to {self.LOCAL_FILE}: {e}", "red"))
                return

            self.data = online_data
            vulnerabilities: List[Dict[str, Any]] = online_data.get("vulnerabilities", [])
            asyncio.run(self.download_all_enriched_data(vulnerabilities))
        else:
            print(colored("Local version is up-to-date.", "green"))

    async def download_enriched_data(
        self,
        session: aiohttp.ClientSession,
        vulnerability: Dict[str, Any],
        semaphore: asyncio.Semaphore,
        progress_bar: tqdm,
    ) -> None:
        async with semaphore:
            cve_id: str = vulnerability.get("cveID", "")
            if not cve_id:
                progress_bar.update(1)
                return

            cve_file = os.path.join(self.ENRICHED_FOLDER, f"{cve_id}.json")
            if not os.path.exists(cve_file):
                cve_url = self.CVE_URL_TEMPLATE.format(cve_id)
                try:
                    async with session.get(cve_url) as resp:
                        if resp.status == 200:
                            cve_data = await resp.text()
                            with open(cve_file, "w") as f:
                                f.write(cve_data)
                        else:
                            print(colored(f"Warning: Received status code {resp.status} for {cve_id}", "yellow"))
                except Exception as e:
                    print(colored(f"Error fetching enriched data for {cve_id}: {e}", "red"))
            progress_bar.update(1)

    async def download_all_enriched_data(self, vulnerabilities: List[Dict[str, Any]]) -> None:
        if not os.path.exists(self.ENRICHED_FOLDER):
            os.makedirs(self.ENRICHED_FOLDER)

        print("Downloading enriched CVE information...")
        semaphore = asyncio.Semaphore(self.SEMAPHORE_LIMIT)
        progress_bar = tqdm(total=len(vulnerabilities), desc="Enriched CVE downloads")
        async with aiohttp.ClientSession() as session:
            tasks = [
                self.download_enriched_data(session, vulnerability, semaphore, progress_bar)
                for vulnerability in vulnerabilities
            ]
            await asyncio.gather(*tasks)
        progress_bar.close()

    def search(self, field: str, search_string: str) -> None:
        vulnerabilities = self.data.get("vulnerabilities", [])
        results = [
            v for v in vulnerabilities if search_string.lower() in v.get(field, "").lower()
        ]
        if not results:
            print(colored(f"No results found for {field}: {search_string}", "red"))
        else:
            self.print_search_results(results, field, search_string)

    def print_search_results(self, results: List[Dict[str, Any]], field: str, search_string: str) -> None:
        print("CVEs found: " + colored(str(len(results)), "green"))
        for result in results:
            # Create a highlighted version of the field value without modifying the original data.
            original_value = result.get(field, "")
            highlighted_value = original_value.replace(search_string, colored(search_string, "green"))
            self.print_vulnerability(result, highlight_field=(field, highlighted_value))

    def print_vulnerability(self, vulnerability: Dict[str, Any], highlight_field: Optional[tuple] = None) -> None:
        print("\n" + "-" * 50)
        print("CVE ID:\t", vulnerability.get("cveID", "N/A"))

        product = vulnerability.get("product", "N/A")
        vendor = vulnerability.get("vendorProject", "N/A")
        if highlight_field:
            field_name, highlighted_value = highlight_field
            if field_name == "product":
                product = highlighted_value
            elif field_name == "vendorProject":
                vendor = highlighted_value

        print("Product:", product)
        print("Vendor:\t", vendor)
        print("Name:\t", vulnerability.get("vulnerabilityName", "N/A"))
        print("Date:\t", vulnerability.get("dateAdded", "N/A"))
        print("URL:\t", "https://nvd.nist.gov/vuln/detail/" + vulnerability.get("cveID", ""))
        print("Info:\t", vulnerability.get("shortDescription", "N/A"))
        print("-" * 50)

    def display_enriched_info(self, cveID: str) -> None:
        cve_file = os.path.join(self.ENRICHED_FOLDER, f"{cveID}.json")
        if os.path.exists(cve_file):
            try:
                with open(cve_file, "r") as f:
                    cve_data = json.load(f)
                json_str = json.dumps(cve_data, indent=4)
                print(highlight(json_str, JsonLexer(), TerminalFormatter()))
            except Exception as e:
                print(colored(f"Error reading enriched info for {cveID}: {e}", "red"))
        else:
            print(colored(f"Enriched data for {cveID} not found.", "red"))

    def display_recent_vulnerabilities(self) -> None:
        vulnerabilities = self.data.get("vulnerabilities", [])
        if not vulnerabilities:
            print(colored("No vulnerabilities data available.", "red"))
            return
        vulnerabilities_sorted = sorted(vulnerabilities, key=lambda x: x.get("dateAdded", ""), reverse=True)
        print("5 Most Recently Added Vulnerabilities:")
        for vulnerability in vulnerabilities_sorted[:5]:
            self.print_vulnerability(vulnerability)

    def export_data(self) -> None:
        vulnerabilities = self.data.get("vulnerabilities", [])
        if not vulnerabilities:
            print(colored("No vulnerabilities data to export.", "red"))
            return

        df = pd.DataFrame(vulnerabilities)

        if "dateAdded" in df.columns:
            df["dateAdded"] = pd.to_datetime(df["dateAdded"], errors="coerce")

        vendor_counts = df["vendorProject"].value_counts().to_dict() if "vendorProject" in df.columns else {}
        product_counts = df["product"].value_counts().to_dict() if "product" in df.columns else {}

        vendor_data = [{"id": k, "name": k, "value": v} for k, v in vendor_counts.items()]
        product_data = [{"name": k, "value": v} for k, v in product_counts.items()]

        if "dateAdded" in df.columns:
            date_counts = df["dateAdded"].dt.date.value_counts().sort_index().to_dict()
        else:
            date_counts = {}
        date_data = [{"x": int(pd.Timestamp(k).value // 10 ** 6), "y": v} for k, v in date_counts.items()]

        try:
            env = Environment(loader=FileSystemLoader("."))
            template = env.get_template("template.html")
        except Exception as e:
            print(colored(f"Error loading template.html: {e}", "red"))
            return

        html = template.render(
            vendor_data=vendor_data, product_data=product_data, date_data=date_data
        )

        output_file = "export_chart.html"
        try:
            with open(output_file, "w") as f:
                f.write(html)
            print(colored(f"Graph exported successfully to '{os.path.abspath(output_file)}'", "green"))
        except Exception as e:
            print(colored(f"Error writing {output_file}: {e}", "red"))

    def print_stats(self) -> None:
        vulnerabilities = self.data.get("vulnerabilities", [])
        if not vulnerabilities:
            print(colored("No vulnerabilities data available.", "red"))
            return

        vendor_projects = [v.get("vendorProject", "") for v in vulnerabilities]
        vendor_count = Counter(vendor_projects)
        top_10_vendors = vendor_count.most_common(10)
        print("Top 10 Vendors:")
        for vendor, count in top_10_vendors:
            print(f"{vendor}: {count}")

        # Count by month (YYYY-MM)
        date_added = [v.get("dateAdded", "")[:7] for v in vulnerabilities if v.get("dateAdded")]
        date_count = Counter(date_added)
        top_10_months = date_count.most_common(10)
        print("\nTop 10 Months:")
        for month, count in top_10_months:
            print(f"{month}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Search and analyze the CISA Known Exploited Vulnerabilities Catalog."
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("update", help="Check for updates and download the most recent version")
    subparsers.add_parser("info", help="Print information about the CISA Catalog")
    subparsers.add_parser("recent", help="Show 5 most recent additions to the CISA Catalog")
    subparsers.add_parser("stats", help="Print statistics about the CISA Catalog")

    parser_product = subparsers.add_parser("product", help="Search for a specific product in the CISA Catalog")
    parser_product.add_argument("product", type=str, help="The product to search for")

    parser_vendor = subparsers.add_parser("vendor", help="Search for a specific vendor in the CISA Catalog")
    parser_vendor.add_argument("vendor", type=str, help="The vendor to search for")

    parser_all = subparsers.add_parser("all", help="Search for both product and vendor in the CISA Catalog")
    parser_all.add_argument("search_string", type=str, help="The string to search for in both product and vendor")

    parser_enriched = subparsers.add_parser("enriched", help="Display detailed information about a CVE")
    parser_enriched.add_argument("cveID", type=str, help="The CVE ID to display enriched info for")

    parser_export = subparsers.add_parser("export", help="Export the data to basic Highcharts graphs")

    args = parser.parse_args()

    catalog = CisaCatalog()

    if args.command == "update":
        catalog.print_local_info()
        catalog.download_latest_version()
    elif args.command == "info":
        catalog.print_local_info()
    elif args.command == "product":
        catalog.print_local_info()
        catalog.search("product", args.product)
    elif args.command == "vendor":
        catalog.print_local_info()
        catalog.search("vendorProject", args.vendor)
    elif args.command == "all":
        catalog.print_local_info()
        catalog.search("product", args.search_string)
        catalog.search("vendorProject", args.search_string)
    elif args.command == "enriched":
        catalog.print_local_info()
        catalog.display_enriched_info(args.cveID)
    elif args.command == "recent":
        catalog.print_local_info()
        catalog.display_recent_vulnerabilities()
    elif args.command == "stats":
        catalog.print_local_info()
        catalog.print_stats()
    elif args.command == "export":
        catalog.print_local_info()
        catalog.export_data()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
