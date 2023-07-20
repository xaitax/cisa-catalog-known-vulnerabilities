# CISA Catalog of Known Exploited Vulnerabilities

<img src="https://upload.wikimedia.org/wikipedia/commons/1/1f/CISA_Logo.png" height="300">

The script, which is designed to be user-friendly and efficient, allows users to search through the CISA Catalog database offline for specific products or vendors, and then displays detailed information about any vulnerabilities that have been identified in those products or by those vendors. The information that is displayed also includes the vulnerability's Common Vulnerabilities and Exposures (CVE) number including a link to the NIST database.
It also features the possibility to display enhanced information about specific CVEs.

This script is particularly useful for organizations and individuals that are required to comply with the new directive issued by the Cybersecurity & Infrastructure Security Agency (CISA), which mandates that federal agencies patch known vulnerability exploits as soon as possible. This directive is intended to help protect the government's networks and systems from cyber attacks by reducing the number of known vulnerabilities that can be exploited.

As part of this directive, CISA is also publishing a list of known vulnerability exploits to aid in this effort. This list is publicly available and can be accessed via the CISA website at https://www.cisa.gov/known-exploited-vulnerabilities-catalog. The list is regularly updated as new vulnerabilities are discovered and can be used as a reference for organizations and individuals to identify known vulnerabilities and take appropriate action to mitigate the risks associated with them.

# Functionality

The script offers the following possibilities:

## Info

```
$ python cisa_known.py info

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.5

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.07.19
Total:   975 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog
```

## Help

```
$ python cisa_known.py -h
usage: cisa_known.py [-h] {update,info,recent,stats,product,vendor,all,enriched,export} ...

Search for a specific product/vendor in the CISA Catalog.

positional arguments:
  {update,info,recent,stats,product,vendor,all,enriched,export}
    update              Check for updates and download the most recent version
    info                Print information about the CISA Catalog
    recent              Show 5 most recent additions to the CISA Catalog
    stats               Print statistics about the CISA Catalog
    product             Search for a specific product in the CISA Catalog
    vendor              Search for a specific vendor in the CISA Catalog
    all                 Search for both product and vendor in the CISA Catalog
    enriched            Display detailed information about a CVE
    export              Export the data basic highcharts graphs

options:
  -h, --help            show this help message and exit
```

## Product Search

```
$ python cisa_known.py product "Office"

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.5

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.07.19
Total:   975 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog


CVEs found: 31


CVE ID:  CVE-2018-0798
Product: Office
Vendor:  Microsoft
Name:    Microsoft Office Memory Corruption Vulnerability
Date:    2021-11-03
URL:     https://nvd.nist.gov/vuln/detail/CVE-2018-0798
Info:    Microsoft Office contains a memory corruption vulnerability due to the way objects are handled in memory. Successful exploitation allows for remote code execution in the context of the current user. This vulnerability is known to be chained with CVE-2018-0802.


CVE ID:  CVE-2018-0802
Product: Office
Vendor:  Microsoft
Name:    Microsoft Office Memory Corruption Vulnerability
Date:    2021-11-03
URL:     https://nvd.nist.gov/vuln/detail/CVE-2018-0802
Info:    Microsoft Office contains a memory corruption vulnerability due to the way objects are handled in memory. Successful exploitation allows for remote code execution in the context of the current user. This vulnerability is known to be chained with CVE-2018-0798.

[...]
```

## Vendor Search

```
$ python cisa_known.py vendor "Adobe"

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.5

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.07.19
Total:   975 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog


CVEs found: 60


CVE ID:  CVE-2021-21017
Product: Acrobat and Reader
Vendor:  Adobe
Name:    Adobe Acrobat and Reader Heap-based Buffer Overflow Vulnerability
Date:    2021-11-03
URL:     https://nvd.nist.gov/vuln/detail/CVE-2021-21017
Info:    Acrobat Acrobat and Reader contain a heap-based buffer overflow vulnerability that could allow an unauthenticated attacker to achieve code execution in the context of the current user.


CVE ID:  CVE-2021-28550
Product: Acrobat and Reader
Vendor:  Adobe
Name:    Adobe Acrobat and Reader Use-After-Free Vulnerability
Date:    2021-11-03
URL:     https://nvd.nist.gov/vuln/detail/CVE-2021-28550
Info:    Adobe Acrobat and Reader contains a use-after-free vulnerability that could allow an unauthenticated attacker to achieve code execution in the context of the current user.

[...]
```

## Detailed CVE Information

```
$ python cisa_known.py enriched "CVE-2023-36884"

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.5

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.07.19
Total:   975 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog


{
    "Modified": "2023-07-17T19:21:00",
    "Published": "2023-07-11T19:15:00",
    "access": {},
    "assigner": "secure@microsoft.com",
    "capec": [],
    "cvss": null,
    "cwe": "NVD-CWE-noinfo",
    "id": "CVE-2023-36884",
    "impact": {},
    "last-modified": "2023-07-17T19:21:00",
    "references": [
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36884"
    ],
    "summary": "Microsoft is investigating reports of a series of remote code execution vulnerabilities impacting Windows and Office products. Microsoft is aware of targeted attacks that attempt to exploit these vulnerabilities by using specially-crafted Microsoft Office documents.\n\nAn attacker could create a specially crafted Microsoft Office document that enables them to perform remote code execution in the context of the victim. However, an attacker would have to convince the victim to open the malicious file.\n\nUpon completion of this investigation, Microsoft will take the appropriate action to help protect our customers. This might include providing a security update through our monthly release process or providing an out-of-cycle security update, depending on customer needs.\n\nPlease see the Microsoft Threat Intelligence  Blog https://aka.ms/Storm-0978 \u00a0Entry for important information about steps you can take to protect your system from this vulnerability.\n\nThis CVE will be updated with new information and links to security updates when they become available.\n\n",
    "vulnerable_configuration": [
        {
            "id": "cpe:2.3:a:microsoft:word:2013:sp1:*:*:*:*:*:*",
            "title": "cpe:2.3:a:microsoft:word:2013:sp1:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:a:microsoft:word:2016:*:*:*:*:*:*:*",
            "title": "cpe:2.3:a:microsoft:word:2016:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:x86:*",
            "title": "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:x86:*"
        },
        {
            "id": "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:x64:*",
            "title": "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:x64:*"
        },
        {
            "id": "cpe:2.3:a:microsoft:office:2021:*:*:*:ltsc:*:x64:*",
            "title": "cpe:2.3:a:microsoft:office:2021:*:*:*:ltsc:*:x64:*"
        },
        {
            "id": "cpe:2.3:a:microsoft:office:2021:*:*:*:ltsc:*:x86:*",
            "title": "cpe:2.3:a:microsoft:office:2021:*:*:*:ltsc:*:x86:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_11:22h2:*:*:*:*:*:x64:*",
            "title": "cpe:2.3:o:microsoft:windows_11:22h2:*:*:*:*:*:x64:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_11:22h2:*:*:*:*:*:arm64:*",
            "title": "cpe:2.3:o:microsoft:windows_11:22h2:*:*:*:*:*:arm64:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*",
            "title": "cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10_1809:-:*:*:*:*:*:x64:*",
            "title": "cpe:2.3:o:microsoft:windows_10_1809:-:*:*:*:*:*:x64:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10_21h2:-:*:*:*:*:*:x64:*",
            "title": "cpe:2.3:o:microsoft:windows_10_21h2:-:*:*:*:*:*:x64:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:x64:*",
            "title": "cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:x64:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10_21h2:-:*:*:*:*:*:arm64:*",
            "title": "cpe:2.3:o:microsoft:windows_10_21h2:-:*:*:*:*:*:arm64:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10_21h2:-:*:*:*:*:*:x86:*",
            "title": "cpe:2.3:o:microsoft:windows_10_21h2:-:*:*:*:*:*:x86:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:arm64:*",
            "title": "cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:arm64:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10_1809:-:*:*:*:*:*:arm64:*",
            "title": "cpe:2.3:o:microsoft:windows_10_1809:-:*:*:*:*:*:arm64:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10_1809:-:*:*:*:*:*:x86:*",
            "title": "cpe:2.3:o:microsoft:windows_10_1809:-:*:*:*:*:*:x86:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:x86:*",
            "title": "cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:x86:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*",
            "title": "cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_11_21h2:-:*:*:*:*:*:arm64:*",
            "title": "cpe:2.3:o:microsoft:windows_11_21h2:-:*:*:*:*:*:arm64:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_11_21h2:-:*:*:*:*:*:x64:*",
            "title": "cpe:2.3:o:microsoft:windows_11_21h2:-:*:*:*:*:*:x64:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10_1507:-:*:*:*:*:*:x64:*",
            "title": "cpe:2.3:o:microsoft:windows_10_1507:-:*:*:*:*:*:x64:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10_1507:-:*:*:*:*:*:x86:*",
            "title": "cpe:2.3:o:microsoft:windows_10_1507:-:*:*:*:*:*:x86:*"
        }
    ],
    "vulnerable_configuration_cpe_2_2": [],
    "vulnerable_product": [
        "cpe:2.3:a:microsoft:word:2013:sp1:*:*:*:*:*:*",
        "cpe:2.3:a:microsoft:word:2016:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*",
        "cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*",
        "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:x86:*",
        "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:x64:*",
        "cpe:2.3:a:microsoft:office:2021:*:*:*:ltsc:*:x64:*",
        "cpe:2.3:a:microsoft:office:2021:*:*:*:ltsc:*:x86:*",
        "cpe:2.3:o:microsoft:windows_11:22h2:*:*:*:*:*:x64:*",
        "cpe:2.3:o:microsoft:windows_11:22h2:*:*:*:*:*:arm64:*",
        "cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x64:*",
        "cpe:2.3:o:microsoft:windows_10_1809:-:*:*:*:*:*:x64:*",
        "cpe:2.3:o:microsoft:windows_10_21h2:-:*:*:*:*:*:x64:*",
        "cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:x64:*",
        "cpe:2.3:o:microsoft:windows_10_21h2:-:*:*:*:*:*:arm64:*",
        "cpe:2.3:o:microsoft:windows_10_21h2:-:*:*:*:*:*:x86:*",
        "cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:arm64:*",
        "cpe:2.3:o:microsoft:windows_10_1809:-:*:*:*:*:*:arm64:*",
        "cpe:2.3:o:microsoft:windows_10_1809:-:*:*:*:*:*:x86:*",
        "cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:x86:*",
        "cpe:2.3:o:microsoft:windows_10_1607:-:*:*:*:*:*:x86:*",
        "cpe:2.3:o:microsoft:windows_11_21h2:-:*:*:*:*:*:arm64:*",
        "cpe:2.3:o:microsoft:windows_11_21h2:-:*:*:*:*:*:x64:*",
        "cpe:2.3:o:microsoft:windows_10_1507:-:*:*:*:*:*:x64:*",
        "cpe:2.3:o:microsoft:windows_10_1507:-:*:*:*:*:*:x86:*"
    ]
}
```

## 5 Most Recently Added Vulnerabilities

```
$ python cisa_known.py recent

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.5

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.07.19
Total:   975 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog


5 Most Recently Added Vulnerabilities:


CVE ID:  CVE-2023-3519
Product: NetScaler ADC and NetScaler Gateway
Vendor:  Citrix
Name:    Citrix NetScaler ADC and NetScaler Gateway Code Injection Vulnerability
Date:    2023-07-19
URL:     https://nvd.nist.gov/vuln/detail/CVE-2023-3519
Info:    Citrix NetScaler ADC and NetScaler Gateway contains a code injection vulnerability that allows for unauthenticated remote code execution.


CVE ID:  CVE-2023-36884
Product: Office and Windows
Vendor:  Microsoft
Name:    Microsoft Office and Windows HTML Remote Code Execution Vulnerability
Date:    2023-07-17
URL:     https://nvd.nist.gov/vuln/detail/CVE-2023-36884
Info:    Microsoft Office and Windows contain an unspecified vulnerability that allows an attacker to perform remote code execution via a specially crafted Microsoft Office document.


CVE ID:  CVE-2022-29303
Product: Compact
Vendor:  SolarView
Name:    SolarView Compact Command Injection Vulnerability
Date:    2023-07-13
URL:     https://nvd.nist.gov/vuln/detail/CVE-2022-29303
Info:    SolarView Compact contains a command injection vulnerability due to improper validation of input values on the send test mail console of the product's web server.


CVE ID:  CVE-2023-37450
Product: Multiple Products
Vendor:  Apple
Name:    Apple Multiple Products WebKit Code Execution Vulnerability
Date:    2023-07-13
URL:     https://nvd.nist.gov/vuln/detail/CVE-2023-37450
Info:    Apple iOS, iPadOS, macOS, and Safari WebKit contain an unspecified vulnerability that can allow an attacker to execute code when processing web content.


CVE ID:  CVE-2023-32046
Product: Windows
Vendor:  Microsoft
Name:    Microsoft Windows MSHTML Platform Privilege Escalation Vulnerability
Date:    2023-07-11
URL:     https://nvd.nist.gov/vuln/detail/CVE-2023-32046
Info:    Microsoft Windows MSHTML Platform contains an unspecified vulnerability that allows for privilege escalation.
```

## Top 10 Statistics (Vendor / Months)

```
$ python cisa_known.py stats

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.5

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.07.19
Total:   975 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog


Top 10 Vendors:
Microsoft: 265
Cisco: 63
Apple: 61
Adobe: 60
Google: 48
Oracle: 32
Apache: 28
VMware: 18
D-Link: 15
Citrix: 12

Top 10 Months:
2021-11: 291
2022-03: 226
2022-05: 83
2022-06: 49
2022-04: 45
2022-01: 40
2022-02: 32
2022-09: 25
2023-06: 24
2022-08: 23
```

## Update Functionality (including CVE details)

```
$ python cisa_known.py -u

Newer version found online. Update? (yes/no) yes
Latest CISA database downloaded.
Downloading enriched CVE information.
Downloading enriched CVE information.
100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████| 977/977 [01:07<00:00, 14.45it/s]

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.5

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.07.20
Total:   977 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog
```

## Export to graph (the repository contains a template.html that can be adapted)
```
$ python cisa_known.py export

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.5

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.07.20
Total:   977 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog


Graph was successfully exported to file 'export_chart.html' in the directory '/home/xaitax/code/cisa-catalog-known-vulnerabilities/'.
```

# Changelog

0.5

[Changed]
- Complete rewrite of the code
[Added]
- Export functionality with stats about Product, Vendor and Timeline vulnerabilities

0.3

[Added]
- Display 5 Most Recently Added Vulnerabilities

0.2

[Added] 
- Local CVE Details retrieved from https://www.cve-search.org/
- Enriched CVE details via `-e CVE-2022-1020` or `--enriched CVE-2022-1020`

0.1 

- Initial version
