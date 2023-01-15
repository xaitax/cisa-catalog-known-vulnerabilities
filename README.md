# CISA Catalog of Known Exploited Vulnerabilities

The script, which is designed to be user-friendly and efficient, allows users to search through the CISA Catalog database offline for specific products or vendors, and then displays detailed information about any vulnerabilities that have been identified in those products or by those vendors. The information that is displayed also includes the vulnerability's Common Vulnerabilities and Exposures (CVE) number including a link to the NIST database.
It also features the possibility to display enhanced information about specific CVEs.

This script is particularly useful for organizations and individuals that are required to comply with the new directive issued by the Cybersecurity & Infrastructure Security Agency (CISA), which mandates that federal agencies patch known vulnerability exploits as soon as possible. This directive is intended to help protect the government's networks and systems from cyber attacks by reducing the number of known vulnerabilities that can be exploited.

As part of this directive, CISA is also publishing a list of known vulnerability exploits to aid in this effort. This list is publicly available and can be accessed via the CISA website at https://www.cisa.gov/known-exploited-vulnerabilities-catalog. The list is regularly updated as new vulnerabilities are discovered and can be used as a reference for organizations and individuals to identify known vulnerabilities and take appropriate action to mitigate the risks associated with them.

# Functionality

The script offers the following possibilities:

## Info

```
$ python cisa_known.py -i

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.3

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.01.10
Total:   870 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog
```

## Help

```
$ python cisa_known.py -h
usage: cisa_known.py [-h] [-p PRODUCT] [-v VENDOR] [-a ALL] [-e ENRICHED] [-u] [-i] [-r] [-s]

Search for a specific product/vendor in the CISA Catalog.

options:
  -h, --help            show this help message and exit
  -p PRODUCT, --product PRODUCT
                        The product to search for
  -v VENDOR, --vendor VENDOR
                        The vendor to search for
  -a ALL, --all ALL     Search for both product and vendor in the CISA Catalog
  -e ENRICHED, --enriched ENRICHED
                        Display detailed information about the CVE
  -u, --update          Check for updates and download the most recent version
  -i, --info            Print information about the CISA Catalog
  -r, --recent          Show 5 most recent additions to the CISA Catalog
  -s, --stats           Print statistics about the CISA Catalog
```

## Product Search

```
$ python cisa_known.py -p "Adobe"

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.3

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.01.10
Total:   870 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog


CVEs found: 2


CVE ID:  CVE-2020-0938
Product: Windows, Windows Adobe Type Manager Library
Vendor:  Microsoft
Name:    Microsoft Windows Type 1 Font Parsing Remote Code Execution Vulnerability
Date:    2021-11-03
URL:     https://nvd.nist.gov/vuln/detail/CVE-2020-0938
Info:    A remote code execution vulnerability exists in Microsoft Windows when the Windows Adobe Type Manager Library improperly handles a specially-crafted multi-master font - Adobe Type 1 PostScript format. This CVE ID is unique from CVE-2020-1020.


CVE ID:  CVE-2020-1020
Product: Windows, Windows Adobe Type Manager Library
Vendor:  Microsoft
Name:    Microsoft Windows Type 1 Font Parsing Remote Code Execution Vulnerability
Date:    2021-11-03
URL:     https://nvd.nist.gov/vuln/detail/CVE-2020-1020
Info:    A remote code execution vulnerability exists in Microsoft Windows when the Windows Adobe Type Manager Library improperly handles a specially-crafted multi-master font - Adobe Type 1 PostScript format. This CVE ID is unique from CVE-2020-0938.
```

## Vendor Search

```
$ python cisa_known.py -v "Adobe"

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.3

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.01.10
Total:   870 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog


CVEs found: 59


CVE ID:  CVE-2021-21017
Product: Acrobat and Reader
Vendor:  Adobe
Name:    Adobe Acrobat and Reader Heap-based Buffer Overflow Vulnerability
Date:    2021-11-03
URL:     https://nvd.nist.gov/vuln/detail/CVE-2021-21017
Info:    Acrobat Reader DC versions versions 2020.013.20074 (and earlier), 2020.001.30018 (and earlier) and 2017.011.30188 (and earlier) are affected by a heap-based buffer overflow vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.


CVE ID:  CVE-2021-28550
Product: Acrobat and Reader
Vendor:  Adobe
Name:    Adobe Acrobat and Reader Use-After-Free Vulnerability
Date:    2021-11-03
URL:     https://nvd.nist.gov/vuln/detail/CVE-2021-28550
Info:    Acrobat Reader DC versions versions 2021.001.20150 (and earlier), 2020.001.30020 (and earlier) and 2017.011.30194 (and earlier) are affected by a Use After Free vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.


CVE ID:  CVE-2018-4939
Product: ColdFusion
Vendor:  Adobe
Name:    Adobe ColdFusion Deserialization of Untrusted Data vulnerability
Date:    2021-11-03
URL:     https://nvd.nist.gov/vuln/detail/CVE-2018-4939
Info:    Adobe ColdFusion Update 5 and earlier versions, ColdFusion 11 Update 13 and earlier versions have an exploitable Deserialization of Untrusted Data vulnerability. Successful exploitation could lead to arbitrary code execution.

[...]
```

## Detailed CVE Information

```
$ python cisa_known.py -e CVE-2020-1020

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.3

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.01.10
Total:   870 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog


{
    "Modified": "2022-07-12T17:42:00",
    "Published": "2020-04-15T15:15:00",
    "access": {
        "authentication": "NONE",
        "complexity": "MEDIUM",
        "vector": "NETWORK"
    },
    "assigner": "secure@microsoft.com",
    "capec": [],
    "cvss": 6.8,
    "cvss-time": "2022-07-12T17:42:00",
    "cvss-vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
    "cwe": "CWE-787",
    "id": "CVE-2020-1020",
    "impact": {
        "availability": "PARTIAL",
        "confidentiality": "PARTIAL",
        "integrity": "PARTIAL"
    },
    "last-modified": "2022-07-12T17:42:00",
    "references": [
        "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1020"
    ],
    "refmap": {
        "misc": [
            "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1020"
        ]
    },
    "summary": "A remote code execution vulnerability exists in Microsoft Windows when the Windows Adobe Type Manager Library improperly handles a specially-crafted multi-master font - Adobe Type 1 PostScript format.For all systems except Windows 10, an attacker who successfully exploited the vulnerability could execute code remotely, aka 'Adobe Font Manager Library Remote Code Execution Vulnerability'. This CVE ID is unique from CVE-2020-0938.",
    "vulnerable_configuration": [
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:itanium:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:itanium:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_8.1:-:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_8.1:-:*:*:*:*:*:*:*"
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
            "id": "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_rt_8.1:-:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_rt_8.1:-:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10:1709:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_10:1709:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10:1803:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_10:1803:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10:1809:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_10:1809:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10:1903:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_10:1903:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_10:1909:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_10:1909:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2016:1803:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2016:1803:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2016:1903:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2016:1903:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2016:1909:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2016:1909:*:*:*:*:*:*:*"
        },
        {
            "id": "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*",
            "title": "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*"
        }
    ],
    "vulnerable_configuration_cpe_2_2": [],
    "vulnerable_product": [
        "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*",
        "cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:itanium:*",
        "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_8.1:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_rt_8.1:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_10:1709:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_10:1803:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_10:1809:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_10:1903:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_10:1909:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2016:1803:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2016:1903:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2016:1909:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*"
    ]
}
```

## 5 Most Recently Added Vulnerabilities

```
$ python cisa_known.py -r

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.3

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.01.10
Total:   870 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog


5 Most Recently Added Vulnerabilities:

CVE ID:  CVE-2022-41080
Product: Exchange Server
Vendor:  Microsoft
Name:    Microsoft Exchange Server Privilege Escalation Vulnerability
Date:    2023-01-10
URL:     https://nvd.nist.gov/vuln/detail/CVE-2022-41080
Info:    Microsoft Exchange Server contains an unspecified vulnerability that allows for privilege escalation. This vulnerability is chainable with CVE-2022-41082, which allows for remote code execution.

CVE ID:  CVE-2023-21674
Product: Windows
Vendor:  Microsoft
Name:    Microsoft Windows Advanced Local Procedure Call (ALPC) Privilege Escalation Vulnerability
Date:    2023-01-10
URL:     https://nvd.nist.gov/vuln/detail/CVE-2023-21674
Info:    Microsoft Windows Advanced Local Procedure Call (ALPC) contains an unspecified vulnerability that allows for privilege escalation.

CVE ID:  CVE-2018-5430
Product: JasperReports
Vendor:  TIBCO
Name:    TIBCO JasperReports Server Information Disclosure Vulnerability
Date:    2022-12-29
URL:     https://nvd.nist.gov/vuln/detail/CVE-2018-5430
Info:    TIBCO JasperReports Server contain a vulnerability which may allow any authenticated user read-only access to the contents of the web application, including key configuration files.

CVE ID:  CVE-2018-18809
Product: JasperReports
Vendor:  TIBCO
Name:    TIBCO JasperReports Library Directory Traversal Vulnerability
Date:    2022-12-29
URL:     https://nvd.nist.gov/vuln/detail/CVE-2018-18809
Info:    TIBCO JasperReports Library contains a directory-traversal vulnerability that may allow web server users to access contents of the host system.

CVE ID:  CVE-2022-42856
Product: iOS
Vendor:  Apple
Name:    Apple iOS Type Confusion Vulnerability
Date:    2022-12-14
URL:     https://nvd.nist.gov/vuln/detail/CVE-2022-42856
Info:    Apple iOS contains a type confusion vulnerability when processing maliciously crafted web content leading to code execution.
```

## Top 10 Statistics (Vendor / Months)

```
$ python cisa_known.py -s

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.3

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.01.10
Total:   870 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog


Top 10 Vendors:
Microsoft: 250
Cisco: 60
Adobe: 59
Apple: 49
Google: 44
Oracle: 29
Apache: 25
VMware: 16
D-Link: 13
Citrix: 11

Top 10 Months:
2021-11: 291
2022-03: 226
2022-05: 83
2022-06: 49
2022-04: 45
2022-01: 40
2022-02: 32
2022-09: 25
2022-08: 23
2021-12: 20
```

## Update Functionality (including CVE details)

```
$ python cisa_known.py -u

Newer version found online. Update? (yes/no) yes
Latest CISA database downloaded.
Downloading enriched CVE information.
Download Progress: 100%|█████████████████████████████████████████████████████████████████| 870/870 [00:02<00:00, 425.90it/s]

_________ .___  _________   _____    _________         __         .__
\_   ___ \|   |/   _____/  /  _  \   \_   ___ \_____ _/  |______  |  |   ____   ____
/    \  \/|   |\_____  \  /  /_\  \  /    \  \/\__  \   __ \__  \ |  |  /  _ \ / ___\
\     \___|   |/        \/    |    \ \     \____/ __ \|  |  / __ \|  |_(  <_> ) /_/  >
 \______  /___/_______  /\____|__  /  \______  (____  /__| (____  /____/\____/\___  /
        \/            \/         \/          \/     \/          \/           /_____/
Alexander Hagenah / ah@primepage.de / @xaitax / v 0.3

Title:   CISA Catalog of Known Exploited Vulnerabilities
Version: 2023.01.10
Total:   870 vulnerabilities
URL:     https://www.cisa.gov/known-exploited-vulnerabilities-catalog
```

# Changelog

0.3

[Added]
- Display 5 Most Recently Added Vulnerabilities

0.2

[Added] 
- Local CVE Details retrieved from https://www.cve-search.org/
- Enriched CVE details via `-e CVE-2022-1020` or `--enriched CVE-2022-1020`

0.1 

- Initial version
