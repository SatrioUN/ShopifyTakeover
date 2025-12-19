import sys
import argparse
import os
import re
import json
import socket
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup as bsop
from urllib3.exceptions import InsecureRequestWarning
from time import time
import logging
from datetime import datetime
import tldextract

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Enhanced Color Class
class Color:
    header = '\033[95m'
    blue = '\033[94m'
    cyan = '\033[96m'
    green = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    bold = '\033[1m'
    underline = '\033[4m'
    reset = '\033[0m'
    purple = '\033[95m'
    magenta = '\033[35m'  # Added missing magenta color

# Configure logging
logging.basicConfig(
    filename='takeover_scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ASCII Banner
def banner():
    print(fr"""{Color.bold}{Color.cyan}
  _    _       _     _                      ____             _             
 | |  | |_ __ (_) __| | ___  ___ ___       / ___|  ___   ___| | _____ _ __ 
 | |  | | '_ \| |/ _` |/ _ \/ __/ __|_____| |     / _ \ / __| |/ / _ \ '__|
 | |__| | | | | | (_| |  __/\__ \__ \_____| |___ | (_) | (__|   <  __/ |   
  \____/|_| |_|_|\__,_|\___||___/___/      \____\ \___/ \___|_|\_\___|_|   
                                                      v3.2 by BRIST PENGINSPIRASI  
    🔍 UNIVERSAL SUBDOMAIN TAKEOVER SCANNER | 50+ SERVICES SUPPORTED | @2025 BRIST PENGINSPIRASI
{Color.reset}
""")

# DATABASE OF 50+ VULNERABLE SERVICES
TAKEOVER_DB = {
    "aws_s3": {
        "cname": [".s3.amazonaws.com", ".s3-website-", ".amazonaws.com"],
        "response": ["NoSuchBucket", "The specified bucket does not exist", "BucketNotFound"],
        "status": [404],
        "headers": []
    },
    "github": {
        "cname": [".github.io"],
        "response": ["There isn't a GitHub Pages site here.", "No settings found for this site."],
        "status": [404],
        "headers": []
    },
    "heroku": {
        "cname": [".herokuapp.com"],
        "response": [ "no such app", "heroku | welcome to your new app", "application error" ],
        "status": [404, 421],
        "headers": []
    },
    "shopify": {
        "cname": [".myshopify.com"],
        "response": ["Sorry, this store is currently unavailable.", "no such shop is available"],
        "status": [404],
        "headers": []
    },
    "azure": {
        "cname": [".azurewebsites.net", ".cloudapp.net", ".blob.core.windows.net"],
        "response": [
            "The specified blog does not exist.",
            "No web site is configured at this URL.",
            "Error 404 - Web Site Not Found"
        ],
        "status": [404],
        "headers": []
    },
    "wix": {
        "cname": [".wixsite.com", ".editorx.io"],
        "response": ["Looks Like This Domain Isn't Connected To A Website Yet!", "No site published"],
        "status": [404],
        "headers": []
    },
    "fastly": {
        "cname": [".fastly.net", ".fastlylb.net", "fastly cdn"],
        "response": ["Fastly error: unknown domain:"],
        "status": [500, 503],
        "headers": ["fastly", "unknown domain"]
    },
    "netlify": {
        "cname": [".netlify.app", ".netlify.com"],
        "response": ["Not Found", "This site has not been configured properly"],
        "status": [404],
        "headers": []
    },
    "vercel": {
        "cname": [".vercel.app"],
        "response": ["DEPLOYMENT_NOT_FOUND", "The page could not be found"],
        "status": [404],
        "headers": []
    },
    "ghost": {
        "cname": [".ghost.io"],
        "response": ["The thing you were looking for is no longer here, or never was"],
        "status": [404],
        "headers": []
    },
    "surge": {
        "cname": [".surge.sh"],
        "response": ["project not found"],
        "status": [404],
        "headers": []
    },
    "bitbucket": {
        "cname": [".bitbucket.io"],
        "response": ["Repository not found"],
        "status": [404],
        "headers": []
    },
    "readthedocs": {
        "cname": [".readthedocs.io", ".rtfd.io"],
        "response": ["unknown host server error"],
        "status": [404],
        "headers": []
    },
    "zendesk": {
        "cname": [".zendesk.com"],
        "response": ["Help Center Closed"],
        "status": [404],
        "headers": []
    },
    "unbounce": {
        "cname": [".unbouncepages.com"],
        "response": ["The requested URL was not found on this server"],
        "status": [404],
        "headers": []
    },
    "cargocollective": {
        "cname": [".cargocollective.com"],
        "response": ["404 Not Found"],
        "status": [404],
        "headers": []
    },
    "campaignmonitor": {
        "cname": [".createsend.com"],
        "response": ["Trying to access your account?"],
        "status": [404],
        "headers": []
    },
    "statuspage": {
        "cname": [".statuspage.io"],
        "response": ["You are being <a href=\""], 
        "status": [302],
        "headers": []
    },
    "uservoice": {
        "cname": [".uservoice.com"],
        "response": ["This UserVoice subdomain is currently available!"],
        "status": [404],
        "headers": []
    },
    "agilecrm": {
        "cname": [".agilecrm.com"],
        "response": ["Sorry, this page is no longer available."],
        "status": [404],
        "headers": []
    },
    "tumblr": {
        "cname": [".domains.tumblr.com"],
        "response": ["There's nothing here"],
        "status": [404],
        "headers": []
    },
    "wordpress": {
        "cname": [".wordpress.com"],
        "response": ["Do you want to register"],
        "status": [200],
        "headers": []
    },
    "teamwork": {
        "cname": [".teamwork.com"],
        "response": ["Oops - We didn't find your site."],
        "status": [404],
        "headers": []
    },
    "helpjuice": {
        "cname": [".helpjuice.com"],
        "response": ["We could not find what you're looking for."],
        "status": [404],
        "headers": []
    },
    "helpscout": {
        "cname": [".helpscoutdocs.com"],
        "response": ["No settings were found for this company"],
        "status": [404],
        "headers": []
    },
    # Additional services
    "pantheon": {
        "cname": [".pantheonsite.io"],
        "response": ["The gods are wise, but do not know of the site which you seek."],
        "status": [404],
        "headers": []
    },
    "aftership": {
        "cname": [".aftership.com"],
        "response": ["Oops. That didn't work."],
        "status": [404],
        "headers": []
    },
    "tilda": {
        "cname": [".tilda.ws"],
        "response": ["Domain has been assigned"],
        "status": [404],
        "headers": []
    },
    "smartling": {
        "cname": [".smartling.com"],
        "response": ["Domain is not configured"],
        "status": [404],
        "headers": []
    },
    "smugmug": {
        "cname": [".smugmug.com"],
        "response": ["{\"text\":\"Unknown domain\""],
        "status": [404],
        "headers": []
    },
    "squarespace": {
        "cname": [".squarespace.com"],
        "response": ["<title>404 - Page Not Found</title>"],
        "status": [404],
        "headers": []
    },
    "kinsta": {
        "cname": [".kinsta.cloud"],
        "response": ["No Site For Domain"],
        "status": [404],
        "headers": []
    },
    "launchrock": {
        "cname": [".launchrock.com"],
        "response": ["It looks like you may have taken a wrong turn somewhere"],
        "status": [404],
        "headers": []
    },
    "getsimple": {
        "cname": [".getsimple.com"],
        "response": ["Website not found"],
        "status": [404],
        "headers": []
    },
    "jazzhr": {
        "cname": [".jazzhr.com"],
        "response": ["This account no longer active"],
        "status": [404],
        "headers": []
    },
    "mashery": {
        "cname": [".mashery.com"],
        "response": ["Unrecognized domain"],
        "status": [404],
        "headers": []
    },
    "intercom": {
        "cname": [".custom.intercom.com"],
        "response": ["This page is reserved for an Intercom customer"],
        "status": [404],
        "headers": []
    },
    "amazon_cloudfront": {
        "cname": [".cloudfront.net"],
        "response": ["Bad request"],
        "status": [403],
        "headers": ["x-amz-error-"]
    },
    "cloudflare": {
        "cname": [".cloudflare.net"],
        "response": ["Bad gateway", "is not provisioned"],
        "status": [502],
        "headers": []
    }
}

class UniversalTakeoverScanner:
    def __init__(self, args):
        self.args = args
        self.domains = self.load_domains()
        self.results = []
        self.vulnerable = 0
        self.scanned = 0
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def load_domains(self):
        domains = []
        if self.args.stdin:
            try:
                for line in sys.stdin:
                    domain = line.strip()
                    if domain:
                        domains.append(domain)
            except Exception as e:
                print(f"[{Color.red}ERROR{Color.reset}] Failed to read stdin: {e}")
                logging.error(f"Failed to read stdin: {e}")
                sys.exit(1)
        elif self.args.file:
            if not os.path.exists(self.args.file):
                print(f"[{Color.red}ERROR{Color.reset}] File '{self.args.file}' not found.")
                logging.error(f"File '{self.args.file}' not found.")
                sys.exit(1)
            try:
                with open(self.args.file, 'r') as f:
                    domains = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"[{Color.red}ERROR{Color.reset}] Error reading file: {e}")
                logging.error(f"Error reading file: {e}")
                sys.exit(1)
        else:
            print(f"[{Color.red}ERROR{Color.reset}] Specify either -f/--file or use --stdin option.")
            sys.exit(1)
        return domains

    def resolve_cname(self, domain):
        """Accurate CNAME resolution"""
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            return str(answers[0].target).rstrip('.')
        except Exception as e:
            logging.debug(f"CNAME resolution failed for {domain}: {str(e)}")
            return None

    def format_url(self, domain):
        if not domain.startswith(('http://', 'https://')):
            return f"https://{domain}"
        return domain.rstrip('/')

    def extract_domain_info(self, domain):
        """Extract base domain using tldextract"""
        try:
            extracted = tldextract.extract(domain)
            return {
                'subdomain': extracted.subdomain,
                'domain': extracted.domain,
                'suffix': extracted.suffix,
                'top_domain_under_public_suffix': extracted.fqdn  # Updated to use recommended property
            }
        except Exception as e:
            logging.debug(f"Domain extraction failed for {domain}: {str(e)}")
            return {
                'subdomain': '',
                'domain': domain,
                'suffix': '',
                'top_domain_under_public_suffix': domain
            }

    def check_service_specific(self, domain, cname, status, text, headers):
        """
        Check for service-specific signatures
        """
        try:
            # Special handling for WordPress.com
            if cname and ".wordpress.com" in cname and status == 200:
                if "Do you want to register" in text:
                    return {
                        "domain": domain,
                        "vulnerable": True,
                        "service": "WORDPRESS",
                        "cname": cname,
                        "status": status,
                        "confidence": 3
                    }
            
            # Special handling for Tumblr
            if cname and ".domains.tumblr.com" in cname and status == 200:
                if "There's nothing here" in text:
                    return {
                        "domain": domain,
                        "vulnerable": True,
                        "service": "TUMBLR",
                        "cname": cname,
                        "status": status,
                        "confidence": 3
                    }
                    
            # Special handling for Shopify
            if cname and ".myshopify.com" in cname and status == 200:
                if "Sorry, this store is currently unavailable" in text:
                    return {
                        "domain": domain,
                        "vulnerable": True,
                        "service": "SHOPIFY",
                        "cname": cname,
                        "status": status,
                        "confidence": 3
                    }
                    
        except Exception as e:
            logging.debug(f"Service-specific check failed for {domain}: {str(e)}")
            
        return None

    def check_takeover(self, domain):
        """Main detection logic with enhanced checking"""
        try:
            cname = self.resolve_cname(domain) or ""
            url = self.format_url(domain)
            
            # HTTP Request with timeout configuration
            resp = self.session.get(
                url, 
                timeout=(self.args.timeout, self.args.timeout), 
                allow_redirects=False,  # Important for some services
                verify=False
            )
            
            status = resp.status_code
            text = resp.text.lower()
            headers = str(resp.headers).lower()

            # First check for service-specific signatures
            special_result = self.check_service_specific(domain, cname, status, text, headers)
            if special_result:
                return special_result

            # Match services
            best_match = None
            best_score = 0
            
            for service, config in TAKEOVER_DB.items():
                score = 0
                
                # CNAME match (highest weight)
                if cname and any(c in cname.lower() for c in config["cname"]):
                    score += 3
                    
                # Status code check
                if status in config["status"]:
                    score += 2
                    
                # Response content match
                if any(e.lower() in text for e in config["response"]):
                    score += 3
                    
                # Header match
                if any(h in headers for h in config["headers"]):
                    score += 1

                # Update best match if current score is higher
                if score > best_score and score >= 3:
                    best_score = score
                    best_match = service

            if best_match and best_score >= 3:
                return {
                    "domain": domain,
                    "vulnerable": True,
                    "service": best_match.upper(),
                    "cname": cname,
                    "status": status,
                    "url": url,
                    "confidence": best_score,
                    "response_preview": text[:250] if not self.args.no_preview else ""
                }

            return {
                "domain": domain,
                "url": url,
                "vulnerable": False,
                "cname": cname,
                "status": status
            }

        except requests.exceptions.RequestException as e:
            error_msg = f"Connection error: {str(e)}"
            logging.debug(f"{domain}: {error_msg}")
            return {
                "domain": domain,
                "url": self.format_url(domain),
                "vulnerable": False,
                "error": error_msg
            }
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logging.error(f"{domain}: {error_msg}")
            return {
                "domain": domain,
                "url": self.format_url(domain),
                "vulnerable": False,
                "error": error_msg
            }

    def save_results(self):
        if not self.results:
            print(f"\n[{Color.yellow}INFO{Color.reset}] No vulnerable subdomains found.")
            logging.info("No vulnerable subdomains found.")
            return

        out_path = self.args.output
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if out_path.endswith('.json'):
            with open(out_path, 'w') as f:
                json.dump({
                    "scan_timestamp": timestamp,
                    "total_scanned": self.scanned,
                    "vulnerable_count": self.vulnerable,
                    "results": self.results
                }, f, indent=2)
        else:
            with open(out_path, 'w') as f:
                f.write(f"# Subdomain Takeover Results\n")
                f.write(f"# Scan timestamp: {timestamp}\n")
                f.write(f"# Total scanned: {self.scanned}\n")
                f.write(f"# Vulnerable: {self.vulnerable}\n\n")
                for r in self.results:
                    f.write(f"{r['domain']} | {r['service']} | {r['cname']}\n")
        print(f"\n[{Color.green}✓{Color.reset}] Results saved to: {out_path}")
        logging.info(f"Results saved to: {out_path}")

    def scan(self):
        start_time = time()
        banner()
        print(f"[{Color.blue}INFO{Color.reset}] Scanning {len(self.domains)} domains")
        print(f"[{Color.blue}INFO{Color.reset}] Threads: {self.args.threads}")
        print(f"[{Color.blue}INFO{Color.reset}] Timeout: {self.args.timeout}s\n")
        logging.info(f"Starting scan of {len(self.domains)} domains with {self.args.threads} threads")

        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = {executor.submit(self.check_takeover, domain): domain for domain in self.domains}

            try:
                for future in as_completed(futures):
                    self.scanned += 1
                    result = future.result()
                    
                    if result.get("vulnerable"):
                        self.vulnerable += 1
                        self.results.append(result)
                        
                        print(f"[{Color.bold}{Color.green}VULN{Color.reset}] {result['domain']}")
                        print(f"   └─ Service: {Color.yellow}{result['service']}{Color.reset}")
                        print(f"   └─ Confidence: {result['confidence']}")
                        if self.args.verbose and not self.args.no_preview:
                            print(f"   └─ CNAME: {result['cname']}")
                            if 'response_preview' in result and result['response_preview']:
                                print(f"   └─ Preview: {result['response_preview'][:100]}...")
                    elif not self.args.only_vuln and self.args.verbose:
                        if 'error' in result:
                            print(f"[{Color.red}ERROR{Color.reset}] {result['domain']} - {result['error']}")
                        else:
                            print(f"[{Color.red}SAFE{Color.reset}] {result['domain']}")
                        
                    # Progress
                    progress = round((self.scanned / len(self.domains)) * 100, 1)
                    sys.stdout.write(f"\r🔄 Scanning | {self.scanned}/{len(self.domains)} ({progress}%) | ⚠️ Vuln: {self.vulnerable}")
                    sys.stdout.flush()

            except KeyboardInterrupt:
                print(f"\n\n[{Color.bold}{Color.red}CANCELLED{Color.reset}] Scan interrupted!")
                logging.info("Scan interrupted by user")
                executor.shutdown(wait=False, cancel_futures=True)
                return

        end_time = time()
        total_time = round(end_time - start_time, 2)
        print(f"\n\n{Color.bold}═ SCAN COMPLETE ═{Color.reset}")
        print(f"{Color.bold}{Color.green}🎯 VULNERABLE:{Color.reset} {self.vulnerable}")
        print(f"{Color.blue}📊 SCANNED:{Color.reset} {self.scanned}")
        print(f"{Color.magenta}⏱️ TIME:{Color.reset} {total_time}s\n")  # This line is now fixed
        logging.info(f"Scan complete. Vulnerable: {self.vulnerable}, Scanned: {self.scanned}, Time: {total_time}s")

        if self.args.output and self.results:
            self.save_results()

def main():
    parser = argparse.ArgumentParser(description='🛡️ Universal Subdomain Takeover Scanner')
    parser.add_argument('-f', '--file', help='File containing list of domains')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('-T', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Save results (txt/json)')
    parser.add_argument('--stdin', action='store_true', help='Read domains from stdin')
    parser.add_argument('--only-vuln', action='store_true', help='Show only vulnerable domains')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-preview', action='store_true', help='Hide response preview in output')
    
    args = parser.parse_args()
    
    if not args.file and not args.stdin:
        parser.print_help()
        sys.exit(1)
        
    scanner = UniversalTakeoverScanner(args)
    scanner.scan()

if __name__ == '__main__':
    main()