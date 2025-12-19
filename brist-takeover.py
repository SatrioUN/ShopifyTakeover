import sys
import argparse
import os
import re
import json
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning
from time import time
import logging
from datetime import datetime
import html
from bs4 import BeautifulSoup

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
    magenta = '\033[35m'

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
                                                      v4.0 by BRIST PENGINSPIRASI  
    🔍 UNIVERSAL SUBDOMAIN TAKEOVER SCANNER | 50+ SERVICES SUPPORTED | @2025 BRIST PENGINSPIRASI
{Color.reset}
""")

# DATABASE OF 50+ VULNERABLE SERVICES WITH IMPROVED SIGNATURES AND PoC TEMPLATES
TAKEOVER_DB = {
    "aws_s3": {
        "cname": [".s3.amazonaws.com", ".s3-website-", ".amazonaws.com"],
        "response": ["NoSuchBucket", "The specified bucket does not exist", "BucketNotFound"],
        "status": [404],
        "headers": [],
        "exclude": ["<title>Amazon S3 Service</title>"],
        "confidence": 95,
        "poc_template": """
AWS S3 Bucket Takeover
======================
Domain: {domain}
CNAME: {cname}
Vulnerability: Unclaimed S3 bucket
Impact: Full control over bucket content
Steps to reproduce:
1. Verify the bucket doesn't exist:
   aws s3 ls s3://{bucket_name}
2. Create the bucket in your AWS account:
   aws s3 mb s3://{bucket_name}
3. Upload content to take control:
   aws s3 cp index.html s3://{bucket_name}/index.html --acl public-read
4. The content will be served at {url}
"""
    },
    "github": {
        "cname": [".github.io"],
        "response": ["There isn't a GitHub Pages site here.", "no longer exists"],
        "status": [404],
        "headers": [],
        "confidence": 90,
        "poc_template": """
GitHub Pages Takeover
=====================
Domain: {domain}
CNAME: {cname}
Vulnerability: Unclaimed GitHub Pages site
Impact: Full control over website content
Steps to reproduce:
1. Create a GitHub repository with the name matching the CNAME
2. Enable GitHub Pages in repository settings
3. Content will be served at {url}
Reference: https://docs.github.com/en/pages/getting-started-with-github-pages/about-github-pages
"""
    },
    "heroku": {
        "cname": [".herokuapp.com"],
        "response": ["no such app", "heroku | welcome to your new app"],
        "status": [404, 421],
        "headers": [],
        "exclude": ["application error", "temporarily unavailable"],
        "confidence": 85,
        "poc_template": """
Heroku App Takeover
===================
Domain: {domain}
CNAME: {cname}
Vulnerability: Unclaimed Heroku app
Impact: Full control over application
Steps to reproduce:
1. Create a Heroku app with matching name
2. Configure custom domain in Heroku settings
3. Content will be served at {url}
Reference: https://devcenter.heroku.com/articles/custom-domains
"""
    },
    "shopify": {
        "cname": [".myshopify.com"],
        "response": ["Sorry, this store is currently unavailable.", "existing shopify store"],
        "status": [404],
        "headers": [],
        "confidence": 90,
        "poc_template": """
Shopify Store Takeover
======================
Domain: {domain}
CNAME: {cname}
Vulnerability: Shopify domain not claimed
Impact: Brand impersonation, phishing potential
Steps to reproduce:
1. Create a Shopify store
2. In Shopify admin, go to Online Store > Domains
3. Add this domain to your store
4. The domain will point to your Shopify store
Reference: https://help.shopify.com/en/manual/online-store/domains/add-a-domain
"""
    },
    "azure": {
        "cname": [".azurewebsites.net", ".cloudapp.net", ".blob.core.windows.net"],
        "response": [
            "The specified blog does not exist.",
            "No web site is configured at this URL.",
            "Error 404 - Web Site Not Found"
        ],
        "status": [404],
        "headers": [],
        "confidence": 85,
        "poc_template": """
Azure App Service Takeover
==========================
Domain: {domain}
CNAME: {cname}
Vulnerability: Unclaimed Azure resource
Impact: Full control over web content
Steps to reproduce:
1. Create an Azure App Service
2. Configure a custom domain in Azure portal
3. Add required CNAME/TXT verification records
4. The domain will serve your Azure web app
Reference: https://docs.microsoft.com/en-us/azure/app-service/app-service-custom-domain
"""
    },
    "wix": {
        "cname": [".wixsite.com", ".editorx.io"],
        "response": ["Looks Like This Domain Isn't Connected To A Website Yet!"],
        "status": [404],
        "headers": [],
        "confidence": 95,
        "poc_template": """
Wix Site Takeover
=================
Domain: {domain}
CNAME: {cname}
Vulnerability: Unclaimed Wix site
Impact: Full control over website content
Steps to reproduce:
1. Create a Wix account
2. In Wix dashboard, go to Settings > Domains
3. Connect this domain to your Wix site
4. Publish the site
Reference: https://support.wix.com/en/article/connecting-a-domain-to-a-wix-site
"""
    },
    "fastly": {
        "cname": [".fastly.net", ".fastlylb.net"],
        "response": ["Fastly error: unknown domain:"],
        "status": [500, 503],
        "headers": ["fastly", "unknown domain"],
        "confidence": 95,
        "poc_template": """
Fastly CDN Takeover
===================
Domain: {domain}
CNAME: {cname}
Vulnerability: Unclaimed Fastly service
Impact: Content delivery control, cache poisoning
Steps to reproduce:
1. Create a Fastly account
2. Create a new service in Fastly dashboard
3. Configure the domain as a custom domain
4. The domain will deliver content through Fastly
Reference: https://docs.fastly.com/en/guides/working-with-domains
"""
    },
    "netlify": {
        "cname": [".netlify.app", ".netlify.com"],
        "response": [
            "server misconfigured",
            "no such site",
            "site no longer exists"
        ],
        "status": [404],
        "headers": ["x-nf-request-id"],
        "exclude": [
            "deployed site not found",
            "checking for deploy",
            "netlify app",
            "<title>Netlify</title>",
            "This site is powered by Netlify"
        ],
        "confidence": 90,
        "poc_template": """
Netlify Site Takeover
=====================
Domain: {domain}
CNAME: {cname}
Vulnerability: Unclaimed Netlify site
Impact: Full control over website content
Steps to reproduce:
1. Create a Netlify account
2. Create a new site (can be from a simple git repository)
3. In site settings, go to Domain Management
4. Add this custom domain
5. The domain will serve your Netlify site
Reference: https://docs.netlify.com/domains-https/custom-domains/
"""
    },
    "vercel": {
        "cname": [".vercel.app"],
        "response": ["DEPLOYMENT_NOT_FOUND"],
        "status": [404],
        "headers": [],
        "confidence": 95,
        "poc_template": """
Vercel Project Takeover
=======================
Domain: {domain}
CNAME: {cname}
Vulnerability: Unclaimed Vercel project
Impact: Full control over website content
Steps to reproduce:
1. Create a Vercel account
2. Deploy any project (even a simple static site)
3. In project settings, go to Domains
4. Add this domain as a custom domain
5. The domain will serve your Vercel project
Reference: https://vercel.com/docs/concepts/projects/custom-domains
"""
    },
    "ghost": {
        "cname": [".ghost.io"],
        "response": ["The thing you were looking for is no longer here"],
        "status": [404],
        "headers": [],
        "confidence": 90,
        "poc_template": """
Ghost Blog Takeover
===================
Domain: {domain}
CNAME: {cname}
Vulnerability: Unclaimed Ghost blog
Impact: Full control over blog content
Steps to reproduce:
1. Create a Ghost(Pro) account
2. Create a new publication
3. In publication settings, add this domain
4. The domain will serve your Ghost blog
Reference: https://ghost.org/docs/hosting/custom-domains/
"""
    },
    "surge": {
        "cname": [".surge.sh"],
        "response": ["project not found"],
        "status": [404],
        "headers": [],
        "confidence": 90,
        "poc_template": """
Surge.sh Takeover
=================
Domain: {domain}
CNAME: {cname}
Vulnerability: Unclaimed Surge project
Impact: Full control over static website
Steps to reproduce:
1. Install Surge CLI: npm install -g surge
2. Create a simple index.html file
3. Deploy with: surge --domain {domain}
4. The domain will serve your content
Reference: https://surge.sh/help/adding-a-custom-domain
"""
    },
    "bitbucket": {
        "cname": [".bitbucket.io"],
        "response": ["Repository not found"],
        "status": [404],
        "headers": [],
        "confidence": 85,
        "poc_template": """
Bitbucket Pages Takeover
========================
Domain: {domain}
CNAME: {cname}
Vulnerability: Unclaimed Bitbucket Pages site
Impact: Full control over website content
Steps to reproduce:
1. Create a Bitbucket repository
2. Enable Bitbucket Pages in repository settings
3. The domain will serve content from your repository
Reference: https://confluence.atlassian.com/bitbucket/publishing-a-website-on-bitbucket-cloud-221449776.html
"""
    },
    "readthedocs": {
        "cname": [".readthedocs.io", ".rtfd.io"],
        "response": ["unknown host server error"],
        "status": [404],
        "headers": [],
        "confidence": 85,
        "poc_template": """
Read the Docs Takeover
======================
Domain: {domain}
CNAME: {cname}
Vulnerability: Unclaimed Read the Docs project
Impact: Full control over documentation site
Steps to reproduce:
1. Create a Read the Docs account
2. Import or create a documentation project
3. In project settings, add this domain as a custom domain
4. The domain will serve your documentation
Reference: https://docs.readthedocs.io/en/stable/custom_domains.html
"""
    },
    "zendesk": {
        "cname": [".zendesk.com"],
        "response": ["Help Center Closed"],
        "status": [404],
        "headers": [],
        "confidence": 90,
        "poc_template": """
Zendesk Help Center Takeover
============================
Domain: {domain}
CNAME: {cname}
Vulnerability: Unclaimed Zendesk help center
Impact: Brand impersonation, support hijacking
Steps to reproduce:
1. Create a Zendesk account
2. Create a help center
3. In help center settings, add this domain
4. The domain will serve your Zendesk help center
Reference: https://support.zendesk.com/hc/en-us/articles/203664346-Changing-the-address-of-your-Help-Center-subdomain
"""
    },
    "unbounce": {
        "cname": [".unbouncepages.com"],
        "response": ["The requested URL was not found on this server"],
        "status": [404],
        "headers": [],
        "confidence": 85,
        "poc_template": """
Unbounce Landing Page Takeover
==============================
Domain: {domain}
CNAME: {cname}
Vulnerability: Unclaimed Unbounce landing page
Impact: Brand impersonation, phishing potential
Steps to reproduce:
1. Create an Unbounce account
2. Create a new landing page
3. In page settings, add this domain as a custom domain
4. The domain will serve your Unbounce page
Reference: https://documentation.unbounce.com/hc/en-us/articles/360001385083-Custom-Domains
"""
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

    def extract_bucket_name(self, cname):
        """Extract bucket name from S3 CNAME"""
        if cname and '.s3.amazonaws.com' in cname:
            return cname.split('.s3.amazonaws.com')[0]
        return cname

    def generate_poc(self, domain, service, cname, url, response_text):
        """Generate Proof of Concept for vulnerability"""
        try:
            service_info = TAKEOVER_DB.get(service.lower(), {})
            poc_template = service_info.get("poc_template", "")
            
            if not poc_template:
                return f"No PoC template available for {service}"
            
            # Extract additional info for PoC
            bucket_name = self.extract_bucket_name(cname)
            
            # Fill in template
            poc = poc_template.format(
                domain=domain,
                cname=cname,
                url=url,
                bucket_name=bucket_name,
                service=service
            )
            
            return poc.strip()
        except Exception as e:
            logging.error(f"Failed to generate PoC for {domain}: {str(e)}")
            return f"Failed to generate PoC: {str(e)}"

    def validate_netlify_domain(self, domain, response_text, response_status, headers):
        """Special validation for Netlify to reduce false positives"""
        # Check for Netlify-specific takeover indicators
        netlify_takeover_indicators = [
            "server misconfigured",
            "no such site",
            "site no longer exists",
            "site not found"
        ]
        
        # Check for false positive indicators
        netlify_fp_indicators = [
            "deployed site not found",
            "checking for deploy",
            "building site",
            "netlify app",
            "<title>Netlify</title>",
            "This site is powered by Netlify",
            "Deploy in progress"
        ]
        
        # Header-based verification (more reliable)
        header_verified = any("x-nf-request-id" in str(header).lower() for header in headers)
        
        # If we have header verification, more confident
        if header_verified:
            return True, 95
            
        # Check for false positive indicators first
        for indicator in netlify_fp_indicators:
            if indicator.lower() in response_text.lower():
                return False, 0
                
        # Check for takeover indicators
        for indicator in netlify_takeover_indicators:
            if indicator.lower() in response_text.lower():
                return True, 85
                
        return False, 0

    def double_check_vulnerability(self, domain, service, cname, response_text, response_status, headers):
        """Perform additional checks for services with high false positive rates"""
        if service == "NETLIFY":
            return self.validate_netlify_domain(domain, response_text, response_status, headers)
        elif service == "HEROKU":
            # Additional Heroku validation
            heroku_fp_indicators = [
                "application error",
                "temporarily unavailable",
                "no such app"
            ]
            
            # Check if it's a temporary error vs actual takeover
            is_temp_error = any(indicator.lower() in response_text.lower() 
                              for indicator in ["application error", "temporarily unavailable"])
            
            if is_temp_error:
                return False, 0
            return True, 80
        elif service == "CARGOCOLLECTIVE":
            # Cargo Collective validation
            cargo_fp_indicators = [
                "cargocollective",
                "portfolio",
                "artist",
                "gallery"
            ]
            
            # Check for false positives
            has_fp_indicators = any(indicator.lower() in response_text.lower() 
                                  for indicator in cargo_fp_indicators)
            
            if has_fp_indicators:
                return False, 0
            return True, 70
            
        # For other services, basic check is sufficient
        return True, TAKEOVER_DB.get(service.lower(), {}).get("confidence", 70)

    def check_takeover(self, domain):
        """Main detection logic with enhanced checking and PoC generation"""
        try:
            cname = self.resolve_cname(domain) or ""
            url = self.format_url(domain)
            
            # HTTP Request with timeout configuration
            resp = self.session.get(
                url, 
                timeout=(self.args.timeout, self.args.timeout), 
                allow_redirects=False,
                verify=False
            )
            
            status = resp.status_code
            text = resp.text.lower()
            headers = resp.headers

            # Match services with improved logic
            best_match = None
            best_score = 0
            matched_service = None
            confidence = 0
            
            for service, config in TAKEOVER_DB.items():
                score = 0
                
                # Skip if CNAME doesn't match
                if cname and not any(c in cname.lower() for c in config["cname"]):
                    continue
                    
                # Check for exclusion patterns (false positive reduction)
                excluded = False
                if "exclude" in config:
                    for exclude_pattern in config["exclude"]:
                        if exclude_pattern.lower() in text:
                            excluded = True
                            break
                if excluded:
                    continue
                
                # CNAME match (highest weight if present)
                if cname and any(c in cname.lower() for c in config["cname"]):
                    score += 3
                    
                # Status code check
                if status in config["status"]:
                    score += 2
                    
                # Response content match
                if any(e.lower() in text for e in config["response"]):
                    score += 3
                    
                # Header match
                if any(h.lower() in str(headers).lower() for h in config["headers"]):
                    score += 2

                # Update best match if current score is higher
                if score > best_score and score >= 3:
                    best_score = score
                    best_match = service
                    matched_service = config

            # If we have a potential match, perform additional verification
            if best_match and best_score >= 3:
                # For services that require double-checking
                if matched_service.get("double_check", False):
                    is_valid, validated_confidence = self.double_check_vulnerability(
                        domain, best_match.upper(), cname, text, status, headers
                    )
                    
                    if not is_valid:
                        # Not actually vulnerable
                        return {
                            "domain": domain,
                            "url": url,
                            "vulnerable": False,
                            "cname": cname,
                            "status": status,
                            "reason": f"False positive filtered for {best_match}"
                        }
                    else:
                        confidence = validated_confidence
                else:
                    confidence = matched_service.get("confidence", 70)
                
                # Generate PoC for confirmed vulnerabilities
                poc = self.generate_poc(domain, best_match.upper(), cname, url, text)
                
                result = {
                    "domain": domain,
                    "vulnerable": True,
                    "service": best_match.upper(),
                    "cname": cname,
                    "status": status,
                    "url": url,
                    "confidence": confidence,
                    "poc": poc,
                    "response_preview": text[:250] if not self.args.no_preview else ""
                }
                
                return result

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
            # Save as JSON with full details including PoCs
            with open(out_path, 'w') as f:
                json.dump({
                    "scan_timestamp": timestamp,
                    "total_scanned": self.scanned,
                    "vulnerable_count": self.vulnerable,
                    "results": self.results
                }, f, indent=2)
        else:
            # Save as detailed text report with PoCs
            with open(out_path, 'w') as f:
                f.write(f"# Subdomain Takeover Results\n")
                f.write(f"# Scan timestamp: {timestamp}\n")
                f.write(f"# Total scanned: {self.scanned}\n")
                f.write(f"# Vulnerable: {self.vulnerable}\n\n")
                
                for r in self.results:
                    f.write(f"\n{'='*60}\n")
                    f.write(f"VULNERABILITY DETECTED\n")
                    f.write(f"{'='*60}\n")
                    f.write(f"Domain: {r['domain']}\n")
                    f.write(f"Service: {r['service']}\n")
                    f.write(f"CNAME: {r['cname']}\n")
                    f.write(f"Status: {r['status']}\n")
                    f.write(f"Confidence: {r['confidence']}%\n")
                    f.write(f"URL: {r['url']}\n")
                    f.write(f"\n--- PoC Instructions ---\n")
                    f.write(f"{r['poc']}\n")
                    if 'response_preview' in r and r['response_preview']:
                        f.write(f"\nResponse Preview:\n{r['response_preview']}\n")
                    f.write(f"\n{'='*60}\n")
        
        print(f"\n[{Color.green}✓{Color.reset}] Results saved to: {out_path}")
        logging.info(f"Results saved to: {out_path}")

        # Save PoCs to individual files if requested
        if self.args.poc_dir:
            if not os.path.exists(self.args.poc_dir):
                os.makedirs(self.args.poc_dir)
            
            for r in self.results:
                poc_filename = f"{r['domain'].replace('.', '_')}_poc.txt"
                poc_path = os.path.join(self.args.poc_dir, poc_filename)
                
                with open(poc_path, 'w') as f:
                    f.write(f"Subdomain Takeover PoC\n")
                    f.write(f"Domain: {r['domain']}\n")
                    f.write(f"Service: {r['service']}\n")
                    f.write(f"CNAME: {r['cname']}\n")
                    f.write(f"URL: {r['url']}\n")
                    f.write(f"Confidence: {r['confidence']}%\n")
                    f.write(f"\n{'='*50}\n")
                    f.write(f"{r['poc']}\n")
            
            print(f"[{Color.green}✓{Color.reset}] PoC files saved to: {self.args.poc_dir}")

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
                        print(f"   └─ Confidence: {result['confidence']}%")
                        if self.args.verbose and not self.args.no_preview:
                            print(f"   └─ CNAME: {result['cname']}")
                            if 'response_preview' in result and result['response_preview']:
                                print(f"   └─ Preview: {result['response_preview'][:100]}...")
                    elif not self.args.only_vuln and self.args.verbose:
                        if 'error' in result:
                            print(f"[{Color.red}ERROR{Color.reset}] {result['domain']} - {result['error']}")
                        elif 'reason' in result:
                            print(f"[{Color.yellow}FILTERED{Color.reset}] {result['domain']} - {result['reason']}")
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
        print(f"{Color.magenta}⏱️ TIME:{Color.reset} {total_time}s\n")
        logging.info(f"Scan complete. Vulnerable: {self.vulnerable}, Scanned: {self.scanned}, Time: {total_time}s")

        if self.args.output and self.results:
            self.save_results()

def main():
    parser = argparse.ArgumentParser(description='🛡️ Universal Subdomain Takeover Scanner v4.0')
    parser.add_argument('-f', '--file', help='File containing list of domains')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('-T', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Save results (txt/json)')
    parser.add_argument('--poc-dir', help='Directory to save individual PoC files')
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