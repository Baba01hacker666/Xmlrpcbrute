#XML-RPC WordPress Authentication 
Testing Tool


#Author: baba01hacker


Version: 2.0


Purpose: Security assessment of WordPress XML-RPC endpoints
Features
✅ User Enumeration - Detect valid usernames via XML-RPC error messages
✅ Single Password Testing - Quick validation of specific credentials
✅ Dictionary Attack - Bruteforce passwords for a single user
✅ Password Spray - Test multiple users with common passwords (stealthier)
✅ Method Enumeration - List available XML-RPC methods
✅ Rate Limiting - Configurable delays to avoid detection
✅ Proxy Support - Route through Burp Suite/ZAP for traffic inspection
✅ Results Export - Save discovered credentials to file
Installation
# Requires Python 3.6+
pip install requests --break-system-packages
Usage Examples
User Enumeration
# Check if single user exists
python3 xmlrpc_auth_tool.py -u https://target.com --enum-user david

# Enumerate from wordlist
python3 xmlrpc_auth_tool.py -u https://target.com --user-file sample_users.txt
Password Testing
# Test single credential pair
python3 xmlrpc_auth_tool.py -u https://target.com --username david --password Test123

# Bruteforce single user
python3 xmlrpc_auth_tool.py -u https://target.com --username david -p sample_passwords.txt

# With delay (recommended)
python3 xmlrpc_auth_tool.py -u https://target.com --username david -p sample_passwords.txt --delay 1
Password Spray Attack
# Spray passwords across multiple users (avoids lockouts)
python3 xmlrpc_auth_tool.py -u https://target.com --user-file sample_users.txt -p sample_passwords.txt --spray --delay 2

# Stop on first success
python3 xmlrpc_auth_tool.py -u https://target.com --user-file sample_users.txt -p sample_passwords.txt --spray
Advanced Options
# Through Burp Suite proxy
python3 xmlrpc_auth_tool.py -u https://target.com --username admin -p passwords.txt --proxy http://127.0.0.1:8080 --no-ssl-verify

# List XML-RPC methods
python3 xmlrpc_auth_tool.py -u https://target.com --list-methods

# Save results and continue after finding creds
python3 xmlrpc_auth_tool.py -u https://target.com --username admin -p passwords.txt --continue --output results.txt

# Verbose output
python3 xmlrpc_auth_tool.py -u https://target.com --username admin -p passwords.txt -v
Command-Line Options
Required:
  -u, --url              Target WordPress URL

User Enumeration:
  --enum-user            Check if single user exists
  --user-file            Username wordlist file

Authentication:
  --username             Username for password testing
  --password             Single password to test
  -p, --password-file    Password wordlist file

Attack Modes:
  --spray                Password spray mode (requires --user-file and -p)
  --list-methods         Enumerate XML-RPC methods

Advanced:
  --delay                Delay between requests (seconds)
  --continue             Continue after finding valid credentials
  --output, -o           Save results to file
  --proxy                Proxy URL (e.g., http://127.0.0.1:8080)
  --no-ssl-verify        Disable SSL certificate verification
  -v, --verbose          Verbose output
Attack Strategies
1. Reconnaissance Phase
# List available methods to identify attack surface
python3 xmlrpc_auth_tool.py -u https://target.com --list-methods

# Enumerate valid usernames
python3 xmlrpc_auth_tool.py -u https://target.com --user-file sample_users.txt
2. Targeted Bruteforce
# Attack specific high-value account (admin, root, etc.)
python3 xmlrpc_auth_tool.py -u https://target.com --username admin -p rockyou.txt --delay 0.5
3. Stealthy Password Spray
# Test common passwords across all users (avoids account lockouts)
python3 xmlrpc_auth_tool.py -u https://target.com --user-file users.txt -p common_passwords.txt --spray --delay 3
Testing Your Own Site
For testing your david low-privilege user:
# Quick test
python3 xmlrpc_auth_tool.py -u https://your-site.com --username david --password YourTestPassword

# Dictionary attack
python3 xmlrpc_auth_tool.py -u https://your-site.com --username david -p sample_passwords.txt --delay 1
Defense Recommendations
Based on this tool's techniques, implement these defenses:
Disable XML-RPC if not needed:
# In wp-config.php
add_filter('xmlrpc_enabled', '__return_false');
Rate Limiting - Limit requests to /xmlrpc.php
Account Lockout - Lock accounts after N failed attempts
WAF Rules - Block repeated wp.getUsersBlogs calls
Monitor Logs - Alert on:
Multiple authentication failures
system.listMethods calls
Sequential user enumeration attempts
2FA/MFA - Enforce multi-factor authentication
Strong Password Policy - Prevent common/weak passwords
IP Blocking - Use fail2ban to block malicious IPs
Legal Notice
⚠️ FOR AUTHORIZED SECURITY TESTING ONLY
This tool is intended for:
Penetration testing your own systems
Red team engagements with written authorization
Security research in controlled environments
Educational purposes on test systems
Unauthorized access to computer systems is illegal. Always obtain explicit written permission before testing.
Blog Content Ideas
XML-RPC attack vectors and exploitation techniques
Password spray vs bruteforce: stealth comparison
WordPress hardening guide
Building detection rules for XML-RPC attacks
Real-world case studies of XML-RPC compromises
Support
For issues, improvements, or questions:
Create detailed bug reports
Include verbose output (-v flag)
Share your use cases for feature requests
Happy Hacking (Ethically)! 🔐
-- baba01hacker
