# WordPress XML-RPC Authentication Testing Tool

import requests

# Define a function to check if XML-RPC is enabled

def check_xmlrpc_enabled(url):
    try:
        # Send a POST request to the XML-RPC endpoint
        response = requests.post(url, data="<?xml version='1.0'?><methodCall><methodName>demo.sayHello</methodName></methodCall>", headers={'Content-Type': 'text/xml'})
        
        # Check for 200 OK response
        if response.status_code == 200:
            return True
        # If we receive a 405 Method Not Allowed, it means XML-RPC is not enabled
        elif response.status_code == 405:
            return False
        else:
            return False
    except requests.exceptions.RequestException as e:
        print(f'Error: {e}')
        return False

# Example usage
if __name__ == '__main__':
    url = 'http://example.com/xmlrpc.php'
    if check_xmlrpc_enabled(url):
        print('XML-RPC is enabled.')
    else:
        print('XML-RPC is not enabled.')