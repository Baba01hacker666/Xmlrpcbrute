def check_xmlrpc_enabled(url):
    try:
        response = requests.post(url, data={'dummy': 'test'})
        if response.status_code == 200:
            return True
        elif response.status_code == 405:
            print("HTTP 405: Method Not Allowed. The server does not support POST requests.")
            return False
        else:
            print(f"Unexpected status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return False
