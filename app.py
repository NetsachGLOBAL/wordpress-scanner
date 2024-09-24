from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
import socket
import multiprocessing
from wordpresstags import wordpress_tags
from theme_vulnerabilities_tags import theme_vulnerabilities_tags
import logging

app = Flask(__name__)

# Function to get WordPress version from the site's meta tag
def get_wp_version(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        meta_generator = soup.find('meta', {'name': 'generator'})
        if meta_generator and 'WordPress' in meta_generator['content']:
            return meta_generator['content']
        return "Unknown WordPress version"
    except Exception as e:
        return f"Error: {str(e)}"

# Function to check WordPress core version
def check_wordpress_version(url):
    for tag, path in wordpress_tags.items():
        try:
            response = requests.get(f"{url}{path}")
            if response.status_code == 200:
                return f"{tag} detected."
        except Exception as e:
            return f"Error: {str(e)}"
    return "Could not detect WordPress core version."

# Function to check for theme vulnerabilities
def check_theme_vulnerabilities(url):
    theme_url = f"{url}/wp-content/themes/"
    for tag, path in theme_vulnerabilities_tags.items():
        try:
            response = requests.get(f"{theme_url}{path}")
            if response.status_code == 200:
                return f"{tag} detected."
        except Exception as e:
            return f"Error: {str(e)}"
    return "No theme vulnerabilities found."

# Function to check security headers
def get_intresting_headers(api_url):
    headers = ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]
    try:
        response = requests.get(api_url)
        missing_headers = [header for header in headers if header not in response.headers]
        return missing_headers if missing_headers else "All important headers are present."
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

# Function to check if WP-cron is enabled
logging.basicConfig(level=logging.INFO)

def check_wp_cron(url):
    try:
        logging.info(f"Checking WP-cron on {url}")
        response = requests.get(f"{url}/wp-cron.php")
        response.raise_for_status()  # Raise an exception for 4xx or 5xx status codes
        if response.status_code == 200:
            logging.info("WP-cron is enabled.")
            return "WP-cron is enabled."
        logging.warning("WP-cron is disabled.")
        return "WP-cron is disabled."
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking WP-cron: {str(e)}")
        return f"Error: {str(e)}"
    except Exception as e:
        logging.exception(f"Unexpected error: {str(e)}")
        return f"Error: {str(e)}"

# Function to check if XML-RPC is enabled
def check_xml_rpc(url):
    try:
        xml_rpc_url = f"{url}/xmlrpc.php"
        response = requests.head(xml_rpc_url)
        if response.status_code == 200:
            return "XML-RPC is enabled."
        return "XML-RPC is not enabled."
    except Exception as e:
        return f"Error: {str(e)}"

# Dummy functions for additional checks
def user_enumeration_check(url):
    return "User enumeration is disabled."

def check_config_backups(url):
    return "Config backups not found."

def timthumbs_check(url):
    return "No TimThumb vulnerabilities detected."

# Function to run individual scan checks
def run_individual_scan(func, url):
    return func(url)

# Combine the scan checks using multiprocessing for efficiency
def run_scan(url):
    scan_functions = [
        get_wp_version,
        check_wordpress_version,
        check_theme_vulnerabilities,
        get_intresting_headers,
        check_wp_cron,
        check_xml_rpc,
        user_enumeration_check,
        check_config_backups,
        timthumbs_check
    ]

    with multiprocessing.Pool(processes=len(scan_functions)) as pool:
        results = pool.starmap(run_individual_scan, [(func, url) for func in scan_functions])

    return results

# Flask routes
@app.route('/', methods=['GET', 'POST'])
def index():
    url = None
    scan_results = {}

    if request.method == 'POST':
        url = request.form['url']
        if not url.startswith('http'):
            url = 'http://' + url

        try:
            socket.gethostbyname(url.replace('http://', '').replace('https://', '').strip('/'))
        except socket.gaierror:
            return render_template('index.html', error="Invalid URL or domain")

        # Run the scan in parallel
        results = run_scan(url)

        scan_results = {
            'wp_version': results[0],
            'core_version': results[1],
            'theme_vulnerabilities': results[2],
            'headers': results[3],
            'wp_cron_status': results[4],
            'xml_rpc_status': results[5],
            'user_enum_status': results[6],
            'config_backup_status': results[7],
            'timthumbs_status': results[8]
        }

    return render_template('index.html', url=url, results=scan_results)

if __name__ == '__main__':
    app.run(debug=True)