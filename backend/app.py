from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import sqlite3
import ssl
import socket
import ipinfo
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# Constants
API_KEY = '270d112f0b8b37910aafe4c612ad5b93ffae8fd48ab0b2f68c4c9723acf2e90f'
DB_FILE = 'subdomains.db'
IPINFO_TOKEN = '4d0115912feee5'
ABUSEIPB_KEY = '7e9cd5d791817a00bd8ee844c00cdc5b426fb50fd12e9bddc6c2d991c14d4b580dbfcfed099d397b'

# Initialize IPinfo handler
ipinfo_handler = ipinfo.getHandler(IPINFO_TOKEN)

def connect_db():
    """Establishes a connection to the database."""
    return sqlite3.connect(DB_FILE)

def execute_query(query, params=(), fetch=False, fetch_one=False):
    """Executes a query on the database and handles connection management."""
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute(query, params)
    result = None
    if fetch:
        result = cursor.fetchone() if fetch_one else cursor.fetchall()
    conn.commit()
    conn.close()
    return result

def fetch_ssl_details(domain):
    """Fetches SSL/TLS certificate details for the domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert['issuer'])['organizationName']
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y GMT')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')

        return {
            "issuer": issuer,
            "valid_from": not_before.strftime('%Y-%m-%d %H:%M:%S'),
            "valid_until": not_after.strftime('%Y-%m-%d %H:%M:%S'),
            "expired": datetime.now() > not_after,
            "about_to_expire": datetime.now() + timedelta(days=30) > not_after,
        }
    except Exception as e:
        return {"error": f"Failed to fetch SSL/TLS details: {str(e)}"}
def get_ip_details(ip):
    """Get detailed IP information from multiple APIs"""
    try:
        # IPAPI Data
        ipapi_url = f"https://ipapi.co/{ip}/json/"
        ipapi_response = requests.get(ipapi_url).json()
        
        # AbuseIPDB Data
        abuse_url = "https://api.abuseipdb.com/api/v2/check"
        abuse_headers = {'Key': ABUSEIPDB_KEY}
        abuse_params = {'ipAddress': ip}
        abuse_response = requests.get(abuse_url, headers=abuse_headers, params=abuse_params).json()
        
        return {
            "isp": ipapi_response.get("org"),
            "asn": ipapi_response.get("asn"),
            "threat_score": abuse_response.get("data", {}).get("abuseConfidenceScore"),
            "reports": abuse_response.get("data", {}).get("totalReports"),
            "last_reported": abuse_response.get("data", {}).get("lastReportedAt")
        }
    except Exception as e:
        return {"error": str(e)}
def fetch_domain_reputation(domain):
    """Fetches domain reputation data."""
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json().get('data', {}).get('attributes', {})
        return data.get('reputation', None), data.get('categories', [])
    except requests.exceptions.RequestException:
        return None, None

def fetch_subdomains_from_db(domain):
    """Fetches stored subdomains from the database."""
    query = 'SELECT subdomain FROM subdomain_results WHERE domain = ?'
    rows = execute_query(query, (domain,), fetch=True)
    return [row[0] for row in rows]

def store_subdomains(domain, subdomains):
    """Stores subdomain results in the database."""
    query = 'INSERT INTO subdomain_results (domain, subdomain) VALUES (?, ?)'
    execute_query(query, [(domain, subdomain) for subdomain in subdomains])

def store_malware_analysis(domain, analysis):
    """Stores malware analysis results in the database."""
    query = 'INSERT INTO malware_results (domain, analysis) VALUES (?, ?)'
    execute_query(query, (domain, analysis))

def fetch_malware_analysis_from_db(domain):
    """Fetches stored malware analysis results from the database."""
    query = 'SELECT analysis FROM malware_results WHERE domain = ?'
    row = execute_query(query, (domain,), fetch=True, fetch_one=True)
    return row[0] if row else None

def get_ip_geodata(ip):
    """Get geolocation data for an IP address"""
    try:
        details = ipinfo_handler.getDetails(ip)
        return {
            "ip": ip,
            "country": details.country_name,
            "city": details.city,
            "coords": [float(x) for x in details.loc.split(",")] if details.loc else [0, 0]
        }
    except:
        return None

@app.route('/')
def home():
    return "Welcome to the Domain Security Tool API! Use /api/subdomains, /api/malware, /api/whois, /api/reputation, /api/ssl, or /api/threat-map"

@app.route('/api/ssl', methods=['POST'])
def get_ssl_details():
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    ssl_details = fetch_ssl_details(domain)
    if "error" in ssl_details:
        return jsonify({'error': ssl_details['error']}), 500

    return jsonify({'sslDetails': ssl_details})

@app.route('/api/malware', methods=['POST'])
def get_malware_analysis():
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    stored_analysis = fetch_malware_analysis_from_db(domain)
    if stored_analysis:
        return jsonify({'malwareAnalysis': stored_analysis})

    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

        analysis_summary = (
            f"Harmless: {stats.get('harmless', 0)}, "
            f"Malicious: {stats.get('malicious', 0)}, "
            f"Suspicious: {stats.get('suspicious', 0)}, "
            f"Undetected: {stats.get('undetected', 0)}"
        )

        store_malware_analysis(domain, analysis_summary)
        return jsonify({'malwareAnalysis': analysis_summary})
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f"Failed to fetch malware analysis: {str(e)}"}), 500

@app.route('/api/reputation', methods=['POST'])
def get_domain_reputation():
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    reputation_score, categories = fetch_domain_reputation(domain)
    if reputation_score is None:
        return jsonify({'error': 'Failed to fetch reputation data'}), 500

    return jsonify({'reputationScore': reputation_score, 'categories': categories})

@app.route('/api/subdomains', methods=['POST'])
def get_subdomains():
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    stored_subdomains = fetch_subdomains_from_db(domain)
    if stored_subdomains:
        return jsonify({'subdomains': stored_subdomains})

    url = f'https://www.virustotal.com/api/v3/domains/{domain}/subdomains'
    headers = {'x-apikey': API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        subdomains = [sub['id'] for sub in response.json().get('data', [])]
        store_subdomains(domain, subdomains)
        return jsonify({'subdomains': subdomains})
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f"Failed to fetch subdomains: {str(e)}"}), 500

@app.route('/api/whois', methods=['POST'])
def get_whois_data():
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        whois_data = response.json().get('data', {}).get('attributes', {}).get('whois')
        
        structured_whois = {}
        if whois_data:
            for line in whois_data.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    structured_whois[key.strip()] = value.strip()
        
        return jsonify({'whois': structured_whois or 'WHOIS data not available for this domain.'})
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f"Failed to fetch WHOIS data: {str(e)}"}), 500

@app.route('/api/threat-map/<domain>')
def get_threat_map(domain):
    """Endpoint for threat map geolocation data"""
    try:
        subdomains = fetch_subdomains_from_db(domain)
        ips = []
        for sub in subdomains:
            try:
                ip = socket.gethostbyname(sub)
                ips.append(ip)
            except: pass
        
        geo_data = [get_ip_geodata(ip) for ip in set(ips)]
        return jsonify([gd for gd in geo_data if gd and gd.get('coords')])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)