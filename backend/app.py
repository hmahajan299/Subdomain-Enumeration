from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import sqlite3
import ssl
import socket
import ipinfo
import subprocess
from datetime import datetime, timedelta
from flask import render_template, make_response
from weasyprint import HTML
from flask_cors import cross_origin
app = Flask(__name__)
CORS(app)

# Constants
API_KEY = '270d112f0b8b37910aafe4c612ad5b93ffae8fd48ab0b2f68c4c9723acf2e90f'
DB_FILE = 'subdomains.db'
IPINFO_TOKEN = '4d0115912feee5'
ABUSEIPB_KEY = '7e9cd5d791817a00bd8ee844c00cdc5b426fb50fd12e9bddc6c2d991c14d4b580dbfcfed099d397b'

# Initialize IPinfo handler
ipinfo_handler = ipinfo.getHandler(IPINFO_TOKEN)

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Create table for scan results
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            subdomain TEXT,
            ip_address TEXT,
            hostname TEXT,
            open_ports TEXT,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Create table for subdomain results (if not already present)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS subdomain_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            subdomain TEXT
        )
    """)
    # Create table for malware analysis (if needed)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS malware_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            analysis TEXT
        )
    """)
    conn.commit()
    conn.close()

def run_nmap_scan(subdomain):
    """Runs Nmap scan on a subdomain and returns IP, hostname, and open ports."""
    try:
        result = subprocess.check_output(['nmap', '-Pn', '-sV', subdomain], text=True)
        try:
            ip_address = socket.gethostbyname(subdomain)
        except Exception as e:
            print(f"Error resolving {subdomain}: {e}")
            ip_address = "Unknown"
        hostname = subdomain
        open_ports = []
        for line in result.splitlines():
            if "/tcp" in line or "/udp" in line:
                open_ports.append(line.strip())
        open_ports = "\n".join(open_ports)
        print(f"Nmap scan for {subdomain}: IP={ip_address}, Ports={open_ports}")
        return ip_address, hostname, open_ports
    except Exception as e:
        print(f"Error scanning {subdomain}: {e}")
        return None, None, None

def store_scan_results(domain, subdomain, ip, hostname, open_ports):
    """Stores the scan results in the database."""
    query = """
        INSERT INTO scan_results (domain, subdomain, ip_address, hostname, open_ports)
        VALUES (?, ?, ?, ?, ?)
    """
    execute_query(query, (domain, subdomain, ip, hostname, open_ports))

def classify_threat(threat_level):
    if threat_level.lower() == "critical":
        return "red"
    elif threat_level.lower() == "warning":
        return "yellow"
    else:
        return "green"

def connect_db():
    return sqlite3.connect(DB_FILE)

def execute_query(query, params=(), fetch=False, fetch_one=False, batch=False):
    conn = connect_db()
    cursor = conn.cursor()
    try:
        if batch:
            cursor.executemany(query, params)
        else:
            cursor.execute(query, params)
        result = None
        if fetch:
            result = cursor.fetchone() if fetch_one else cursor.fetchall()
        conn.commit()
        return result
    finally:
        conn.close()

def fetch_ssl_details(domain):
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
    try:
        ipapi_url = f"https://ipapi.co/{ip}/json/"
        ipapi_response = requests.get(ipapi_url).json()
        abuse_url = "https://api.abuseipdb.com/api/v2/check"
        abuse_headers = {'Key': ABUSEIPB_KEY}
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
    query = 'SELECT subdomain FROM subdomain_results WHERE domain = ?'
    rows = execute_query(query, (domain,), fetch=True)
    return [row[0] for row in rows]

def store_subdomains(domain, subdomains):
    query = 'INSERT INTO subdomain_results (domain, subdomain) VALUES (?, ?)'
    data = [(domain, sub) for sub in subdomains]
    execute_query(query, data, batch=True)

def store_malware_analysis(domain, analysis):
    query = 'INSERT INTO malware_results (domain, analysis) VALUES (?, ?)'
    execute_query(query, (domain, analysis))

def fetch_malware_analysis_from_db(domain):
    query = 'SELECT analysis FROM malware_results WHERE domain = ?'
    row = execute_query(query, (domain,), fetch=True, fetch_one=True)
    return row[0] if row else None

def get_ip_geodata(ip):
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



@app.route('/api/generate-report', methods=['POST','OPTIONS'])
@cross_origin()
def generate_report():
    domain = request.json.get("domain")
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    # Retrieve data from your existing functions
    subdomains = fetch_subdomains_from_db(domain)
    scan_rows = execute_query("SELECT subdomain, ip_address, hostname, open_ports FROM scan_results WHERE domain = ?", (domain,), fetch=True)
    nmap_results = []
    if scan_rows:
        for row in scan_rows:
            nmap_results.append({
                "subdomain": row[0],
                "ip_address": row[1],
                "hostname": row[2],
                "open_ports": row[3]
            })
    malware = fetch_malware_analysis_from_db(domain) or "No malware analysis available."

    # Retrieve WHOIS data via VT API (or use stored data if available)
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        whois_raw = response.json().get('data', {}).get('attributes', {}).get('whois')
        whois = {}
        if whois_raw:
            for line in whois_raw.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    whois[key.strip()] = value.strip()
    except Exception as e:
        whois = {"error": str(e)}

    ssl_details = fetch_ssl_details(domain)

    # For threat map, retrieve geodata for subdomains
    subs_for_threat = fetch_subdomains_from_db(domain)
    ips = []
    for sub in subs_for_threat:
        try:
            ip = socket.gethostbyname(sub)
            ips.append(ip)
        except Exception:
            pass
    threat_map = [get_ip_geodata(ip) for ip in set(ips)]
    threat_map = [item for item in threat_map if item and item.get('coords')]

    # Render the HTML template with the gathered data
    html_out = render_template("report_template.html", 
                               domain=domain,
                               subdomains=subdomains,
                               nmap_results=nmap_results,
                               malware=malware,
                               whois=whois,
                               ssl=ssl_details,
                               threat_map=threat_map)
    pdf = HTML(string=html_out).write_pdf()
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=report_{domain}.pdf'
    return response
@app.route('/scan/<domain>', methods=['GET'])
def scan_domain(domain):
    subdomains = fetch_subdomains_from_db(domain)
    if not subdomains:
        return jsonify({"error": "No subdomains found for this domain."}), 404
    for sub in subdomains:
        ip, hostname, open_ports = run_nmap_scan(sub)
        if ip:
            store_scan_results(domain, sub, ip, hostname, open_ports)
    return jsonify({"status": "Scan completed and results stored."})

@app.route('/api/scan-results/<domain>', methods=['GET'])
def get_scan_results(domain):
    query = 'SELECT subdomain, ip_address, hostname, open_ports FROM scan_results WHERE domain = ?'
    rows = execute_query(query, (domain,), fetch=True)
    results = []
    if rows:
        for row in rows:
            results.append({
                "subdomain": row[0],
                "ip_address": row[1],
                "hostname": row[2],
                "open_ports": row[3]
            })
    return jsonify(results)

@app.route('/')
def home():
    return "Welcome to the Domain Security Tool API! Use /api/subdomains, /api/malware, /api/whois, /api/reputation, /api/ssl, or /api/threat-map"

@app.route('/api/threat-status', methods=['POST'])
def check_domain_threats():
    domain = request.json.get('domain')
    # Placeholder since get_threat_data is not defined
    threats = {}
    threat_results = []
    for subdomain, level in threats.items():
        color = classify_threat(level)
        threat_results.append({"subdomain": subdomain, "threat_level": level, "color": color})
    return jsonify({"domain": domain, "threat_results": threat_results})

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
    try:
        subfinder_output = subprocess.check_output(
            ['subfinder', '-d', domain, '-silent'],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip().split('\n')
        subdomains = list(filter(None, subfinder_output))
        if subdomains:
            store_subdomains(domain, subdomains)
            return jsonify({'subdomains': subdomains})
    except subprocess.CalledProcessError:
        pass
    url = f'https://www.virustotal.com/api/v3/domains/{domain}/subdomains'
    headers = {'x-apikey': API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        subdomains = [sub['id'] for sub in response.json().get('data', [])]
        if subdomains:
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
    try:
        subdomains = fetch_subdomains_from_db(domain)
        ips = []
        for sub in subdomains:
            try:
                ip = socket.gethostbyname(sub)
                ips.append(ip)
            except:
                pass
        geo_data = [get_ip_geodata(ip) for ip in set(ips)]
        return jsonify([gd for gd in geo_data if gd and gd.get('coords')])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
