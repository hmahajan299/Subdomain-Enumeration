from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import sqlite3

app = Flask(__name__)
CORS(app)

API_KEY = '270d112f0b8b37910aafe4c612ad5b93ffae8fd48ab0b2f68c4c9723acf2e90f'  # Replace with your VirusTotal API key
DB_FILE = 'subdomains.db'

def store_subdomains(domain, subdomains):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    for subdomain in subdomains:
        cursor.execute('INSERT INTO subdomain_results (domain, subdomain) VALUES (?, ?)', (domain, subdomain))
    conn.commit()
    conn.close()

def fetch_subdomains_from_db(domain):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT subdomain FROM subdomain_results WHERE domain = ?', (domain,))
    rows = cursor.fetchall()
    conn.close()
    return [row[0] for row in rows]

def store_malware_analysis(domain, analysis):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO malware_results (domain, analysis) VALUES (?, ?)', (domain, analysis))
    conn.commit()
    conn.close()

def fetch_malware_analysis_from_db(domain):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT analysis FROM malware_results WHERE domain = ?', (domain,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

@app.route('/')
def home():
    return "Welcome to the Subdomain Tool API. Use the /api/subdomains and /api/malware endpoints."

@app.route('/api/subdomains', methods=['POST'])
def get_subdomains():
    data = request.get_json()
    domain = data.get('domain')
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
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/whois', methods=['POST'])
def get_whois_data():
    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        domain_data = response.json()

        whois_data = domain_data.get('data', {}).get('attributes', {}).get('whois', None)
        if whois_data:
            return jsonify({'whois': whois_data})
        else:
            return jsonify({'error': 'WHOIS data not available for this domain.'}), 404
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/malware', methods=['POST'])
def get_malware_analysis():
    data = request.get_json()
    domain = data.get('domain')
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
        analysis_data = response.json().get('data', {}).get('attributes', {})
        last_analysis_stats = analysis_data.get('last_analysis_stats', {})
        analysis_summary = f"Harmless: {last_analysis_stats.get('harmless', 0)}, " \
                           f"Malicious: {last_analysis_stats.get('malicious', 0)}, " \
                           f"Suspicious: {last_analysis_stats.get('suspicious', 0)}, " \
                           f"Undetected: {last_analysis_stats.get('undetected', 0)}"
        
        store_malware_analysis(domain, analysis_summary)
        return jsonify({'malwareAnalysis': analysis_summary})
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
