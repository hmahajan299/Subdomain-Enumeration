from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import os
import asyncio
import httpx
import logging

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO, filename="app.log", format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

# Load API key from environment variable
API_KEY = os.getenv('VT_API_KEY')
if not API_KEY:
    logger.error("VirusTotal API key is not set in the environment variables.")
    raise ValueError("API key not found. Set VT_API_KEY as an environment variable.")

DB_FILE = 'subdomains_and_reports.db'

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subdomain_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            report TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Store subdomains and their reports in the database
def store_subdomains_and_reports(domain, subdomain_data):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        for subdomain, report in subdomain_data.items():
            cursor.execute('''
                INSERT INTO subdomain_reports (domain, subdomain, report)
                VALUES (?, ?, ?)
            ''', (domain, subdomain, str(report)))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")

# Fetch stored subdomains and reports from the database
def fetch_subdomains_and_reports_from_db(domain):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT subdomain, report FROM subdomain_reports
            WHERE domain = ?
        ''', (domain,))
        rows = cursor.fetchall()
        conn.close()
        return {row[0]: eval(row[1]) for row in rows}  # Convert string back to dict
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        return {}

# Asynchronous function to fetch subdomain report
async def fetch_subdomain_report(subdomain, headers):
    url = f'https://www.virustotal.com/api/v3/domains/{subdomain}'
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return subdomain, response.json().get('data', {}).get('attributes', {})

# Fetch all subdomain reports concurrently
async def fetch_all_subdomain_reports(subdomains, headers):
    tasks = [fetch_subdomain_report(sub, headers) for sub in subdomains]
    return await asyncio.gather(*tasks)

@app.route('/')
def home():
    return "Welcome to the Subdomain and Domain Report Tool API. Use /api/subdomains-reports."

@app.route('/api/subdomains-reports', methods=['POST'])
async def get_subdomains_and_reports():
    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    # Check if subdomains and reports are already stored
    stored_data = fetch_subdomains_and_reports_from_db(domain)
    if stored_data:
        return jsonify({'data': stored_data})

    # VirusTotal API headers
    headers = {'x-apikey': API_KEY}
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'

    try:
        # Fetch domain information
        response = httpx.get(url, headers=headers)
        response.raise_for_status()

        # Extract subdomains
        data = response.json().get('data', {}).get('attributes', {})
        subdomains = [record.get('value') for record in data.get('last_dns_records', []) if record.get('value')]

        if not subdomains:
            return jsonify({'error': 'No subdomains found'}), 404

        # Fetch subdomain reports concurrently
        subdomain_results = await fetch_all_subdomain_reports(subdomains, headers)

        # Process and store the results
        subdomain_data = {sub: {
            'last_analysis_stats': report.get('last_analysis_stats', {}),
            'reputation': report.get('reputation'),
            'categories': report.get('categories'),
            'last_analysis_date': report.get('last_analysis_date'),
            'tags': report.get('tags'),
            'popularity_ranks': report.get('popularity_ranks', {}),
        } for sub, report in subdomain_results}

        store_subdomains_and_reports(domain, subdomain_data)

        return jsonify({'data': subdomain_data})

    except httpx.RequestError as e:
        logger.error(f"Request error: {e}")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
