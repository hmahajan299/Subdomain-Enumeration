
import sqlite3

# Connect to SQLite database
conn = sqlite3.connect('subdomains.db')
cursor = conn.cursor()

# Create a table for subdomains
cursor.execute('''
CREATE TABLE IF NOT EXISTS subdomain_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

conn.commit()
conn.close()
