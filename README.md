 # Subdomain-Enumeration

A comprehensive tool for subdomain enumeration, malware analysis, WHOIS data retrieval, SSL/TLS certificate checks, and threat mapping. Built with React + Vite for the frontend and Flask for the backend, this tool helps you analyze and secure domains effectively.


## Features

Subdomain Enumeration**: Discover subdomains associated with a given domain.
- **Malware Analysis**: Check if a domain is flagged as malicious by security services.
- **WHOIS Data**: Retrieve domain registration and ownership details.
- **SSL/TLS Check**: Analyze SSL/TLS certificates for validity and expiration.
- **Threat Map**: Visualize the geographic distribution of threats associated with a domain.


##  Technologies Used
- **Frontend**: React, Vite, CSS
- **Backend**: Flask, SQLite
- **APIs**: VirusTotal, IPinfo, AbuseIPDB
##  Project Structure

domain-security-scanner/                                            
├──public/                                                                                                                  
├──src/                                                                 
│ ├── components                                                   
│ │ └── DomainScanner.jsx                                          
│ ├──Apps.css                                                            
│ ├── main.jsx                                                     
├──backend/                                                        
│├──Apps.py                                                                         
│ ├── subdomains.db                                                
├── README.md
## Setup Instructions

### Prerequisites

- Node.js (for frontend)
- Python 3.x (for backend)
- SQLite (for database)

### Frontend Setup

1. Navigate to the `frontend` directory:
   ```bash
   cd domain-security-scanner
## install dependencies
npm install
