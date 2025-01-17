// src/components/DomainScanner.jsx
import React, { useState } from "react";

const DomainScanner = () => {
  const [domain, setDomain] = useState("");
  const [results, setResults] = useState("");

  const fetchSubdomains = async () => {
    setResults("Fetching subdomains...");
    if (!domain.trim()) {
      setResults("Please enter a valid domain.");
      return;
    }

    try {
      const response = await fetch("http://127.0.0.1:5000/api/subdomains", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });

      const data = await response.json();
      if (data.error) {
        setResults(`Error: ${data.error}`);
      } else {
        setResults(JSON.stringify(data.subdomains, null, 2));
      }
    } catch (error) {
      setResults("Error fetching subdomains. Please try again.");
    }
  };

  return (
    <div className="container">
      <div className="header">
        <div className="icon">🔒</div>
        <h1>Domain Security Scanner</h1>
        <p>Subdomain Enumeration & Malware Analysis</p>
      </div>
      <div className="search-box">
        <input
          type="text"
          placeholder="Enter domain (e.g., example.com)"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
        />
        <button onClick={fetchSubdomains}>🔍 Scan</button>
      </div>
      <div className="results">
        <pre>{results}</pre>
      </div>
    </div>
  );
};

export default DomainScanner;
