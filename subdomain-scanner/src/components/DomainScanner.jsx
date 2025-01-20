import React, { useState } from "react";
import "./DomainScanner.jsx"; // Custom styles

const DomainScanner = () => {
  const [domain, setDomain] = useState("");
  const [results, setResults] = useState("");
  const [malwareResults, setMalwareResults] = useState("");
  const [whoisResults, setWhoisResults] = useState("");

  const handleInputChange = (event) => {
    setDomain(event.target.value);
  };

  const validateDomain = () => {
    if (!domain.trim()) {
      return "Please enter a valid domain.";
    }
    return null;
  };

  const fetchData = async (url, setResultState, resultType) => {
    const validationError = validateDomain();
    if (validationError) {
      setResultState(validationError);
      return;
    }

    setResultState(`Fetching ${resultType}...`);

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });

      const data = await response.json();
      if (data.error) {
        setResultState(`Error: ${data.error}`);
      } else {
        const resultData =
          resultType === "subdomains"
            ? data.subdomains
            : resultType === "malware analysis"
            ? data.malwareAnalysis
            : data.whois;

        setResultState(formatResults(resultData));
      }
    } catch (error) {
      setResultState(`Error fetching ${resultType}. Please try again.`);
    }
  };

  const fetchSubdomains = () => {
    fetchData("http://127.0.0.1:5000/api/subdomains", setResults, "subdomains");
  };

  const fetchMalwareAnalysis = () => {
    fetchData("http://127.0.0.1:5000/api/malware", setMalwareResults, "malware analysis");
  };

  const fetchWhoisData = () => {
    fetchData("http://127.0.0.1:5000/api/whois", setWhoisResults, "WHOIS data");
  };

  const formatResults = (results) => {
    if (Array.isArray(results)) {
      return (
        <ul className="bullet-list">
          {results.map((result, index) => (
            <li key={index}>{result}</li>
          ))}
        </ul>
      );
    }

    if (typeof results === "object") {
      return (
        <div className="whois-details">
          {Object.entries(results).map(([key, value]) => (
            <p key={key}>
              <strong>{key}:</strong> {value}
            </p>
          ))}
        </div>
      );
    }

    return results;
  };

  return (
    <div className="scanner-container">
      <header className="scanner-header">
        <div className="icon">🔒</div>
        <h1>Domain Security Scanner</h1>
        <p>Subdomain Enumeration, Malware Analysis, & WHOIS Data</p>
      </header>

      <div className="input-section">
        <input
          type="text"
          className="domain-input"
          placeholder="Enter domain (e.g., example.com)"
          value={domain}
          onChange={handleInputChange}
        />
        <div className="button-group">
          <button className="scan-button" onClick={fetchSubdomains}>
            🔍 Subdomain Scan
          </button>
          <button className="scan-button malware-button" onClick={fetchMalwareAnalysis}>
            🛡️ Malware Analysis
          </button>
          <button className="scan-button whois-button" onClick={fetchWhoisData}>
            🌐 WHOIS Data
          </button>
        </div>
      </div>

      <div className="results-section">
        <div className="result-block">
          <h3>Subdomain Results:</h3>
          <div className="result-content">{results || "No results yet."}</div>
        </div>
        <div className="result-block">
          <h3>Malware Analysis Results:</h3>
          <div className="result-content">{malwareResults || "No results yet."}</div>
        </div>
        <div className="result-block">
          <h3>WHOIS Data:</h3>
          <div className="result-content">{whoisResults || "No results yet."}</div>
        </div>
      </div>
    </div>
  );
};

export default DomainScanner;
