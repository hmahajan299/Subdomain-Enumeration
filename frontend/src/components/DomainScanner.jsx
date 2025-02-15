import React, { useState, useEffect } from "react";
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";
import "./DomainScanner.jsx";

const DomainScanner = () => {
  // State declarations
  const [domain, setDomain] = useState("");
  const [subdomainResults, setSubdomainResults] = useState([]); // List of subdomains
  const [nmapResults, setNmapResults] = useState([]); // Array of Nmap scan results
  const [malwareResults, setMalwareResults] = useState("");
  const [whoisResults, setWhoisResults] = useState("");
  const [sslResults, setSslResults] = useState("");
  const [threatMapData, setThreatMapData] = useState([]);
  const [selectedIp, setSelectedIp] = useState(null);
  const [tooltipPosition, setTooltipPosition] = useState({ x: 0, y: 0 });

  // Helper: Format object or array results to JSX
  const formatResults = (results) => {
    if (Array.isArray(results)) {
      return (
        <ul className="bullet-list">
          {results.map((item, idx) => (
            <li key={idx}>{item}</li>
          ))}
        </ul>
      );
    } else if (typeof results === "object" && results !== null) {
      return (
        <div className="details-grid">
          {Object.entries(results).map(([key, value]) => (
            <div className="detail-item" key={key}>
              <div className="detail-key">{key}:</div>
              <div className="detail-value">{value}</div>
            </div>
          ))}
        </div>
      );
    } else {
      return results;
    }
  };

  // Input change handler
  const handleInputChange = (e) => {
    setDomain(e.target.value);
  };

  // Basic domain validation
  const validateDomain = () => domain.trim() !== "";

  // Fetch subdomain list from /api/subdomains
  const fetchSubdomainList = async () => {
    if (!validateDomain()) {
      alert("Please enter a valid domain.");
      return;
    }
    try {
      const res = await fetch("http://127.0.0.1:5000/api/subdomains", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      const data = await res.json();
      if (data.error) {
        alert(`Error: ${data.error}`);
      } else {
        // Expecting data: { subdomains: ["sub1.example.com", ...] }
        setSubdomainResults(data.subdomains || []);
      }
    } catch (error) {
      console.error("Error fetching subdomains:", error);
    }
  };

  // Fetch Nmap scan results: first trigger the scan, then fetch stored results.
  const fetchNmapResults = async () => {
    if (!validateDomain()) {
      alert("Please enter a valid domain.");
      return;
    }
    try {
      // Trigger the Nmap scan
      const scanResponse = await fetch(`http://127.0.0.1:5000/scan/${domain}`);
      const scanData = await scanResponse.json();
      console.log("Scan status:", scanData);

      // Now retrieve the stored scan results
      const res = await fetch(`http://127.0.0.1:5000/api/scan-results/${domain}`);
      const data = await res.json();
      console.log("Nmap scan results received:", data);
      if (data.error) {
        alert(`Error: ${data.error}`);
      } else {
        if (Array.isArray(data)) {
          setNmapResults(data);
        } else {
          console.error("Unexpected Nmap results format:", data);
          setNmapResults([]);
        }
      }
    } catch (error) {
      console.error("Error fetching Nmap results:", error);
    }
  };

  // Generic function to fetch data (malware, WHOIS, SSL/TLS)
  const fetchData = async (url, setResult, resultType) => {
    if (!validateDomain()) {
      setResult("Please enter a valid domain.");
      return;
    }
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      const data = await res.json();
      if (data.error) {
        setResult(`Error: ${data.error}`);
      } else {
        if (resultType === "malware analysis") {
          setMalwareResults(data.malwareAnalysis || "No results found.");
        } else if (resultType === "WHOIS data") {
          setWhoisResults(
            typeof data.whois === "object" && data.whois !== null
              ? formatResults(data.whois)
              : (data.whois || "No results found.")
          );
        } else if (resultType === "SSL/TLS details") {
          setSslResults(
            typeof data.sslDetails === "object" && data.sslDetails !== null
              ? formatResults(data.sslDetails)
              : (data.sslDetails || "No results found.")
          );
        }
      }
    } catch (error) {
      console.error(`Error fetching ${resultType}:`, error);
      setResult(`Error fetching ${resultType}. Please try again.`);
    }
  };

  // Fetch threat map data from /api/threat-map/:domain
  const fetchThreatMap = async () => {
    if (!validateDomain()) return;
    try {
      const res = await fetch(`http://127.0.0.1:5000/api/threat-map/${domain}`);
      const data = await res.json();
      setThreatMapData(data.filter((item) => item?.coords && item.coords.length === 2));
    } catch (error) {
      console.error("Error fetching threat map data:", error);
      setThreatMapData([]);
    }
  };

  // Hide tooltip on click outside or scroll
  useEffect(() => {
    const handleClickOutside = () => setSelectedIp(null);
    const handleScroll = () => setSelectedIp(null);
    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("scroll", handleScroll);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("scroll", handleScroll);
    };
  }, []);

  return (
    <div className="scanner-container">
      <header className="scanner-header">
        <div className="icon">🔒</div>
        <h1>Domain Security Scanner</h1>
        <p>
          Subdomain Enumeration, Malware Analysis, WHOIS Data, SSL/TLS Check, Threat Map, Nmap Scan
        </p>
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
          <button onClick={fetchSubdomainList}>🔍 Subdomain Scan</button>
          <button onClick={() => fetchData("http://127.0.0.1:5000/api/malware", setMalwareResults, "malware analysis")}>
            🛡 Malware Analysis
          </button>
          <button onClick={() => fetchData("http://127.0.0.1:5000/api/whois", setWhoisResults, "WHOIS data")}>
            🌐 WHOIS Data
          </button>
          <button onClick={() => fetchData("http://127.0.0.1:5000/api/ssl", setSslResults, "SSL/TLS details")}>
            🔑 SSL/TLS Check
          </button>
          <button onClick={fetchThreatMap}>🌍 Threat Map</button>
          <button onClick={fetchNmapResults}>Scan Subdomains (Nmap)</button>
        </div>
      </div>

      <div className="results-section">
        {/* Subdomain List */}
        <div className="result-block">
          <h3>Subdomain List:</h3>
          <div className="result-content">
            {subdomainResults.length > 0 ? (
              <ul>
                {subdomainResults.map((sub, idx) => (
                  <li key={idx}>{sub}</li>
                ))}
              </ul>
            ) : (
              "No subdomains found."
            )}
          </div>
        </div>

        {/* Nmap Scan Results */}
        <div className="result-block">
          <h3>Nmap Scan Results for {domain}:</h3>
          <div className="result-content">
            {nmapResults.length > 0 ? (
              nmapResults.map((result, idx) => (
                <div key={idx}>
                  <h4>{result.subdomain}</h4>
                  <p>
                    <strong>IP:</strong> {result.ip_address}
                  </p>
                  <p>
                    <strong>Hostname:</strong> {result.hostname}
                  </p>
                  <p>
                    <strong>Open Ports:</strong>
                    <pre>{result.open_ports}</pre>
                  </p>
                </div>
              ))
            ) : (
              "No Nmap scan results found."
            )}
          </div>
        </div>

        {/* Malware Analysis */}
        <div className="result-block">
          <h3>Malware Analysis Results:</h3>
          <div className="result-content">{malwareResults || "No results yet."}</div>
        </div>

        {/* WHOIS Data */}
        <div className="result-block">
          <h3>WHOIS Data:</h3>
          <div className="result-content">{whoisResults || "No results yet."}</div>
        </div>

        {/* SSL/TLS Check */}
        <div className="result-block">
          <h3>SSL/TLS Check:</h3>
          <div className="result-content">{sslResults || "No results yet."}</div>
        </div>

        {/* Threat Map */}
        {threatMapData.length > 0 && (
          <div className="result-block">
            <h3>Threat Map:</h3>
            <div className="map-container">
              <ComposableMap projection="geoMercator">
                <Geographies geography="/world-map.json">
                  {({ geographies }) =>
                    geographies.map((geo) => (
                      <Geography
                        key={`geo-${geo.rsmKey}`}
                        geography={geo}
                        fill="#2a364a"
                        stroke="#3a4a63"
                      />
                    ))
                  }
                </Geographies>
                {threatMapData.map((loc, idx) => (
                  <Marker
                    key={`marker-${idx}`}
                    coordinates={[loc.coords[1], loc.coords[0]]}
                    onClick={(e) => {
                      setSelectedIp(loc);
                      setTooltipPosition({ x: e.clientX, y: e.clientY });
                    }}
                  >
                    <circle
                      r={6}
                      fill="#f56565"
                      stroke="#fff"
                      strokeWidth={0.5}
                      className="map-marker"
                    />
                  </Marker>
                ))}
              </ComposableMap>
              {selectedIp && (
                <div
                  className="marker-tooltip"
                  style={{ left: tooltipPosition.x + 15, top: tooltipPosition.y - 50 }}
                >
                  <div className="tooltip-header">{selectedIp.city || "Unknown Location"}</div>
                  <div className="tooltip-row">
                    <span className="tooltip-label">IP:</span>
                    <span className="tooltip-value">{selectedIp.ip}</span>
                  </div>
                  <div className="tooltip-row">
                    <span className="tooltip-label">ISP:</span>
                    <span className="tooltip-value">{selectedIp.isp || "N/A"}</span>
                  </div>
                  <div className="tooltip-row">
                    <span className="tooltip-label">Threat Score:</span>
                    <span className="tooltip-value">{selectedIp.threat_score || 0}/100</span>
                  </div>
                  <div className="tooltip-row">
                    <span className="tooltip-label">Last Reported:</span>
                    <span className="tooltip-value">{selectedIp.last_reported || "Never"}</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default DomainScanner;