import React, { useState, useEffect } from "react";
import "./DomainScanner.jsx";
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";

const DomainScanner = () => {
  const [threatMapData, setThreatMapData] = useState([]);
  const [domain, setDomain] = useState("");
  const [results, setResults] = useState("");
  const [malwareResults, setMalwareResults] = useState("");
  const [malwareButtonColor, setMalwareButtonColor] = useState("#3173f3");
  const [whoisResults, setWhoisResults] = useState("");
  const [sslResults, setSslResults] = useState("");
  const [selectedIp, setSelectedIp] = useState(null);
  const [tooltipPosition, setTooltipPosition] = useState({ x: 0, y: 0 });
  
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

  const handleInputChange = (event) => {
    setDomain(event.target.value);
  };

  const validateDomain = () => {
    return domain.trim() ? null : "Please enter a valid domain.";
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
      } else if (resultType === "malware analysis") {
        const isMalicious = data.status === "red";
        setMalwareButtonColor(isMalicious ? "#d43a3a" : "#38a169");
        setResultState(data.malwareAnalysis || "No results found.");
      } else {
        const resultData = {
          subdomains: data.subdomains,
          "malware analysis": data.malwareAnalysis,
          "WHOIS data": data.whois,
          "SSL/TLS details": data.sslDetails,
        }[resultType];

        setResultState(formatResults(resultData) || "No results found.");
      }
    } catch (error) {
      setResultState(`Error fetching ${resultType}. Please try again.`);
    }
  };

  const fetchThreatMap = async () => {
    if (!domain) return;

    try {
      const response = await fetch(`http://localhost:5000/api/threat-map/${domain}`);
      const data = await response.json();
      setThreatMapData(data.filter((item) => item?.coords?.length === 2));
    } catch (error) {
      console.error("Threat map error:", error);
      setThreatMapData([]);
    }
  };

  const formatResults = (results) => {
    if (Array.isArray(results)) {
      return (
        <ul className="bullet-list">
          {results.map((result, index) => (
            <li key={`result-${index}`}>{result}</li>
          ))}
        </ul>
      );
    }

    if (typeof results === "object" && results !== null) {
      return results.hasOwnProperty("Domain Name") ? (
        <div className="details-grid">
          {Object.entries(results).map(([key, value]) => (
            <div className="detail-item" key={`whois-${key}`}>
              <div className="detail-key">{key}:</div>
              <div className="detail-value">{value}</div>
            </div>
          ))}
        </div>
      ) : (
        <div className="details">
          {Object.entries(results).map(([key, value]) => (
            <p key={`detail-${key}`}>
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
        <p>Subdomain Enumeration, Malware Analysis, WHOIS Data, SSL/TLS Check, Threat Map</p>
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
          <button
            className="scan-button"
            onClick={() => fetchData("http://127.0.0.1:5000/api/subdomains", setResults, "subdomains")}
          >
            🔍 Subdomain Scan
          </button>
          <button
            className="scan-button malware-button"
            style={{ backgroundColor: malwareButtonColor }}
            onClick={() => fetchData("http://127.0.0.1:5000/api/malware", setMalwareResults, "malware analysis")}
          >
            🛡 Malware Analysis
          </button>
          <button
            className="scan-button whois-button"
            onClick={() => fetchData("http://127.0.0.1:5000/api/whois", setWhoisResults, "WHOIS data")}
          >
            🌐 WHOIS Data
          </button>
          <button
            className="scan-button ssl-button"
            onClick={() => fetchData("http://127.0.0.1:5000/api/ssl", setSslResults, "SSL/TLS details")}
          >
            🔑 SSL/TLS Check
          </button>
          <button
            className="scan-button map-button"
            onClick={async () => {
              await fetchData("http://127.0.0.1:5000/api/subdomains", setResults, "subdomains");
              fetchThreatMap();
            }}
          >
            🌍 Threat Map
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

        <div className="result-block">
          <h3>SSL/TLS Check:</h3>
          <div className="result-content">{sslResults || "No results yet."}</div>
        </div>

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
                {threatMapData.map((loc, i) => (
                  <Marker
                    key={`marker-${i}`}
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
                  style={{
                    left: tooltipPosition.x + 15,
                    top: tooltipPosition.y - 50,
                  }}
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
