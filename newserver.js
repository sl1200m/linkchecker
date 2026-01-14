const express = require("express");
const axios = require("axios");
const dns = require("dns").promises;
const app = express();
const port = 8000;

app.use(express.json());

// Known IP addresses used by Indonesian ISPs for DNS redirection/blocking
const BLOCK_IPS = [
  "125.160.17.84",
  "36.86.63.185",
  "118.97.115.30",
  "103.111.1.1",
];

/**
 * Extracts the root domain from a string (removes https://, paths, and ports)
 */
function getCleanDomain(input) {
  try {
    let domain = input.trim().toLowerCase();
    if (domain.includes("://")) {
      domain = new URL(domain).hostname;
    } else {
      domain = domain.split("/")[0];
    }
    return domain;
  } catch (e) {
    return input.trim().toLowerCase();
  }
}

/**
 * Fetches official blocklist status from TrustPositif (Komdigi)
 */
async function getTrustPositifStatus(domains) {
  try {
    const cleaned = domains.map((d) => getCleanDomain(d));
    const params = new URLSearchParams();
    params.append("name", cleaned.join(" "));

    const response = await axios.post(
      "https://trustpositif.komdigi.go.id/Rest_server/getrecordsname_home",
      params,
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 10000,
      }
    );

    let data = response.data;
    // Normalize response: Always return an array
    if (Array.isArray(data)) return data;
    if (data && typeof data === "object") return [data];
    return [];
  } catch (e) {
    console.error("TrustPositif API Error:", e.message);
    return [];
  }
}

/**
 * Performs local DNS and SNI checks
 */
async function checkSingleDomain(originalInput, officialStatus) {
  const domain = getCleanDomain(originalInput);
  if (!domain) return null;

  let res = {
    input: originalInput,
    domain: domain,
    dns_blocked: false,
    sni_blocked: false,
    official_blocked: officialStatus === "ADA",
    status: "Clean",
  };

  // 1. DNS Check
  try {
    const addresses = await dns.resolve4(domain);
    if (addresses.some((ip) => BLOCK_IPS.includes(ip))) {
      res.dns_blocked = true;
    }
  } catch (e) {}

  // 2. SNI/Connection Check
  try {
    const response = await axios.get(`https://${domain}`, {
      timeout: 3500,
      maxRedirects: 5,
      validateStatus: false,
    });
    const finalUrl = response.request.res.responseUrl || "";
    if (finalUrl.includes("internetpositif") || finalUrl.includes("uzone.id")) {
      res.sni_blocked = true;
    }
  } catch (e) {
    // Connection Reset usually indicates SNI block
    res.sni_blocked = true;
  }

  if (res.dns_blocked || res.sni_blocked || res.official_blocked) {
    res.status = "Blocked";
  }

  return res;
}

// API Endpoint
app.post("/api/check", async (req, res) => {
  const { domains } = req.body;
  if (!Array.isArray(domains))
    return res.status(400).send({ error: "Invalid input" });

  const officialResults = await getTrustPositifStatus(domains);
  const officialMap = {};

  if (Array.isArray(officialResults)) {
    officialResults.forEach((item) => {
      if (item && item.name) officialMap[item.name.toLowerCase()] = item.status;
    });
  }

  const results = await Promise.all(
    domains.map((d) => checkSingleDomain(d, officialMap[getCleanDomain(d)]))
  );

  res.json({ results: results.filter((r) => r !== null) });
});

// Dashboard UI
app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>ID Domain Checker Pro</title>
        <style>
            body { background:#0f172a; color:#e2e8f0; font-family:'Segoe UI', sans-serif; padding:40px; }
            .container { max-width: 1000px; margin: auto; }
            textarea { 
                width:100%; height:120px; background:#1e293b; color:white; 
                border:1px solid #334155; border-radius:12px; padding:15px; font-size:14px; outline:none;
            }
            button { 
                width:100%; padding:15px; margin-top:15px; background:#3b82f6; 
                border:none; border-radius:12px; color:white; font-weight:bold; 
                cursor:pointer; font-size:16px; transition: 0.3s;
            }
            button:hover { background:#2563eb; }
            button:disabled { background:#475569; }
            table { width:100%; border-collapse: collapse; margin-top:30px; background:#1e293b; border-radius:12px; overflow:hidden; }
            th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #334155; }
            th { background: #334155; font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; }
            .status-blocked { color: #f87171; font-weight: bold; }
            .status-clean { color: #4ade80; font-weight: bold; }
            .badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-right: 5px; }
            .badge-on { background: #ef4444; color: white; }
            .badge-off { background: #475569; color: #94a3b8; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ ID Domain Checker</h1>
            <p style="color:#94a3b8">Checking against Komdigi Database, DNS Poisoning, and ISP SNI Filtering.</p>
            
            <textarea id="input" placeholder="Enter URLs or Domains (one per line)...&#10;https://idvip.co/jAmfAJ9&#10;reddit.com"></textarea>
            <button id="checkBtn" onclick="run()">Analyze Domains</button>
            
            <div id="resultsContainer"></div>
        </div>

        <script>
            async function run() {
                const btn = document.getElementById('checkBtn');
                const container = document.getElementById('resultsContainer');
                const domains = document.getElementById('input').value.split('\\n').filter(d => d.trim());

                if (domains.length === 0) return;

                btn.disabled = true;
                btn.innerText = 'Analyzing...';
                container.innerHTML = '<p>Running multi-layer checks...</p>';

                try {
                    const res = await fetch('/api/check', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ domains })
                    });
                    const data = await res.json();
                    
                    let html = '<table><thead><tr><th>Domain</th><th>Status</th><th>Detection Triggers</th></tr></thead><tbody>';
                    
                    data.results.forEach(r => {
                        const statusClass = r.status === 'Blocked' ? 'status-blocked' : 'status-clean';
                        html += \`<tr>
                            <td><strong>\${r.domain}</strong><br><small style="color:#64748b">\${r.input}</small></td>
                            <td class="\${statusClass}">\${r.status}</td>
                            <td>
                                <span class="badge \${r.official_blocked ? 'badge-on' : 'badge-off'}">Official API</span>
                                <span class="badge \${r.dns_blocked ? 'badge-on' : 'badge-off'}">DNS</span>
                                <span class="badge \${r.sni_blocked ? 'badge-on' : 'badge-off'}">SNI/DPI</span>
                            </td>
                        </tr>\`;
                    });
                    
                    html += '</tbody></table>';
                    container.innerHTML = html;
                } catch (e) {
                    container.innerHTML = '<p style="color:red">Error communicating with the backend.</p>';
                } finally {
                    btn.disabled = false;
                    btn.innerText = 'Analyze Domains';
                }
            }
        </script>
    </body>
    </html>
  `);
});

app.listen(port, "0.0.0.0", () => {
  console.log(`🚀 Advanced Checker running at http://localhost:${port}`);
});
