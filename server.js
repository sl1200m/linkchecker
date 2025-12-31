const express = require('express');
const axios = require('axios');
const dns = require('dns').promises;
const app = express();
const port = 8000;

app.use(express.json());

const BLOCK_IPS = ["125.160.17.84", "36.86.63.185", "118.97.115.30", "103.111.1.1"];

async function checkSingleDomain(domain) {
    const cleanDomain = domain.trim().toLowerCase();
    if (!cleanDomain) return null;

    let res = { domain: cleanDomain, dns_blocked: false, sni_blocked: false, status: "Clean" };

    // 1. DNS Check
    try {
        const addresses = await dns.resolve4(cleanDomain);
        if (addresses.some(ip => BLOCK_IPS.includes(ip))) {
            res.dns_blocked = true;
        }
    } catch (e) {
        // DNS failure might mean it's blocked or doesn't exist
    }

    // 2. SNI/Connection Check
    try {
        const response = await axios.get(`https://${cleanDomain}`, { 
            timeout: 4000,
            maxRedirects: 5,
            validateStatus: false // Follow even if it's a 404 or 403
        });
        const finalUrl = response.request.res.responseUrl || "";
        if (finalUrl.includes("internetpositif") || finalUrl.includes("uzone.id")) {
            res.sni_blocked = true;
        }
    } catch (e) {
        // Most Indonesian ISPs drop the connection for SNI blocks
        res.sni_blocked = true;
    }

    if (res.dns_blocked || res.sni_blocked) {
        res.status = "Blocked";
    }

    return res;
}

// API Endpoint
app.post('/api/check', async (req, res) => {
    const { domains } = req.body;
    if (!Array.isArray(domains)) return res.status(400).send({ error: "Invalid input" });

    const results = await Promise.all(domains.map(d => checkSingleDomain(d)));
    res.json({ results: results.filter(r => r !== null) });
});

// Simple Dashboard (Same as your Python one)
app.get('/', (req, res) => {
    res.send(`
        <html>
            <body style="background:#1a202c; color:white; font-family:sans-serif; padding:20px;">
                <h1>Node.js ID Domain Checker</h1>
                <textarea id="input" style="width:100%; height:100px; background:#2d3748; color:white; border:none; border-radius:8px; padding:10px;"></textarea>
                <button onclick="run()" style="width:100%; padding:15px; margin-top:10px; background:#4299e1; border:none; border-radius:8px; color:white; font-weight:bold; cursor:pointer;">Check</button>
                <pre id="output" style="margin-top:20px; background:#2d3748; padding:10px; border-radius:8px;"></pre>
                <script>
                    async function run() {
                        const domains = document.getElementById('input').value.split('\\n').filter(d => d.trim());
                        const res = await fetch('/api/check', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({ domains })
                        });
                        const data = await res.json();
                        document.getElementById('output').innerText = JSON.stringify(data, null, 2);
                    }
                </script>
            </body>
        </html>
    `);
});

app.listen(port, '0.0.0.0', () => {
    console.log(`Server running at http://localhost:${port}`);
});
