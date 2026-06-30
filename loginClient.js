// CWE-319: Cleartext Transmission of Sensitive Information
//
// Credentials and a session token are sent over plain HTTP, exposing them to
// anyone able to observe network traffic. The fix is to use https.

const http = require("http");

function authenticate(username, password, apiToken) {
  const payload = JSON.stringify({ username, password });

  const options = {
    hostname: "api.example.com",
    port: 80,
    path: "/v1/login",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      // CWE-319: API token sent in cleartext over HTTP
      Authorization: `Bearer ${apiToken}`,
      "Content-Length": Buffer.byteLength(payload),
    },
  };

  // CWE-319: using the unencrypted http module instead of https
  const req = http.request(options, (res) => {
    console.log(`HTTP ${res.statusCode}`);
  });

  req.write(payload);
  req.end();
}

authenticate("alice", "S3cr3tP@ss", "tok_live_abc123");

module.exports = { authenticate };
