// CWE-319: Cleartext Transmission of Sensitive Information
//
// Several common JS patterns that send sensitive data over an unencrypted
// channel. The fix in every case is to use an https:// (or wss://) endpoint.

// --- Pattern 1: fetch() over http:// ---
async function loginWithFetch(username, password) {
  // CWE-319: credentials posted to a plaintext HTTP endpoint
  const res = await fetch("http://api.example.com/v1/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  return res.status;
}


// --- Pattern 2: token in URL query string over http:// ---
async function fetchProfile(apiToken) {
  // CWE-319: API token leaked in a cleartext URL query parameter
  const url = "http://api.example.com/v1/profile?access_token=" + apiToken;
  const res = await fetch(url);
  return res.json();
}

// --- Pattern 3: XMLHttpRequest over http:// ---
function sendCreditCard(cardNumber, cvv) {
  const xhr = new XMLHttpRequest();
  // CWE-319: payment data sent over unencrypted HTTP
  xhr.open("POST", "http://payments.example.com/charge", true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.send(JSON.stringify({ cardNumber, cvv }));
}

module.exports = { loginWithFetch, fetchProfile, sendCreditCard };
