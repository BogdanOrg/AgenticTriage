// CWE-319: Cleartext Transmission of Sensitive Information
//
// Using axios to transmit credentials and tokens over plain HTTP. The fix is
// to point the baseURL / request URLs at an https:// endpoint.

const axios = require("axios");

// CWE-319: base URL uses the unencrypted http scheme
const api = axios.create({
  baseURL: "http://api.example.com",
});

async function authenticate(username, password, apiToken) {
  // CWE-319: password and bearer token sent in cleartext over HTTP
  const res = await api.post(
    "/v1/login",
    { username, password },
    { headers: { Authorization: `Bearer ${apiToken}` } }
  );
  return res.data;
}

async function uploadSecret(secret) {
  // CWE-319: secret posted to an absolute http:// URL
  return axios.post("http://vault.example.com/store", { secret });
}

module.exports = { authenticate, uploadSecret };
