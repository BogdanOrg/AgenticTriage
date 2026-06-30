// CWE-319: Cleartext Transmission of Sensitive Information
//
// Opening a WebSocket over the unencrypted ws:// scheme and sending an auth
// token across it. The fix is to use wss:// (WebSocket over TLS).

const WebSocket = require("ws");

function connect(authToken) {
  // CWE-319: unencrypted ws:// connection
  const socket = new WebSocket("ws://realtime.example.com/stream");

  socket.on("open", () => {
    // CWE-319: auth token sent in cleartext over the WebSocket
    socket.send(JSON.stringify({ type: "auth", token: authToken }));
  });

  return socket;
}

module.exports = { connect };
