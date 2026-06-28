// ⚠️ DEMO FIXTURE — intentionally vulnerable, used to verify vibecheck rules fire.
// All "secrets" here are obviously fake placeholders, NOT real credentials.
const express = require("express");
const app = express();

// BLOCKER: hardcoded secret (fake placeholder)
const apiKey = "sk_live_EXAMPLE";
const password = "supersecret_fake_value_123";

// BLOCKER: server secret name shipped to client (fake)
const SUPABASE_SERVICE_ROLE = "service_role_fake_token_xxx";

// HIGH: CORS wildcard
app.use((req, res, next) => { res.header("Access-Control-Allow-Origin", "*"); next(); });

// HIGH: SQL string concatenation
function getUser(id) {
  const q = "SELECT * FROM users WHERE id = " + id;
  return db.query(q);
}

// HIGH: dynamic eval
function run(expr) { return eval(expr); }

// HIGH: command injection
const { exec } = require("child_process");
function ping(host) { exec("ping " + host); }

// HIGH: XSS sink
function render(el, data) { el.innerHTML = data; }

// MEDIUM: debug + non-TLS endpoint
const DEBUG = true;
const API = "http://api.example.com/v1";

// MEDIUM: security TODO
// TODO: add auth check before this is exposed
app.get("/admin", (req, res) => res.send("admin"));

module.exports = app;
