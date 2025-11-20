// server.js
// File path: ./server.js
// Purpose: OTP server with robust logging for debugging email send failures.

const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const axios = require("axios");
const dotenv = require("dotenv");
const cors = require("cors");

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(cors({
  origin: true,
  methods: ["GET","POST","OPTIONS"],
  allowedHeaders: ["Content-Type","x-api-key","Authorization"]
}));

const PORT = process.env.PORT || 10000;
const OTP_FILE = process.env.OTP_FILE || "otps.json";
const OTP_TTL = parseInt(process.env.OTP_TTL_MINUTES || "10", 10) * 60 * 1000;

console.log("🚀 Starting ProBrush OTP Server...");
console.log("➡ RESEND_API_KEY set:", !!process.env.RESEND_API_KEY);
console.log("➡ OTP_API_KEY set:", !!process.env.OTP_API_KEY);
console.log("➡ OTP_FILE:", OTP_FILE);
console.log("➡ OTP_TTL (ms):", OTP_TTL);

// API key middleware
function requireApiKey(req, res, next) {
  const received = req.get("x-api-key");
  const expected = process.env.OTP_API_KEY;

  console.log("🔑 Received key:", received ? "[REDACTED]" : "none");
  if (!expected) {
    console.error("⚠️ Server misconfigured: OTP_API_KEY is not set.");
    return res.status(500).json({ success: false, message: "Server misconfigured (OTP_API_KEY missing)" });
  }
  if (!received || received !== expected) {
    console.log("❌ API key mismatch → 401 Unauthorized");
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }
  next();
}

// helpers
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function readOTPs() {
  try {
    if (!fs.existsSync(OTP_FILE)) return {};
    return JSON.parse(fs.readFileSync(OTP_FILE, "utf-8") || "{}");
  } catch (err) {
    console.error("❌ readOTPs error:", err.message);
    return {};
  }
}

function saveOTP(uid, otp) {
  const otps = readOTPs();
  otps[uid] = { otp, expires: Date.now() + OTP_TTL };
  try {
    fs.writeFileSync(OTP_FILE, JSON.stringify(otps, null, 2));
  } catch (err) {
    console.error("❌ Failed to write OTP file:", err.message);
    throw new Error("Failed to persist OTP");
  }
}

function verifyOTP(uid, code) {
  const otps = readOTPs();
  const rec = otps[uid];
  if (!rec) return false;
  if (Date.now() > rec.expires) {
    delete otps[uid];
    try { fs.writeFileSync(OTP_FILE, JSON.stringify(otps, null, 2)); } catch {}
    return false;
  }
  return rec.otp === code;
}

// send email via Resend
async function sendMailViaResend(to, otp) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error("RESEND_API_KEY not set");

  // IMPORTANT: no invisible characters in 'from'
  const payload = {
    from: "ProBrush <noreply.proartstudio@gmail.com>",
    to: [to],
    subject: "Your ProBrush Verification Code",
    html: `
      <div style="font-family:Arial;padding:20px;text-align:center">
        <h2>Your verification code</h2>
        <h1 style="font-size:42px;letter-spacing:6px">${otp}</h1>
        <p>This code expires in ${process.env.OTP_TTL_MINUTES || 10} minutes.</p>
      </div>
    `
  };

  try {
    const response = await axios.post("https://api.resend.com/emails", payload, {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      timeout: 15000,
    });
    console.log("📧 Resend sent email status:", response.status);
    return response.data;
  } catch (err) {
    // Log rich axios info for debugging (do not leak to client)
    console.error("❌ Resend error: message=", err.message);
    if (err.response) {
      console.error("❌ Resend response status:", err.response.status);
      // Truncate large bodies in logs
      const bodyPreview = JSON.stringify(err.response.data).slice(0, 2000);
      console.error("❌ Resend response data (preview):", bodyPreview);
      console.error("❌ Resend response headers:", err.response.headers);
    } else {
      console.error("❌ Resend no response (network/timeout):", err.code || "unknown");
    }
    throw err;
  }
}

// routes
app.get("/", (req, res) => res.send("✅ ProBrush OTP API is running successfully!"));

app.post("/send-otp", requireApiKey, async (req, res) => {
  console.log("➡ /send-otp called");
  console.log("Headers (redacted):", { "x-api-key": req.get("x-api-key") ? "[REDACTED]" : "none" });
  console.log("Body:", req.body);

  try {
    const { uid, email } = req.body;
    if (!uid || !email) return res.status(400).json({ success: false, message: "Missing uid or email" });

    const otp = generateOTP();
    // persist before sending email — allows manual retry if send fails
    saveOTP(uid, otp);
    console.log(`💾 OTP saved for uid=${uid}`);

    // try send email — if it fails, logs above will show details
    await sendMailViaResend(email, otp);

    return res.json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
    console.error("❌ /send-otp handler error:", err.message);
    // Return safe error to client; logs contain axios details for debugging
    return res.status(500).json({
      success: false,
      message: "Failed to send OTP",
      error: err.response?.data || err.message,
    });
  }
});

app.post("/verify-otp", requireApiKey, (req, res) => {
  console.log("➡ /verify-otp called", req.body);
  const { uid, code } = req.body;
  if (!uid || !code) return res.status(400).json({ success: false, message: "Missing uid or code" });

  const valid = verifyOTP(uid, code);
  return res.json({ success: valid, message: valid ? "OTP verified" : "Invalid or expired OTP" });
});

app.listen(PORT, () => console.log(`🚀 OTP server listening on port ${PORT}`));
