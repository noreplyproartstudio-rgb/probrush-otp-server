// server.js  ✅ CommonJS, route-level API key, Resend HTTP API

const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const axios = require("axios");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
app.use(bodyParser.json());

// ====== CONFIG ======
const PORT = process.env.PORT || 10000;
const OTP_FILE = "otps.json";
const OTP_TTL = parseInt(process.env.OTP_TTL_MINUTES || "10", 10) * 60 * 1000;

console.log("🚀 Starting ProBrush OTP Server...");
console.log("➡ RESEND_API_KEY set:", !!process.env.RESEND_API_KEY);
console.log("➡ OTP_API_KEY set:", !!process.env.OTP_API_KEY);

// ====== API KEY PROTECTION ======
function requireApiKey(req, res, next) {
  const received = req.headers["x-api-key"];
  const expected = process.env.OTP_API_KEY;

  console.log("🔑 Received key:", received);
  console.log("🔑 Expected key:", expected);

  if (!received || received !== expected) {
    console.log("❌ API key mismatch → 401 Unauthorized");
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }

  console.log("✅ API key authorized");
  next();
}

// ====== HEALTH CHECK ======
app.get("/", (req, res) => {
  res.send("✅ ProBrush OTP API is running successfully!");
});

// ====== OTP HELPERS ======
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function saveOTP(uid, otp) {
  let otps = {};
  if (fs.existsSync(OTP_FILE)) {
    try {
      otps = JSON.parse(fs.readFileSync(OTP_FILE, "utf-8"));
    } catch {
      otps = {};
    }
  }
  otps[uid] = { otp, expires: Date.now() + OTP_TTL };
  fs.writeFileSync(OTP_FILE, JSON.stringify(otps, null, 2));
}

function verifyOTP(uid, code) {
  if (!fs.existsSync(OTP_FILE)) return false;
  const otps = JSON.parse(fs.readFileSync(OTP_FILE, "utf-8"));
  const record = otps[uid];
  if (!record) return false;
  if (Date.now() > record.expires) return false;
  return record.otp === code;
}

// ====== SEND EMAIL WITH RESEND ======
async function sendMailViaResend(to, otp) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error("RESEND_API_KEY not set");

  const payload = {
    from: "ProBrush <onboarding@resend.dev>",     // ✅ safe sender for testing
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

    console.log("📧 Resend sent email:", response.status);
    return response.data;
  } catch (err) {
    console.error("❌ Resend error:", err.response?.data || err.message);
    throw err;
  }
}

// ====== SEND OTP ENDPOINT ======
app.post("/send-otp", requireApiKey, async (req, res) => {
  try {
    const { uid, email } = req.body;

    if (!uid || !email) {
      return res.status(400).json({ success: false, message: "Missing uid or email" });
    }

    const otp = generateOTP();
    saveOTP(uid, otp);

    await sendMailViaResend(email, otp);

    return res.json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Failed to send OTP",
      error: err.response?.data || err.message,
    });
  }
});

// ====== VERIFY OTP ENDPOINT ======
app.post("/verify-otp", requireApiKey, (req, res) => {
  const { uid, code } = req.body;

  if (!uid || !code) {
    return res.status(400).json({ success: false, message: "Missing uid or code" });
  }

  const valid = verifyOTP(uid, code);

  return res.json({
    success: valid,
    message: valid ? "OTP verified" : "Invalid or expired OTP",
  });
});

// ====== START SERVER ======
app.listen(PORT, () => console.log(`🚀 OTP server listening on port ${PORT}`));

