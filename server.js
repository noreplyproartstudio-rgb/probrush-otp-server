// server.js (CommonJS)
const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const axios = require("axios");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 10000;
const OTP_FILE = "otps.json";
const OTP_TTL = parseInt(process.env.OTP_TTL_MINUTES || "10", 10) * 60 * 1000;

console.log("RESEND_API_KEY set?", !!process.env.RESEND_API_KEY);
console.log("OTP_API_KEY set?", !!process.env.OTP_API_KEY);

function requireApiKey(req, res, next) {
  const apiKey = req.headers["x-api-key"];
  if (apiKey !== process.env.OTP_API_KEY) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }
  next();
}

app.get("/", (req, res) => {
  res.send("✅ ProBrush OTP API is running successfully!");
});

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function saveOTP(uid, otp) {
  let otps = {};
  if (fs.existsSync(OTP_FILE)) {
    try { otps = JSON.parse(fs.readFileSync(OTP_FILE, "utf-8")); } catch { otps = {}; }
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

async function sendMailViaResend(to, otp) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error("RESEND_API_KEY not set");

  const payload = {
    from: "ProBrush <noreply.proartstudio@gmail.com>",
    to: [to],
    subject: "Your ProBrush verification code",
    html: `<div style="font-family:Arial,sans-serif;padding:20px;text-align:center">
            <h2>ProBrush verification code</h2>
            <h1 style="letter-spacing:4px">${otp}</h1>
            <p>This code expires in ${parseInt(process.env.OTP_TTL_MINUTES||'10',10)} minutes.</p>
           </div>`
  };

  try {
    const resp = await axios.post("https://api.resend.com/emails", payload, {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      timeout: 15000,
    });
    console.log("Resend status:", resp.status);
    return resp.data;
  } catch (err) {
    console.error("Resend error:", err.response?.data || err.message);
    throw err;
  }
}

app.post("/send-otp", requireApiKey, async (req, res) => {
  try {
    const { uid, email } = req.body;
    if (!uid || !email) return res.status(400).json({ success:false, message:"Missing uid or email" });

    const otp = generateOTP();
    saveOTP(uid, otp);

    await sendMailViaResend(email, otp);

    return res.json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
    console.error("send-otp failed:", err.response?.data || err.message || err);
    return res.status(500).json({ success:false, message:"Failed to send OTP", error: err.response?.data || err.message });
  }
});

app.post("/verify-otp", requireApiKey, (req, res) => {
  const { uid, code } = req.body;
  if (!uid || !code) return res.status(400).json({ success:false, message:"Missing uid or code" });

  const valid = verifyOTP(uid, code);
  res.json({ success: valid, message: valid ? "OTP verified" : "Invalid or expired OTP" });
});

app.listen(PORT, () => console.log(`OTP server listening on ${PORT}`));
