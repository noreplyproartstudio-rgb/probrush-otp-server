import express from "express";
import bodyParser from "body-parser";
import fs from "fs";
import axios from "axios";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 10000;
const OTP_FILE = "otps.json";
const OTP_TTL = parseInt(process.env.OTP_TTL_MINUTES || "10", 10) * 60 * 1000;

// Debug logs so we know env is loaded
console.log("RESEND_API_KEY set?", !!process.env.RESEND_API_KEY);
console.log("OTP_API_KEY set?", !!process.env.OTP_API_KEY);

// ROUTE-LEVEL API KEY CHECKER
function requireApiKey(req, res, next) {
  const apiKey = req.headers["x-api-key"];
  if (apiKey !== process.env.OTP_API_KEY) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }
  next();
}

// Public route (MUST NOT require API key)
app.get("/", (req, res) => {
  res.send("✅ ProBrush OTP API is running successfully!");
});

// Generate OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Save OTP
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

// Verify OTP
function verifyOTP(uid, code) {
  if (!fs.existsSync(OTP_FILE)) return false;
  const otps = JSON.parse(fs.readFileSync(OTP_FILE, "utf-8"));
  const record = otps[uid];
  if (!record) return false;
  if (Date.now() > record.expires) return false;
  return record.otp === code;
}

// Send Email via Resend
async function sendMail(to, otp) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error("Missing RESEND_API_KEY");

  const payload = {
    from: "ProBrush <noreply.proartstudio@gmail.com>",
    to: [to],
    subject: "Your ProBrush verification code",
    html: `<h1>Your OTP is ${otp}</h1>`
  };

  try {
    const resp = await axios.post("https://api.resend.com/emails", payload, {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
    });
    console.log("Email sent:", resp.data);
  } catch (error) {
    console.error("Resend error:", error.response?.data || error.message);
    throw error;
  }
}

// Protected: send otp
app.post("/send-otp", requireApiKey, async (req, res) => {
  const { uid, email } = req.body;

  if (!uid || !email)
    return res.status(400).json({ success: false, message: "Missing uid or email" });

  const otp = generateOTP();
  saveOTP(uid, otp);

  try {
    await sendMail(email, otp);
    res.json({ success: true, message: "OTP sent" });
  } catch (e) {
    res.status(500).json({ success: false, message: "Email failed", error: e.message });
  }
});

// Protected: verify otp
app.post("/verify-otp", requireApiKey, (req, res) => {
  const { uid, code } = req.body;

  if (!uid || !code)
    return res.status(400).json({ success: false, message: "Missing uid or code" });

  const valid = verifyOTP(uid, code);

  res.json({
    success: valid,
    message: valid ? "OTP verified" : "Invalid or expired OTP",
  });
});

app.listen(PORT, () =>
  console.log(`🚀 OTP server running on ${PORT}`)
);
