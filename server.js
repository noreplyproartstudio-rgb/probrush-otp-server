// server.js — Gmail SMTP ONLY OTP server
// Requirements (Render Environment Variables):
// SMTP_USER          = noreply.proartstudio@gmail.com
// SMTP_PASS          = <your 16-digit Gmail App Password>
// SMTP_HOST          = smtp.gmail.com
// SMTP_PORT          = 587
// OTP_API_KEY        = (same key used by your mobile app)
// OTP_TTL_MINUTES    = 10 (optional)

const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const cors = require("cors");
const nodemailer = require("nodemailer");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(
  cors({
    origin: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "x-api-key", "Authorization"],
  })
);

const PORT = process.env.PORT || 10000;
const OTP_FILE = "otps.json";
const OTP_TTL =
  parseInt(process.env.OTP_TTL_MINUTES || "10", 10) * 60 * 1000;

console.log("🚀 ProBrush Gmail OTP Server started");

// --- API key middleware -----------------------------------------
function requireApiKey(req, res, next) {
  const received = req.get("x-api-key");
  if (!process.env.OTP_API_KEY) {
    return res
      .status(500)
      .json({ success: false, message: "Server missing OTP_API_KEY" });
  }
  if (!received || received !== process.env.OTP_API_KEY) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }
  next();
}

// --- OTP helpers --------------------------------------------------
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function readOTPs() {
  try {
    if (!fs.existsSync(OTP_FILE)) return {};
    return JSON.parse(fs.readFileSync(OTP_FILE, "utf-8") || "{}");
  } catch (err) {
    console.error("readOTPs error:", err.message);
    return {};
  }
}

function saveOTP(uid, otp) {
  const otps = readOTPs();
  otps[uid] = { otp, expires: Date.now() + OTP_TTL };
  fs.writeFileSync(OTP_FILE, JSON.stringify(otps, null, 2));
}

function verifyOTP(uid, code) {
  const otps = readOTPs();
  const rec = otps[uid];
  if (!rec) return false;
  if (Date.now() > rec.expires) return false;
  return rec.otp === code;
}

// --- Gmail SMTP Transporter --------------------------------------
if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
  console.error("❌ Missing SMTP_USER or SMTP_PASS");
  process.exit(1);
}

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: parseInt(process.env.SMTP_PORT || "587", 10),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Test SMTP
transporter
  .verify()
  .then(() => console.log("📧 Gmail SMTP verified"))
  .catch((err) => {
    console.error("❌ Gmail SMTP failed:", err.message);
  });

// --- Routes -------------------------------------------------------

app.get("/", (req, res) =>
  res.send("✅ ProBrush Gmail OTP Server is running")
);

app.post("/send-otp", requireApiKey, async (req, res) => {
  const { uid, email } = req.body;
  if (!uid || !email)
    return res
      .status(400)
      .json({ success: false, message: "uid and email required" });

  const otp = generateOTP();
  saveOTP(uid, otp);

  try {
    await transporter.sendMail({
      from: `"ProBrush" <${process.env.SMTP_USER}>`,
      to: email,
      subject: "Your ProBrush Verification Code",
      html: `
        <div style="font-family:Arial;padding:20px;text-align:center">
          <h2>Your verification code</h2>
          <h1 style="font-size:40px;letter-spacing:6px">${otp}</h1>
          <p>Expires in ${process.env.OTP_TTL_MINUTES || 10} minutes.</p>
        </div>
      `,
    });

    return res.json({
      success: true,
      message: "OTP sent successfully (Gmail)",
    });
  } catch (err) {
    console.error("SMTP send error:", err.message);
    return res.status(500).json({
      success: false,
      message: "Failed to send OTP",
    });
  }
});

app.post("/verify-otp", requireApiKey, (req, res) => {
  const { uid, code } = req.body;

  if (!uid || !code)
    return res
      .status(400)
      .json({ success: false, message: "uid and code required" });

  const valid = verifyOTP(uid, code);
  return res.json({
    success: valid,
    message: valid ? "OTP verified" : "Invalid or expired OTP",
  });
});

// --- Start server -------------------------------------------------
app.listen(PORT, () =>
  console.log(`🚀 Gmail OTP Server running on port ${PORT}`)
);
