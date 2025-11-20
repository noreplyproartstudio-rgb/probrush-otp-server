// server.js – ProBrush OTP Server with Embedded Logo HTML Template
require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");

const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;
const OTP_TTL_MINUTES = Number(process.env.OTP_TTL_MINUTES || 10);
const API_KEY = process.env.OTP_API_KEY;

// ----- SMTP CONFIG -----
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ----- IN-MEMORY OTP STORE -----
const otpStore = new Map(); // uid -> { otp, expires }

// ----- API-KEY VALIDATION -----
app.use((req, res, next) => {
  const key = req.headers["x-api-key"];
  if (key !== API_KEY)
    return res.status(401).json({ success: false, message: "Unauthorized" });
  next();
});

// ----- HEALTH CHECK -----
app.get("/_health", (req, res) => res.json({ ok: true }));

// ----- SEND OTP -----
app.post("/send-otp", async (req, res) => {
  const { uid, email } = req.body;
  if (!uid || !email)
    return res.status(400).json({ error: "uid and email required" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + OTP_TTL_MINUTES * 60 * 1000;
  otpStore.set(uid, { otp, expires });

  // ----- HTML TEMPLATE WITH EMBEDDED LOGO -----
  const htmlBody = `
  <div style="font-family:Arial,sans-serif;background-color:#f7f9fc;padding:40px;">
    <div style="max-width:480px;margin:auto;background:#ffffff;border-radius:12px;padding:32px;box-shadow:0 2px 10px rgba(0,0,0,0.05);">
      <div style="text-align:center;margin-bottom:20px;">
        <img src="cid:probrush_logo_v2" alt="ProBrush Logo" width="72" height="72" style="margin-bottom:10px;border-radius:8px;">
        <h2 style="color:#333;margin-top:10px;">ProBrush verification code</h2>
      </div>
      <p style="color:#555;font-size:15px;text-align:center;">Your verification code is:</p>
      <div style="text-align:center;margin:20px 0;">
        <div style="display:inline-block;font-size:36px;font-weight:bold;letter-spacing:6px;color:#000;">
          ${otp}
        </div>
      </div>
      <p style="color:#777;font-size:14px;text-align:center;">
        This code expires in ${OTP_TTL_MINUTES} minutes.
      </p>
      <hr style="border:none;border-top:1px solid #eee;margin:25px 0;">
      <p style="color:#aaa;font-size:12px;text-align:center;">
        This is an automated message from ProBrush.<br>
        Please do not reply to this email.
      </p>
    </div>
  </div>`;

  try {
    await transporter.sendMail({
      from: `"ProBrush" <${process.env.SMTP_USER}>`,
      to: email,
      subject: "Your ProBrush verification code",
      html: htmlBody,
      attachments: [
        {
          filename: "logo_transparent.PNG", // exact case-sensitive name
          path: "./logo_transparent.PNG",   // same folder as server.js
          cid: "probrush_logo_v2",          // must match <img src="cid:...">
        },
      ],
    });

    res.json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
    console.error("sendMail error:", err);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});

// ----- VERIFY OTP -----
app.post("/verify-otp", (req, res) => {
  const { uid, code } = req.body;
  if (!uid || !code)
    return res.status(400).json({ error: "uid and code required" });

  const record = otpStore.get(uid);
  if (!record)
    return res
      .status(400)
      .json({ success: false, message: "No OTP found for this UID" });
  if (Date.now() > record.expires)
    return res
      .status(400)
      .json({ success: false, message: "OTP expired" });

  if (record.otp === code) {
    otpStore.delete(uid);
    return res.json({
      success: true,
      message: "OTP verified successfully",
    });
  }

  res.status(400).json({ success: false, message: "Invalid OTP" });
});

// ----- START SERVER -----
app.listen(PORT, () => console.log(`OTP server listening on ${PORT}`));
