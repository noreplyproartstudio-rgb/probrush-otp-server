ProBrush OTP Server - Quick Start

1) Put these two files in D:\ProBrush-OTP-Server:
   - server.js
   - package.json

2) Install Node.js (v18 recommended) and npm.

3) Open PowerShell / CMD:
   cd D:\ProBrush-OTP-Server
   npm install

4) Set environment variables (locally you can use a .env tool or set them in shell)
   Required:
     SERVICE_ACCOUNT_JSON  -> (paste full service account JSON string)
     FIREBASE_PROJECT_ID   -> your firebase project id
     SMTP_HOST             -> smtp.gmail.com
     SMTP_PORT             -> 587
     SMTP_USER             -> your-smtp-user (email)
     SMTP_PASS             -> your-smtp-password (app password for Gmail)
     OTP_API_KEY           -> a long random secret your app will include in header x-api-key
     OTP_TTL_MINUTES       -> (optional) default 10

   Example (PowerShell):
     $env:SERVICE_ACCOUNT_JSON = Get-Content "C:\path\to\serviceAccount.json" -Raw
     $env:FIREBASE_PROJECT_ID = "your-project-id"
     $env:SMTP_USER = "you@gmail.com"
     $env:SMTP_PASS = "your_app_password"
     $env:OTP_API_KEY = "YOUR_SECRET_KEY"

5) Run:
   npm start

6) Endpoints:
   GET  /_health
   POST /send-otp    { uid, email }    header: x-api-key: YOUR_SECRET_KEY
   POST /verify-otp  { uid, code }     header: x-api-key: YOUR_SECRET_KEY
