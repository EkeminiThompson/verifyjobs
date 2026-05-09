# Job Scam Detector — Setup Guide

## Why a proxy server?
Browsers block direct calls to `api.x.ai` due to CORS restrictions.
This proxy runs locally on your machine and forwards requests to Grok on your behalf.

## Requirements
- Node.js 18+ (https://nodejs.org)

## Setup (3 steps)

### 1. Install dependencies
```bash
cd proxy-server
npm install
```

### 2. Start the proxy
```bash
npm start
```
You should see:
```
Proxy running at http://localhost:3000
```

### 3. Open the app
Open `index.html` in your browser, or visit:
```
http://localhost:3000/index.html
```

## Files
- `server.js` — Express proxy that forwards requests to Grok API
- `index.html` — The full Job Scam Detector frontend
- `package.json` — Node.js dependencies

## Notes
- Keep the terminal running while using the app
- The Grok API key is already embedded in `server.js`
- To change the key, edit line 6 of `server.js`
