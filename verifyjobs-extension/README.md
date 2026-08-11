# VerifyJobs Chrome Extension

Instantly check job postings for scams using your VerifyJobs backend (`server.js`).

Results appear **inside the extension popup / side panel** — no need to leave the page.

## Features

- **Context menu**: Right-click selected text or any page → “Check with VerifyJobs”
- **Floating button** on LinkedIn, Indeed, Glassdoor, Monster, ZipRecruiter, WhatsApp Web
- **Popup UI** with three modes: Paste Text · URL · This Page
- **Side panel** support (Chrome 114+)
- Calls your own API:
  - `POST /analyze` (text)
  - `POST /analyze-url` (URL)
- Configurable API base URL in Options (default: `http://localhost:3000`)

## Load the extension (unpacked)

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select this folder (`verifyjobs-extension`)

## Point it at your server

1. Click the extension icon → ⚙ (settings)  
   **or** right-click the icon → Options
2. Set **API Base URL** to wherever your `server.js` is running  
   (e.g. `http://localhost:3000` or your production URL)
3. Save

Make sure CORS on the server allows the extension origin (your `server.js` already has `corsOrigin: '*'` by default, which works).

## Usage

- Select any job text → right-click → **Check selection with VerifyJobs**
- On a job page → click the floating **VerifyJobs** button (bottom-right)
- Or open the extension popup and paste text / enter a URL / analyze the current page

## File structure

```
verifyjobs-extension/
├── manifest.json
├── background.js          # context menus + API proxy
├── content.js + content.css  # floating button on job sites
├── popup.html / popup.js / popup.css
├── sidepanel.html
├── options.html / options.js
├── icons/
└── README.md
```

## Notes

- The extension does **not** talk to the public verifyjobs.org site by default. It talks to **your** instance of the server you provided.
- Replace the placeholder icons in `/icons` with proper branded ones if desired.
- For production, set a proper `CORS_ORIGIN` on the server and lock down rate limits.

## License

Use freely with your VerifyJobs project.

## v1.3.2
- Aligned with site: `not_a_job` / `not_applicable` decision when input is not a job posting
- Neutral verdict tone styles
- Risk/legitimacy show N/A for non-job results

## v1.3.3
- Side panel aligned with popup (verdict card, reasons, next steps)
- Side panel loads decision.js
- Null-safe renderResult; explicit not_a_job handling when decision missing

## v1.3.4
- Synced decision.js with site (not_a_job, verdict, next steps)
- ML blend chips when API returns hybrid `ml` block
- Side panel + popup both load decision.js
- Advisory disclaimer under results
- Meta shows Hybrid ML + rules / Rules only / Not a job
