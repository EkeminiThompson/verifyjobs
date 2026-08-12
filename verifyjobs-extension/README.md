# VerifyJobs Chrome Extension v1.3.5

Same hybrid engine as [verifyjobs.org](https://verifyjobs.org).

## Analyse
- **Paste text** — job ads, WhatsApp / Telegram messages
- **URL** — server fetches the page
- **File / Image** — PDF, Word, or photo (OCR on server). Upload runs **in the popup** so the file is sent correctly.
- **This Page** — analyses the active tab URL

## Install (developer)
1. Unzip
2. Chrome → Extensions → Developer mode → Load unpacked → select this folder

## Settings
Optional API base URL (default `https://verifyjobs.org`). Use `http://localhost:3000` for local server.

## Privacy
Content is sent only when you click Analyse. No account, no ads, no browsing history collection.
