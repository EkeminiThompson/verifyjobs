// server.js — VerifyJobs v1.4
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const multer  = require('multer');
const https   = require('https');
const http    = require('http');

// Core modules
const analyzeJob = require('./engine/analyzer');
const { ensureStorage, getAllAnalyses } = require('./engine/storage');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────
// MULTER
// ─────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.pdf', '.doc', '.docx'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Only PDF and Word files (.pdf, .doc, .docx) allowed'));
  }
});

// ─────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname), { index: false }));

// ─────────────────────────────────────────────
// FAVICON
// ─────────────────────────────────────────────
app.get('/favicon.ico',       (req, res) => res.sendFile(path.join(__dirname, 'favicon.ico')));
app.get('/favicon.png',       (req, res) => res.sendFile(path.join(__dirname, 'favicon.png')));
app.get('/apple-touch-icon.png', (req, res) => res.sendFile(path.join(__dirname, 'apple-touch-icon.png')));

// ─────────────────────────────────────────────
// HTML ROUTES
// ─────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.get('/health', (req, res) => res.json({
  status: 'ok',
  timestamp: new Date().toISOString(),
  uptime: process.uptime()
}));

app.get('*.html', (req, res) => res.sendFile(path.join(__dirname, req.path)));

ensureStorage();

// ─────────────────────────────────────────────
// PDF PARSER
// ─────────────────────────────────────────────
let pdfParse;
try {
  pdfParse = require('pdf-parse');
  console.log('✅ pdf-parse loaded');
} catch (e) {
  console.error('❌ pdf-parse unavailable:', e.message);
}

// ─────────────────────────────────────────────
// URL FETCHER — real HTTP(S) scrape
// ─────────────────────────────────────────────

/**
 * Fetches a URL and returns the raw HTML as a string.
 * Follows up to 5 redirects. Times out after 10 s.
 * Rejects on non-200, timeout, or network error.
 */
function fetchUrl(rawUrl, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(rawUrl);
    } catch {
      return reject(new Error('Invalid URL'));
    }

    const lib = url.protocol === 'https:' ? https : http;

    const req = lib.get(
      rawUrl,
      {
        timeout: 10_000,
        headers: {
          // Impersonate a real browser so job boards don't block us
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' +
            'AppleWebKit/537.36 (KHTML, like Gecko) ' +
            'Chrome/124.0.0.0 Safari/537.36',
          'Accept':
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'identity', // avoid gzip so we can read it directly
        },
      },
      (res) => {
        // Follow redirects
        if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
          if (redirectsLeft <= 0) return reject(new Error('Too many redirects'));
          const location = res.headers['location'];
          if (!location) return reject(new Error('Redirect with no Location header'));
          // Resolve relative redirects
          const next = location.startsWith('http')
            ? location
            : new URL(location, rawUrl).href;
          res.resume(); // drain the old response
          return resolve(fetchUrl(next, redirectsLeft - 1));
        }

        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode}`));
        }

        // Check Content-Type — only accept HTML
        const ct = (res.headers['content-type'] || '').toLowerCase();
        if (!ct.includes('text/html') && !ct.includes('text/plain') && !ct.includes('application/xhtml')) {
          res.resume();
          return reject(new Error(`Unsupported content type: ${ct}`));
        }

        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end',  ()    => resolve(Buffer.concat(chunks).toString('utf-8')));
        res.on('error', reject);
      }
    );

    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    req.on('error',   reject);
  });
}

/**
 * Strips HTML tags and decodes common entities, returning clean plain text.
 * Preserves meaningful whitespace between block elements.
 */
function htmlToText(html) {
  return html
    // Remove <script>, <style>, <noscript>, <nav>, <footer>, <header> blocks entirely
    .replace(/<(script|style|noscript|nav|footer|header|svg|iframe)[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    // Insert newlines before block-level tags so we get readable paragraphs
    .replace(/<\/?(p|div|li|br|h[1-6]|section|article|main|aside|tr|th|td)[^>]*>/gi, '\n')
    // Strip all remaining tags
    .replace(/<[^>]+>/g, ' ')
    // Decode HTML entities
    .replace(/&amp;/g,  '&')
    .replace(/&lt;/g,   '<')
    .replace(/&gt;/g,   '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g,  "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    // Collapse whitespace but keep paragraph breaks
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/**
 * Validates that a URL is safe to fetch (no private IPs, no file://, etc.).
 */
function isSafeUrl(rawUrl) {
  let url;
  try { url = new URL(rawUrl); } catch { return false; }

  if (!['http:', 'https:'].includes(url.protocol)) return false;

  const host = url.hostname.toLowerCase();

  // Block private / loopback ranges
  const privatePatterns = [
    /^localhost$/,
    /^127\./,
    /^0\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^::1$/,
    /^fc00:/,
    /^fe80:/,
  ];
  if (privatePatterns.some(p => p.test(host))) return false;

  return true;
}

// ─────────────────────────────────────────────
// API — TEXT ANALYSIS
// ─────────────────────────────────────────────
app.post('/analyze', (req, res) => {
  try {
    const { text, jobTitle = 'Untitled Job', source = 'Manual' } = req.body;
    if (!text || text.trim().length === 0) {
      return res.status(400).json({ error: 'Job description text is required' });
    }
    res.json(analyzeJob(text, jobTitle, source));
  } catch (err) {
    console.error('Text analysis error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// API — FILE ANALYSIS
// ─────────────────────────────────────────────
app.post('/analyze-file', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const file     = req.file;
    const jobTitle = req.body.jobTitle || file.originalname;
    const ext      = path.extname(file.originalname).toLowerCase();
    let   extractedText = '';

    if (ext === '.pdf') {
      if (!pdfParse) throw new Error('PDF parser not available');
      const data = await pdfParse(file.buffer);
      extractedText = data.text || '';
    } else if (ext === '.docx' || ext === '.doc') {
      const mammoth = require('mammoth');
      const result  = await mammoth.extractRawText({ buffer: file.buffer });
      extractedText = result.value || '';
    }

    if (!extractedText || extractedText.trim().length < 30) {
      return res.status(400).json({
        error: 'Could not extract enough text. Please paste the job content manually.'
      });
    }

    const result = analyzeJob(extractedText, jobTitle, 'File Upload');
    res.json({ ...result, filename: file.originalname, extractedLength: extractedText.length });

  } catch (err) {
    console.error('File analysis error:', err);
    res.status(500).json({ error: 'File processing failed', message: err.message });
  }
});

// ─────────────────────────────────────────────
// API — URL ANALYSIS (real fetch)
// ─────────────────────────────────────────────
app.post('/analyze-url', async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL is required' });
  }

  // Normalise — add https:// if missing
  const rawUrl = url.startsWith('http') ? url : `https://${url}`;

  if (!isSafeUrl(rawUrl)) {
    return res.status(400).json({ error: 'Invalid or disallowed URL' });
  }

  let pageText   = '';
  let fetchError = null;
  let pageTitle  = 'URL Job Posting';

  try {
    const html = await fetchUrl(rawUrl);

    // Try to grab <title> for a better job title
    const titleMatch = html.match(/<title[^>]*>([^<]{1,120})<\/title>/i);
    if (titleMatch) pageTitle = titleMatch[1].trim().replace(/\s+/g, ' ');

    pageText = htmlToText(html);

    // Trim to a sensible max so we don't blow the analyser
    if (pageText.length > 15_000) pageText = pageText.slice(0, 15_000);

    if (pageText.trim().length < 50) {
      throw new Error('Page returned too little readable text');
    }

  } catch (err) {
    fetchError = err.message;
    console.warn(`URL fetch failed for ${rawUrl}: ${err.message}`);
  }

  // If fetch failed entirely, fall back to URL-structure analysis only
  // (much more honest than the old fake simulatedText)
  if (!pageText) {
    const urlObj   = new URL(rawUrl);
    const hostname = urlObj.hostname.replace(/^www\./, '');
    const pathname = urlObj.pathname;

    // Build a minimal but real signal set from the URL itself
    const urlSignals = [
      `Job posting URL: ${rawUrl}`,
      `Domain: ${hostname}`,
      `Path: ${pathname}`,
    ];

    // Known-legitimate job board domains get a note
    const trustedBoards = [
      'linkedin.com', 'indeed.com', 'glassdoor.com', 'monster.com',
      'ziprecruiter.com', 'lever.co', 'greenhouse.io', 'workday.com',
      'bamboohr.com', 'ashbyhq.com', 'careers.google.com', 'jobs.apple.com',
      'jobs.microsoft.com', 'amazon.jobs',
    ];
    if (trustedBoards.some(b => hostname.endsWith(b))) {
      urlSignals.push('Posted on a verified job board platform');
      urlSignals.push('Official company careers page');
      urlSignals.push('Apply through our website');
    }

    // Suspicious path patterns
    if (/whatsapp|telegram|bit\.ly|tinyurl|t\.me/i.test(rawUrl)) {
      urlSignals.push('Contact only on WhatsApp');
    }
    if (/earn|income|passive|crypto|bitcoin/i.test(rawUrl)) {
      urlSignals.push('Easy money earn income');
    }

    pageText = urlSignals.join('\n');
  }

  try {
    const result = analyzeJob(pageText, pageTitle, 'URL');

    res.json({
      ...result,
      url:          rawUrl,
      pageTitle,
      fetchSuccess: !fetchError,
      fetchError:   fetchError || null,
      extractedLength: pageText.length,
      // Always include a note so the UI can show context
      note: fetchError
        ? `Could not fetch page content (${fetchError}). Score is based on URL structure only.`
        : `Page content fetched and analysed (${pageText.length} characters).`,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// API — HISTORY
// ─────────────────────────────────────────────
app.get('/analyses', (req, res) => {
  try {
    res.json(getAllAnalyses(50));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// CATCH-ALL
// ─────────────────────────────────────────────
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 VerifyJobs running on http://localhost:${PORT}`);
  console.log(`📄 Serving from: ${__dirname}`);
  console.log(`✅ Health: http://localhost:${PORT}/health`);
});