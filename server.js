// server.js — VerifyJobs v1.5
// Real URL fetching with canonical apply-link follow-through.

const express = require('express');
const cors    = require('cors');
const path    = require('path');
const multer  = require('multer');
const https   = require('https');
const http    = require('http');

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
// STATIC ROUTES
// ─────────────────────────────────────────────
app.get('/favicon.ico',          (req, res) => res.sendFile(path.join(__dirname, 'favicon.ico')));
app.get('/favicon.png',          (req, res) => res.sendFile(path.join(__dirname, 'favicon.png')));
app.get('/apple-touch-icon.png', (req, res) => res.sendFile(path.join(__dirname, 'apple-touch-icon.png')));
app.get('/',                     (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString(), uptime: process.uptime() }));
app.get('*.html',  (req, res) => res.sendFile(path.join(__dirname, req.path)));

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
// DOMAIN LISTS
// ─────────────────────────────────────────────

// Aggregator/wrapper sites — should always follow to the real job page
const KNOWN_AGGREGATORS = [
  'jobinsider.in', 'jobsora.com', 'jobisjob.com', 'jobrapido.com',
  'trovit.com', 'mitula.com', 'neuvoo.com', 'talent.com',
  'jobgurus.com', 'jobsearch.co', 'joblist.com', 'jobcase.com',
  'simplyhired.com', 'zippia.com', 'careerjet.com', 'jobted.com',
  'jooble.org', 'adzuna.com', 'snagajob.com', 'jobomas.com',
  'recruitnet.co', 'jobsboard.io', 'myjobmag.com', 'jobberman.com',
  'ngcareers.com', 'hotnigerianobs.com',
];

// Authoritative job sources — if we land here we are already at the real page
const CANONICAL_SOURCES = [
  'linkedin.com', 'indeed.com', 'glassdoor.com', 'monster.com',
  'ziprecruiter.com', 'lever.co', 'greenhouse.io', 'workday.com',
  'bamboohr.com', 'ashbyhq.com', 'myworkdayjobs.com', 'icims.com',
  'taleo.net', 'smartrecruiters.com', 'jobvite.com',
  'amazon.jobs', 'careers.google.com', 'jobs.apple.com',
  'jobs.microsoft.com', 'meta.com', 'careers.meta.com',
];

function isKnownAggregator(hostname) {
  const h = hostname.replace(/^www\./, '');
  return KNOWN_AGGREGATORS.some(d => h === d || h.endsWith('.' + d));
}

function isCanonicalSource(hostname) {
  const h = hostname.replace(/^www\./, '');
  return CANONICAL_SOURCES.some(d => h === d || h.endsWith('.' + d));
}

// ─────────────────────────────────────────────
// SAFETY CHECK
// ─────────────────────────────────────────────
function isSafeUrl(rawUrl) {
  let url;
  try { url = new URL(rawUrl); } catch { return false; }
  if (!['http:', 'https:'].includes(url.protocol)) return false;
  const host = url.hostname.toLowerCase();
  return ![
    /^localhost$/, /^127\./, /^0\./, /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^::1$/, /^fc00:/, /^fe80:/,
  ].some(p => p.test(host));
}

// ─────────────────────────────────────────────
// HTTP FETCHER  (follows redirects, returns html + finalUrl)
// ─────────────────────────────────────────────
function fetchUrl(rawUrl, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(rawUrl); } catch { return reject(new Error('Invalid URL')); }

    const lib = url.protocol === 'https:' ? https : http;

    const req = lib.get(rawUrl, {
      timeout: 12_000,
      headers: {
        'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'identity',
        'Cache-Control':   'no-cache',
      },
    }, (res) => {
      // Follow HTTP redirects
      if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
        if (redirectsLeft <= 0) return reject(new Error('Too many redirects'));
        const location = res.headers['location'];
        if (!location) return reject(new Error('Redirect with no Location header'));
        const next = location.startsWith('http') ? location : new URL(location, rawUrl).href;
        res.resume();
        return resolve(fetchUrl(next, redirectsLeft - 1));
      }

      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }

      const ct = (res.headers['content-type'] || '').toLowerCase();
      if (!ct.includes('text/html') && !ct.includes('text/plain') && !ct.includes('application/xhtml')) {
        res.resume();
        return reject(new Error(`Unsupported content type: ${ct}`));
      }

      const chunks = [];
      res.on('data',  chunk => chunks.push(chunk));
      res.on('end',   ()    => resolve({ html: Buffer.concat(chunks).toString('utf-8'), finalUrl: rawUrl }));
      res.on('error', reject);
    });

    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    req.on('error',   reject);
  });
}

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
function resolveUrl(href, base) {
  try { return new URL(href, base).href; } catch { return null; }
}

function isSameHost(a, b) {
  try { return new URL(a).hostname === new URL(b).hostname; } catch { return false; }
}

function extractPageTitle(html) {
  const m = html.match(/<title[^>]*>([^<]{1,200})<\/title>/i);
  return m ? m[1].trim().replace(/\s+/g, ' ') : '';
}

function htmlToText(html) {
  return html
    .replace(/<(script|style|noscript|nav|footer|header|svg|iframe)[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<\/?(p|div|li|br|h[1-6]|section|article|main|aside|tr|th|td)[^>]*>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g,  '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
}

// ─────────────────────────────────────────────
// CANONICAL URL EXTRACTOR
// Given the HTML of a wrapper/aggregator page, finds the real job URL.
// Returns { url, strategy } or null.
// ─────────────────────────────────────────────
function extractCanonicalJobUrl(html, pageUrl) {
  const candidates = [];

  // ── 1. <link rel="canonical"> ───────────────────────────────────────────
  const cm = html.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']/i)
          || html.match(/<link[^>]+href=["']([^"']+)["'][^>]+rel=["']canonical["']/i);
  if (cm) {
    const u = resolveUrl(cm[1], pageUrl);
    if (u && !isSameHost(u, pageUrl) && isSafeUrl(u)) candidates.push({ url: u, strategy: 'canonical-link', priority: 1 });
  }

  // ── 2. og:url meta tag ──────────────────────────────────────────────────
  const og = html.match(/<meta[^>]+property=["']og:url["'][^>]+content=["']([^"']+)["']/i)
          || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:url["']/i);
  if (og) {
    const u = resolveUrl(og[1], pageUrl);
    if (u && !isSameHost(u, pageUrl) && isSafeUrl(u)) candidates.push({ url: u, strategy: 'og:url', priority: 2 });
  }

  // ── 3. JSON-LD Schema.org JobPosting ────────────────────────────────────
  const jsonLdBlocks = html.match(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi) || [];
  for (const block of jsonLdBlocks) {
    try {
      const data  = JSON.parse(block.replace(/<\/?script[^>]*>/gi, '').trim());
      const items = Array.isArray(data) ? data : [data];
      for (const item of items) {
        if (item['@type'] === 'JobPosting') {
          for (const key of ['url', 'sameAs']) {
            const val = item[key];
            if (val && typeof val === 'string') {
              const u = resolveUrl(val, pageUrl);
              if (u && !isSameHost(u, pageUrl) && isSafeUrl(u)) candidates.push({ url: u, strategy: 'json-ld', priority: 2 });
            }
          }
        }
      }
    } catch { /* malformed JSON */ }
  }

  // ── 4. "Apply" button or link pointing off-site ─────────────────────────
  const applyRegexes = [
    /<a[^>]+href=["']([^"']+)["'][^>]*>\s*(?:<[^>]+>\s*)*apply(?:\s+now|\s+here|\s+online|\s+for\s+this\s+job)?\s*(?:<\/[^>]+>\s*)*<\/a>/gi,
    /<a[^>]*class=["'][^"']*(?:apply|btn-apply|job-apply|apply-btn)[^"']*["'][^>]*href=["']([^"']+)["']/gi,
    /<a[^>]*href=["']([^"']+)["'][^>]*class=["'][^"']*(?:apply|btn-apply|job-apply)[^"']*["']/gi,
  ];
  for (const rx of applyRegexes) {
    rx.lastIndex = 0;
    let m;
    while ((m = rx.exec(html)) !== null) {
      const href = m[1];
      if (!href || /^[#\s]|javascript:|mailto:/i.test(href)) continue;
      const u = resolveUrl(href, pageUrl);
      if (u && !isSameHost(u, pageUrl) && isSafeUrl(u)) candidates.push({ url: u, strategy: 'apply-button', priority: 3 });
    }
  }

  // ── 5. data-* attributes (common in React job boards) ───────────────────
  const dataRx = [
    /data-(?:apply-url|apply-link|external-url|source-url|job-url|redirect-url)=["']([^"']+)["']/gi,
    /data-(?:href|link)=["'](https?:\/\/[^"']+)["']/gi,
  ];
  for (const rx of dataRx) {
    rx.lastIndex = 0;
    let m;
    while ((m = rx.exec(html)) !== null) {
      const u = resolveUrl(m[1], pageUrl);
      if (u && !isSameHost(u, pageUrl) && isSafeUrl(u)) candidates.push({ url: u, strategy: 'data-attribute', priority: 4 });
    }
  }

  // ── 6. Redirect/tracking query params ───────────────────────────────────
  const redirectRx = [
    /href=["'][^"']*[?&](?:url|to|href|link|target|go)=(https?%3A[^"'&]+)/gi,
    /href=["'][^"']*[?&](?:url|to|href|link|target|go)=(https?:\/\/[^"'&]+)/gi,
  ];
  for (const rx of redirectRx) {
    rx.lastIndex = 0;
    let m;
    while ((m = rx.exec(html)) !== null) {
      try {
        const u = resolveUrl(decodeURIComponent(m[1]), pageUrl);
        if (u && !isSameHost(u, pageUrl) && isSafeUrl(u)) candidates.push({ url: u, strategy: 'redirect-param', priority: 3 });
      } catch { /* skip */ }
    }
  }

  if (!candidates.length) return null;

  // Deduplicate and rank:
  // canonical sources (amazon.jobs, linkedin, etc.) come first, then by strategy priority
  const seen   = new Set();
  const unique = candidates.filter(c => {
    if (seen.has(c.url)) return false;
    seen.add(c.url); return true;
  });

  unique.sort((a, b) => {
    const aIs = isCanonicalSource(new URL(a.url).hostname) ? 0 : 1;
    const bIs = isCanonicalSource(new URL(b.url).hostname) ? 0 : 1;
    return aIs !== bIs ? aIs - bIs : a.priority - b.priority;
  });

  return unique[0];
}

// ─────────────────────────────────────────────
// FULL SCRAPE PIPELINE
// ─────────────────────────────────────────────
async function scrapeAndAnalyze(rawUrl) {
  const ctx = {
    submittedUrl:   rawUrl,
    canonicalUrl:   null,
    resolvedFrom:   null,
    fetchedPages:   [],
    combinedText:   '',
    pageTitle:      'URL Job Posting',
    fetchError:     null,
    canonicalError: null,
    isAggregator:   false,
  };

  // Step 1 — fetch the submitted page
  let wrapperHtml = '';
  try {
    const { html } = await fetchUrl(rawUrl);
    wrapperHtml     = html;
    ctx.pageTitle   = extractPageTitle(html) || ctx.pageTitle;
    ctx.fetchedPages.push(rawUrl);
    ctx.isAggregator = isKnownAggregator(new URL(rawUrl).hostname);
  } catch (err) {
    ctx.fetchError = err.message;
    // Build URL-structure-only fallback text
    ctx.combinedText = buildUrlFallbackText(rawUrl);
    return ctx;
  }

  const wrapperText = htmlToText(wrapperHtml);

  // Step 2 — find the canonical / real job URL
  const canonical = extractCanonicalJobUrl(wrapperHtml, rawUrl);

  if (canonical && isSafeUrl(canonical.url)) {
    ctx.canonicalUrl = canonical.url;
    ctx.resolvedFrom = canonical.strategy;

    // Step 3 — fetch the real job page
    try {
      const { html: realHtml } = await fetchUrl(canonical.url);
      const realText  = htmlToText(realHtml);
      const realTitle = extractPageTitle(realHtml);
      if (realTitle) ctx.pageTitle = realTitle;
      ctx.fetchedPages.push(canonical.url);

      // Merge: real page first (authoritative), wrapper appended for context
      ctx.combinedText = [
        realText.slice(0, 10_000),
        '---',
        wrapperText.slice(0, 5_000),
      ].join('\n').slice(0, 15_000);

    } catch (err) {
      ctx.canonicalError = err.message;
      // Real page failed — wrapper text only
      ctx.combinedText = wrapperText.slice(0, 15_000);
    }

  } else {
    // No canonical found — wrapper text only
    ctx.combinedText = wrapperText.slice(0, 15_000);
  }

  // Last-resort fallback if still too thin
  if (ctx.combinedText.trim().length < 50) {
    ctx.combinedText = buildUrlFallbackText(rawUrl);
  }

  return ctx;
}

function buildUrlFallbackText(rawUrl) {
  const urlObj   = new URL(rawUrl);
  const hostname = urlObj.hostname.replace(/^www\./, '');
  const lines    = [`Job posting URL: ${rawUrl}`, `Domain: ${hostname}`, `Path: ${urlObj.pathname}`];
  if (isCanonicalSource(hostname)) {
    lines.push('Posted on a verified job board platform', 'Official company careers page', 'Apply through our website');
  }
  if (/whatsapp|telegram|bit\.ly|tinyurl|t\.me/i.test(rawUrl)) lines.push('Contact only on WhatsApp');
  if (/earn|income|passive|crypto|bitcoin/i.test(rawUrl))       lines.push('Easy money earn income');
  return lines.join('\n');
}

function buildNote(ctx) {
  const parts = [];
  if (ctx.canonicalUrl) {
    parts.push(`Real job page found on ${new URL(ctx.canonicalUrl).hostname} (via ${ctx.resolvedFrom}).`);
    if (ctx.canonicalError) parts.push(`Could not fetch that page (${ctx.canonicalError}) — wrapper text used instead.`);
    else parts.push('Both pages were analysed for maximum accuracy.');
  } else if (ctx.fetchError) {
    parts.push(`Page fetch failed (${ctx.fetchError}). Score is based on URL structure only.`);
  } else {
    parts.push(`Analysed ${ctx.combinedText.length} characters from ${ctx.fetchedPages.length} page(s).`);
    if (!ctx.canonicalUrl) parts.push('No external apply link detected — this may already be the source page.');
  }
  return parts.join(' ');
}

// ─────────────────────────────────────────────
// API — TEXT
// ─────────────────────────────────────────────
app.post('/analyze', (req, res) => {
  try {
    const { text, jobTitle = 'Untitled Job', source = 'Manual' } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'Job description text is required' });
    res.json(analyzeJob(text, jobTitle, source));
  } catch (err) {
    console.error('Text analysis error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// API — FILE
// ─────────────────────────────────────────────
app.post('/analyze-file', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const file     = req.file;
    const jobTitle = req.body.jobTitle || file.originalname;
    const ext      = path.extname(file.originalname).toLowerCase();
    let text       = '';

    if (ext === '.pdf') {
      if (!pdfParse) throw new Error('PDF parser not available');
      text = (await pdfParse(file.buffer)).text || '';
    } else if (ext === '.docx' || ext === '.doc') {
      const mammoth = require('mammoth');
      text = (await mammoth.extractRawText({ buffer: file.buffer })).value || '';
    }

    if (!text || text.trim().length < 30) {
      return res.status(400).json({ error: 'Could not extract enough text. Please paste the content manually.' });
    }

    res.json({ ...analyzeJob(text, jobTitle, 'File Upload'), filename: file.originalname, extractedLength: text.length });
  } catch (err) {
    console.error('File analysis error:', err);
    res.status(500).json({ error: 'File processing failed', message: err.message });
  }
});

// ─────────────────────────────────────────────
// API — URL  (the full pipeline)
// ─────────────────────────────────────────────
app.post('/analyze-url', async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'URL is required' });

  const rawUrl = url.trim().startsWith('http') ? url.trim() : `https://${url.trim()}`;
  if (!isSafeUrl(rawUrl)) return res.status(400).json({ error: 'Invalid or disallowed URL' });

  try {
    const ctx      = await scrapeAndAnalyze(rawUrl);
    const analysis = analyzeJob(ctx.combinedText, ctx.pageTitle, 'URL');

    res.json({
      ...analysis,
      submittedUrl:    ctx.submittedUrl,
      canonicalUrl:    ctx.canonicalUrl,
      resolvedFrom:    ctx.resolvedFrom,
      fetchedPages:    ctx.fetchedPages,
      isAggregator:    ctx.isAggregator,
      pageTitle:       ctx.pageTitle,
      fetchSuccess:    !ctx.fetchError,
      fetchError:      ctx.fetchError    || null,
      canonicalError:  ctx.canonicalError || null,
      extractedLength: ctx.combinedText.length,
      note:            buildNote(ctx),
    });
  } catch (err) {
    console.error('URL analysis error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// API — HISTORY
// ─────────────────────────────────────────────
app.get('/analyses', (req, res) => {
  try { res.json(getAllAnalyses(50)); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// ─────────────────────────────────────────────
// CATCH-ALL
// ─────────────────────────────────────────────
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'API endpoint not found' });
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 VerifyJobs v1.5 on http://localhost:${PORT}`);
  console.log(`📄 Root: ${__dirname}`);
  console.log(`✅ Health: http://localhost:${PORT}/health`);
});