// server.js — VerifyJobs v2.0 — Production-Ready
// Enhanced with security, rate limiting, caching, logging, and robust error handling

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const dns = require('dns').promises;
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const winston = require('winston');

const analyzeJob = require('./engine/analyzer');
const { ensureStorage, getAllAnalyses } = require('./engine/storage');

// ── CHANGE 1: ML enrichment layer ─────────────────────────────
const { enrichWithML, checkServerHealth } = require('./engine/ml_scorer');

// ─────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────
const config = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024,
  fetchTimeout: parseInt(process.env.FETCH_TIMEOUT) || 12000,
  maxRedirects: parseInt(process.env.MAX_REDIRECTS) || 5,
  cacheEnabled: process.env.CACHE_ENABLED !== 'false',
  cacheTTL: parseInt(process.env.CACHE_TTL) || 3600,
  rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
  rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX) || 50,
  corsOrigin: process.env.CORS_ORIGIN || '*',
};

// ─────────────────────────────────────────────
// LOGGING
// ─────────────────────────────────────────────
const logger = winston.createLogger({
  level: config.nodeEnv === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'verifyjobs-api' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

if (config.nodeEnv !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    ),
  }));
}

// ─────────────────────────────────────────────
// CACHE
// ─────────────────────────────────────────────
const analysisCache = new NodeCache({
  stdTTL: config.cacheTTL,
  checkperiod: 600,
  useClones: false,
});

function getCacheKey(type, data) {
  const normalized = typeof data === 'string' ? data.toLowerCase().trim() : JSON.stringify(data);
  return crypto.createHash('sha256').update(`${type}:${normalized}`).digest('hex');
}

analysisCache.on('expired', (key) => {
  logger.debug('Cache entry expired', { key });
});

// ─────────────────────────────────────────────
// EXPRESS APP
// ─────────────────────────────────────────────
const app = express();

// Trust proxy (required for rate limiting behind reverse proxy)
app.set('trust proxy', 1);

// ─────────────────────────────────────────────
// SECURITY MIDDLEWARE
// ─────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // Handled in HTML
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
}));

app.use(compression());

app.use(cors({
  origin: config.corsOrigin,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
  maxAge: 86400,
}));

app.use(express.json({ limit: '5mb' }));

// ─────────────────────────────────────────────
// RATE LIMITING
// ─────────────────────────────────────────────
const generalLimiter = rateLimit({
  windowMs: config.rateLimitWindow,
  max: config.rateLimitMax * 2,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('Rate limit exceeded', { ip: req.ip, path: req.path });
    res.status(429).json({ error: 'Too many requests, please try again later.' });
  },
});

const analyzeLimiter = rateLimit({
  windowMs: config.rateLimitWindow,
  max: config.rateLimitMax,
  message: { error: 'Too many analysis requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  handler: (req, res) => {
    logger.warn('Analysis rate limit exceeded', { ip: req.ip, path: req.path });
    res.status(429).json({
      error: 'Too many analysis requests, please try again later.',
      retryAfter: Math.ceil(config.rateLimitWindow / 1000 / 60),
    });
  },
});

app.use('/analyze', analyzeLimiter);
app.use('/analyze-file', analyzeLimiter);
app.use('/analyze-url', analyzeLimiter);

// ─────────────────────────────────────────────
// REQUEST LOGGING
// ─────────────────────────────────────────────
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info('Request completed', {
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration,
      ip: req.ip,
    });
  });
  next();
});

// ─────────────────────────────────────────────
// MULTER
// ─────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxFileSize },
  fileFilter: (req, file, cb) => {
    const allowed = ['.pdf', '.doc', '.docx'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only PDF and Word files (.pdf, .doc, .docx) allowed'));
    }
  },
});

// ─────────────────────────────────────────────
// STATIC FILE SERVING
// ─────────────────────────────────────────────

// 1. SEO-CRITICAL FILES FIRST (must be before other static middleware)
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.sendFile(path.join(__dirname, 'robots.txt'), (err) => {
    if (err) {
      logger.error('robots.txt not found');
      res.status(404).send('Not found');
    }
  });
});

app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml');
  res.sendFile(path.join(__dirname, 'sitemap.xml'), (err) => {
    if (err) {
      logger.error('sitemap.xml not found');
      res.status(404).send('Not found');
    }
  });
});

app.get('/structured-data.json', (req, res) => {
  res.type('application/json');
  res.sendFile(path.join(__dirname, 'structured-data.json'), (err) => {
    if (err) {
      logger.error('structured-data.json not found');
      res.status(404).send('Not found');
    }
  });
});

app.get('/llms.txt', (req, res) => {
  res.type('text/plain');
  res.sendFile(path.join(__dirname, 'llms.txt'), (err) => {
    if (err) {
      logger.error('llms.txt not found');
      res.status(404).send('Not found');
    }
  });
});

// Google Search Console verification file
app.get('/google6c2364060583a1e1.html', (req, res) => {
  res.type('text/html');
  res.sendFile(path.join(__dirname, 'google6c2364060583a1e1.html'), (err) => {
    if (err) {
      logger.error('Google verification file not found');
      res.status(404).send('Not found');
    }
  });
});

// 2. Root assets (favicon, og-image, logo, etc.) - NOT recursive
app.use(express.static(__dirname, {
  index: false,
  maxAge: config.nodeEnv === 'production' ? '7d' : 0,
  dotfiles: 'ignore',
  extensions: ['png', 'jpg', 'svg', 'ico', 'webp'],
}));

// 3. Public directory for HTML/CSS/JS
app.use(express.static(path.join(__dirname, 'public'), {
  index: false,
  maxAge: config.nodeEnv === 'production' ? '1d' : 0,
}));

// 4. .well-known directory (RFC 8615)
app.use('/.well-known', express.static(path.join(__dirname, '.well-known'), {
  maxAge: '7d',
}));

// 5. Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '2.0',
    cache: {
      enabled: config.cacheEnabled,
      keys: analysisCache.keys().length,
      stats: analysisCache.getStats(),
    },
  });
});

// 6. Homepage - explicitly serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
    if (err) {
      logger.error('index.html not found');
      res.status(500).send('Server error');
    }
  });
});

// ─────────────────────────────────────────────
// 7. HTML PAGES - Blog & Page Handler
// ─────────────────────────────────────────────
app.get(/^\/[^.]*\.html?$|^\/[a-zA-Z0-9\-_\/]+$/, (req, res) => {
  let fileName = req.path;
  const fs = require('fs');
  
  // Remove trailing slash
  if (fileName.endsWith('/') && fileName.length > 1) {
    fileName = fileName.slice(0, -1);
  }
  
  // Add .html if no extension
  if (!path.extname(fileName)) {
    fileName += '.html';
  }
  
  // Build full path
  const cleanPath = fileName.startsWith('/') ? fileName.slice(1) : fileName;
  const fullPath = path.join(__dirname, 'public', cleanPath);
  
  // Check if file exists
  if (fs.existsSync(fullPath)) {
    res.sendFile(fullPath);
  } else {
    // Try /blog/index.html for /blog
    if (!path.extname(req.path)) {
      const indexPath = path.join(__dirname, 'public', req.path, 'index.html');
      if (fs.existsSync(indexPath)) {
        return res.sendFile(indexPath);
      }
    }
    // Fallback to root index.html
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

// ─────────────────────────────────────────────
// PDF PARSER
// ─────────────────────────────────────────────
let pdfParse;
try {
  pdfParse = require('pdf-parse');
  logger.info('✅ pdf-parse loaded');
} catch (e) {
  logger.error('❌ pdf-parse unavailable', { error: e.message });
}

// ─────────────────────────────────────────────
// DOMAIN LISTS
// ─────────────────────────────────────────────
const KNOWN_AGGREGATORS = [
  'jobinsider.in', 'jobsora.com', 'jobisjob.com', 'jobrapido.com',
  'trovit.com', 'mitula.com', 'neuvoo.com', 'talent.com',
  'jobgurus.com', 'jobsearch.co', 'joblist.com', 'jobcase.com',
  'simplyhired.com', 'zippia.com', 'careerjet.com', 'jobted.com',
  'jooble.org', 'adzuna.com', 'snagajob.com', 'jobomas.com',
  'recruitnet.co', 'jobsboard.io', 'myjobmag.com', 'jobberman.com',
  'ngcareers.com', 'hotnigerianobs.com',
];

const CANONICAL_SOURCES = [
  'linkedin.com', 'indeed.com', 'glassdoor.com', 'monster.com',
  'ziprecruiter.com', 'lever.co', 'greenhouse.io', 'workday.com',
  'bamboohr.com', 'ashbyhq.com', 'myworkdayjobs.com', 'icims.com',
  'taleo.net', 'smartrecruiters.com', 'jobvite.com',
  'amazon.jobs', 'careers.google.com', 'jobs.apple.com',
  'jobs.microsoft.com', 'meta.com', 'careers.meta.com',
];

const BLOCKED_DOMAINS = [
  'localhost', '127.0.0.1', '0.0.0.0',
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
// ENHANCED SAFETY CHECK WITH DNS RESOLUTION
// ─────────────────────────────────────────────
async function isSafeUrl(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }

  if (!['http:', 'https:'].includes(url.protocol)) {
    return false;
  }

  const host = url.hostname.toLowerCase();

  if (BLOCKED_DOMAINS.some(d => host === d || host.endsWith('.' + d))) {
    logger.warn('Blocked domain attempted', { domain: host });
    return false;
  }

  const privatePatterns = [
    /^localhost$/i,
    /^127\./,
    /^0\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^169\.254\./,
    /^::1$/,
    /^fc00:/,
    /^fe80:/,
    /^fd[0-9a-f]{2}:/i,
  ];

  if (privatePatterns.some(p => p.test(host))) {
    logger.warn('Private IP blocked', { host });
    return false;
  }

  try {
    const addresses = await dns.resolve4(host);
    for (const addr of addresses) {
      if (privatePatterns.some(p => p.test(addr))) {
        logger.warn('DNS resolved to private IP', { host, resolvedTo: addr });
        return false;
      }
    }
  } catch (err) {
    logger.warn('DNS resolution failed', { host, error: err.message });
  }

  return true;
}

// ─────────────────────────────────────────────
// HTTP FETCHER WITH ABORT CONTROLLER
// ─────────────────────────────────────────────
function fetchUrl(rawUrl, redirectsLeft = config.maxRedirects, signal = null) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(rawUrl);
    } catch {
      return reject(new Error('Invalid URL'));
    }

    const lib = url.protocol === 'https:' ? https : http;

    const req = lib.get(rawUrl, {
      timeout: config.fetchTimeout,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'identity',
        'Cache-Control': 'no-cache',
        'DNT': '1',
      },
    }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
        if (redirectsLeft <= 0) {
          res.resume();
          return reject(new Error('Too many redirects'));
        }
        const location = res.headers['location'];
        if (!location) {
          res.resume();
          return reject(new Error('Redirect with no Location header'));
        }
        const next = location.startsWith('http') ? location : new URL(location, rawUrl).href;
        res.resume();
        return resolve(fetchUrl(next, redirectsLeft - 1, signal));
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

      const contentLength = parseInt(res.headers['content-length'] || '0');
      if (contentLength > 5 * 1024 * 1024) {
        res.resume();
        return reject(new Error('Response too large'));
      }

      const chunks = [];
      let receivedBytes = 0;

      res.on('data', chunk => {
        receivedBytes += chunk.length;
        if (receivedBytes > 5 * 1024 * 1024) {
          req.destroy();
          return reject(new Error('Response too large'));
        }
        chunks.push(chunk);
      });

      res.on('end', () => {
        try {
          const html = Buffer.concat(chunks).toString('utf-8');
          resolve({ html, finalUrl: rawUrl });
        } catch (err) {
          reject(new Error('Failed to decode response'));
        }
      });

      res.on('error', reject);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });

    req.on('error', (err) => {
      reject(err);
    });

    if (signal) {
      signal.addEventListener('abort', () => {
        req.destroy();
        reject(new Error('Request aborted'));
      });
    }
  });
}

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
function resolveUrl(href, base) {
  try {
    return new URL(href, base).href;
  } catch {
    return null;
  }
}

function isSameHost(a, b) {
  try {
    return new URL(a).hostname === new URL(b).hostname;
  } catch {
    return false;
  }
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
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// ─────────────────────────────────────────────
// CANONICAL URL EXTRACTOR
// ─────────────────────────────────────────────
function extractCanonicalJobUrl(html, pageUrl) {
  const candidates = [];

  const cm = html.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']/i) ||
    html.match(/<link[^>]+href=["']([^"']+)["'][^>]+rel=["']canonical["']/i);
  if (cm) {
    const u = resolveUrl(cm[1], pageUrl);
    if (u && !isSameHost(u, pageUrl) && isSafeUrl(u)) {
      candidates.push({ url: u, strategy: 'canonical-link', priority: 1 });
    }
  }

  const og = html.match(/<meta[^>]+property=["']og:url["'][^>]+content=["']([^"']+)["']/i) ||
    html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:url["']/i);
  if (og) {
    const u = resolveUrl(og[1], pageUrl);
    if (u && !isSameHost(u, pageUrl) && isSafeUrl(u)) {
      candidates.push({ url: u, strategy: 'og:url', priority: 2 });
    }
  }

  const jsonLdBlocks = html.match(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi) || [];
  for (const block of jsonLdBlocks) {
    try {
      const data = JSON.parse(block.replace(/<\/?script[^>]*>/gi, '').trim());
      const items = Array.isArray(data) ? data : [data];
      for (const item of items) {
        if (item['@type'] === 'JobPosting') {
          for (const key of ['url', 'sameAs']) {
            const val = item[key];
            if (val && typeof val === 'string') {
              const u = resolveUrl(val, pageUrl);
              if (u && !isSameHost(u, pageUrl) && isSafeUrl(u)) {
                candidates.push({ url: u, strategy: 'json-ld', priority: 2 });
              }
            }
          }
        }
      }
    } catch {
      // Malformed JSON
    }
  }

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
      if (u && !isSameHost(u, pageUrl) && isSafeUrl(u)) {
        candidates.push({ url: u, strategy: 'apply-button', priority: 3 });
      }
    }
  }

  const dataRx = [
    /data-(?:apply-url|apply-link|external-url|source-url|job-url|redirect-url)=["']([^"']+)["']/gi,
    /data-(?:href|link)=["'](https?:\/\/[^"']+)["']/gi,
  ];
  for (const rx of dataRx) {
    rx.lastIndex = 0;
    let m;
    while ((m = rx.exec(html)) !== null) {
      const u = resolveUrl(m[1], pageUrl);
      if (u && !isSameHost(u, pageUrl) && isSafeUrl(u)) {
        candidates.push({ url: u, strategy: 'data-attribute', priority: 4 });
      }
    }
  }

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
        if (u && !isSameHost(u, pageUrl) && isSafeUrl(u)) {
          candidates.push({ url: u, strategy: 'redirect-param', priority: 3 });
        }
      } catch {
        // Skip malformed URLs
      }
    }
  }

  if (!candidates.length) return null;

  const seen = new Set();
  const unique = candidates.filter(c => {
    if (seen.has(c.url)) return false;
    seen.add(c.url);
    return true;
  });

  unique.sort((a, b) => {
    const aIs = isCanonicalSource(new URL(a.url).hostname) ? 0 : 1;
    const bIs = isCanonicalSource(new URL(b.url).hostname) ? 0 : 1;
    return aIs !== bIs ? aIs - bIs : a.priority - b.priority;
  });

  return unique[0];
}

// ─────────────────────────────────────────────
// FULL SCRAPE PIPELINE WITH ABORT CONTROLLER
// ─────────────────────────────────────────────
async function scrapeAndAnalyze(rawUrl) {
  const abortController = new AbortController();
  const timeoutId = setTimeout(() => abortController.abort(), 30000);

  const ctx = {
    submittedUrl: rawUrl,
    canonicalUrl: null,
    resolvedFrom: null,
    fetchedPages: [],
    combinedText: '',
    pageTitle: 'URL Job Posting',
    fetchError: null,
    canonicalError: null,
    isAggregator: false,
  };

  try {
    const isSafe = await isSafeUrl(rawUrl);
    if (!isSafe) {
      throw new Error('URL is not allowed (private IP or blocked domain)');
    }

    let wrapperHtml = '';
    try {
      const { html } = await fetchUrl(rawUrl, config.maxRedirects, abortController.signal);
      wrapperHtml = html;
      ctx.pageTitle = extractPageTitle(html) || ctx.pageTitle;
      ctx.fetchedPages.push(rawUrl);
      ctx.isAggregator = isKnownAggregator(new URL(rawUrl).hostname);
      logger.debug('Fetched wrapper page', { url: rawUrl, length: html.length });
    } catch (err) {
      ctx.fetchError = err.message;
      logger.warn('Failed to fetch wrapper page', { url: rawUrl, error: err.message });
      ctx.combinedText = buildUrlFallbackText(rawUrl);
      return ctx;
    }

    const wrapperText = htmlToText(wrapperHtml);

    const canonical = extractCanonicalJobUrl(wrapperHtml, rawUrl);

    if (canonical) {
      const canonicalSafe = await isSafeUrl(canonical.url);
      if (canonicalSafe) {
        ctx.canonicalUrl = canonical.url;
        ctx.resolvedFrom = canonical.strategy;

        logger.debug('Canonical URL found', { canonical: canonical.url, strategy: canonical.strategy });

        try {
          const { html: realHtml } = await fetchUrl(canonical.url, config.maxRedirects, abortController.signal);
          const realText = htmlToText(realHtml);
          const realTitle = extractPageTitle(realHtml);
          if (realTitle) ctx.pageTitle = realTitle;
          ctx.fetchedPages.push(canonical.url);

          ctx.combinedText = [
            realText.slice(0, 10000),
            '---',
            wrapperText.slice(0, 5000),
          ].join('\n').slice(0, 15000);

          logger.debug('Fetched canonical page', { url: canonical.url, length: realHtml.length });
        } catch (err) {
          ctx.canonicalError = err.message;
          logger.warn('Failed to fetch canonical page', { url: canonical.url, error: err.message });
          ctx.combinedText = wrapperText.slice(0, 15000);
        }
      } else {
        logger.warn('Canonical URL is unsafe, skipping', { url: canonical.url });
        ctx.combinedText = wrapperText.slice(0, 15000);
      }
    } else {
      ctx.combinedText = wrapperText.slice(0, 15000);
    }

    if (ctx.combinedText.trim().length < 50) {
      ctx.combinedText = buildUrlFallbackText(rawUrl);
    }

    return ctx;
  } finally {
    clearTimeout(timeoutId);
  }
}

function buildUrlFallbackText(rawUrl) {
  const urlObj = new URL(rawUrl);
  const hostname = urlObj.hostname.replace(/^www\./, '');
  const lines = [
    `Job posting URL: ${rawUrl}`,
    `Domain: ${hostname}`,
    `Path: ${urlObj.pathname}`,
  ];

  if (isCanonicalSource(hostname)) {
    lines.push('Posted on a verified job board platform');
    lines.push('Official company careers page');
    lines.push('Apply through our website');
  }

  if (/whatsapp|telegram|bit\.ly|tinyurl|t\.me/i.test(rawUrl)) {
    lines.push('Contact only on WhatsApp');
  }

  if (/earn|income|passive|crypto|bitcoin/i.test(rawUrl)) {
    lines.push('Easy money earn income');
  }

  return lines.join('\n');
}

function buildNote(ctx) {
  const parts = [];
  if (ctx.canonicalUrl) {
    parts.push(`Real job page found on ${new URL(ctx.canonicalUrl).hostname} (via ${ctx.resolvedFrom}).`);
    if (ctx.canonicalError) {
      parts.push(`Could not fetch that page (${ctx.canonicalError}) — wrapper text used instead.`);
    } else {
      parts.push('Both pages were analysed for maximum accuracy.');
    }
  } else if (ctx.fetchError) {
    parts.push(`Page fetch failed (${ctx.fetchError}). Score is based on URL structure only.`);
  } else {
    parts.push(`Analysed ${ctx.combinedText.length} characters from ${ctx.fetchedPages.length} page(s).`);
    if (!ctx.canonicalUrl) {
      parts.push('No external apply link detected — this may already be the source page.');
    }
  }
  return parts.join(' ');
}

// ─────────────────────────────────────────────
// INPUT VALIDATION MIDDLEWARE
// ─────────────────────────────────────────────
function validateTextInput(req, res, next) {
  const { text, jobTitle, source } = req.body;

  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: 'Job description text is required' });
  }

  const trimmedText = text.trim();
  if (trimmedText.length < 10) {
    return res.status(400).json({ error: 'Job description is too short (minimum 10 characters)' });
  }

  if (trimmedText.length > 50000) {
    return res.status(400).json({ error: 'Job description is too long (maximum 50,000 characters)' });
  }

  if (jobTitle && typeof jobTitle === 'string' && jobTitle.length > 200) {
    return res.status(400).json({ error: 'Job title is too long (maximum 200 characters)' });
  }

  if (source && typeof source === 'string' && source.length > 100) {
    return res.status(400).json({ error: 'Source is too long (maximum 100 characters)' });
  }

  req.validatedInput = {
    text: trimmedText,
    jobTitle: jobTitle?.trim() || 'Untitled Job',
    source: source?.trim() || 'Manual',
  };

  next();
}

function validateUrlInput(req, res, next) {
  const { url } = req.body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL is required' });
  }

  const trimmedUrl = url.trim();
  if (trimmedUrl.length > 2048) {
    return res.status(400).json({ error: 'URL is too long' });
  }

  req.validatedUrl = trimmedUrl.startsWith('http') ? trimmedUrl : `https://${trimmedUrl}`;
  next();
}

// ─────────────────────────────────────────────
// API — TEXT (CHANGE 3: async + enrichWithML)
// ─────────────────────────────────────────────
app.post('/analyze', validateTextInput, async (req, res) => {
  const startTime = Date.now();
  try {
    const { text, jobTitle, source } = req.validatedInput;

    if (config.cacheEnabled) {
      const cacheKey = getCacheKey('text', { text, jobTitle, source });
      const cached = analysisCache.get(cacheKey);
      if (cached) {
        logger.info('Cache hit for text analysis', { jobTitle, duration: Date.now() - startTime });
        return res.json({ ...cached, cached: true, cachedAt: new Date().toISOString() });
      }
    }

    const ruleResult = analyzeJob(text, jobTitle, source);
    const result     = await enrichWithML(text, ruleResult);

    if (config.cacheEnabled) {
      const cacheKey = getCacheKey('text', { text, jobTitle, source });
      analysisCache.set(cacheKey, result);
    }

    logger.info('Text analysis completed', {
      jobTitle,
      status: result.status,
      riskScore: result.riskScore,
      mlAvailable: result.ml?.available,
      blendMethod: result.ml?.blendMethod,
      duration: Date.now() - startTime,
    });

    res.json(result);
  } catch (err) {
    logger.error('Text analysis error', { error: err.message, stack: err.stack });
    res.status(500).json({
      error: 'Analysis failed',
      message: config.nodeEnv === 'development' ? err.message : 'Internal server error',
    });
  }
});

// ─────────────────────────────────────────────
// API — FILE (CHANGE 4: async + enrichWithML)
// ─────────────────────────────────────────────
app.post('/analyze-file', upload.single('file'), async (req, res) => {
  const startTime = Date.now();
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const file = req.file;
    const jobTitle = req.body.jobTitle?.trim() || file.originalname;
    const ext = path.extname(file.originalname).toLowerCase();
    let text = '';

    logger.info('File upload received', {
      filename: file.originalname,
      size: file.size,
      mimetype: file.mimetype,
    });

    if (ext === '.pdf') {
      if (!pdfParse) {
        throw new Error('PDF parser not available on this server');
      }
      const pdfData = await pdfParse(file.buffer);
      text = pdfData.text || '';
    } else if (ext === '.docx' || ext === '.doc') {
      const mammoth = require('mammoth');
      const extracted = await mammoth.extractRawText({ buffer: file.buffer });
      text = extracted.value || '';
    } else {
      return res.status(400).json({ error: 'Unsupported file type' });
    }

    text = text.trim();

    if (!text || text.length < 30) {
      logger.warn('Insufficient text extracted from file', {
        filename: file.originalname,
        extractedLength: text.length,
      });
      return res.status(400).json({
        error: 'Could not extract enough text from the file',
        message: 'Please ensure the file contains readable text, or paste the content manually.',
        extractedLength: text.length,
      });
    }

    if (config.cacheEnabled) {
      const cacheKey = getCacheKey('file', { text, jobTitle });
      const cached = analysisCache.get(cacheKey);
      if (cached) {
        logger.info('Cache hit for file analysis', { filename: file.originalname });
        return res.json({ ...cached, filename: file.originalname, extractedLength: text.length, cached: true });
      }
    }

    const ruleResult = analyzeJob(text, jobTitle, 'File Upload');
    const result     = await enrichWithML(text, ruleResult);

    if (config.cacheEnabled) {
      const cacheKey = getCacheKey('file', { text, jobTitle });
      analysisCache.set(cacheKey, result);
    }

    logger.info('File analysis completed', {
      filename: file.originalname,
      status: result.status,
      riskScore: result.riskScore,
      mlAvailable: result.ml?.available,
      extractedLength: text.length,
      duration: Date.now() - startTime,
    });

    res.json({ ...result, filename: file.originalname, extractedLength: text.length });
  } catch (err) {
    logger.error('File analysis error', {
      error: err.message,
      stack: err.stack,
      filename: req.file?.originalname,
    });
    res.status(500).json({
      error: 'File processing failed',
      message: config.nodeEnv === 'development' ? err.message : 'Could not process the file',
    });
  }
});

// ─────────────────────────────────────────────
// API — URL (CHANGE 5: enrichWithML added)
// ─────────────────────────────────────────────
app.post('/analyze-url', validateUrlInput, async (req, res) => {
  const startTime = Date.now();
  const rawUrl = req.validatedUrl;

  try {
    const isSafe = await isSafeUrl(rawUrl);
    if (!isSafe) {
      logger.warn('Unsafe URL blocked', { url: rawUrl, ip: req.ip });
      return res.status(400).json({
        error: 'Invalid or disallowed URL',
        message: 'The URL appears to be a private IP address or blocked domain.',
      });
    }

    if (config.cacheEnabled) {
      const cacheKey = getCacheKey('url', rawUrl);
      const cached = analysisCache.get(cacheKey);
      if (cached) {
        logger.info('Cache hit for URL analysis', { url: rawUrl, duration: Date.now() - startTime });
        return res.json({ ...cached, cached: true, cachedAt: new Date().toISOString() });
      }
    }

    const ctx        = await scrapeAndAnalyze(rawUrl);
    const ruleResult = analyzeJob(ctx.combinedText, ctx.pageTitle, 'URL');
    const result     = await enrichWithML(ctx.combinedText, ruleResult);

    const final = {
      ...result,
      submittedUrl:    ctx.submittedUrl,
      canonicalUrl:    ctx.canonicalUrl,
      resolvedFrom:    ctx.resolvedFrom,
      fetchedPages:    ctx.fetchedPages,
      isAggregator:    ctx.isAggregator,
      pageTitle:       ctx.pageTitle,
      fetchSuccess:    !ctx.fetchError,
      fetchError:      ctx.fetchError || null,
      canonicalError:  ctx.canonicalError || null,
      extractedLength: ctx.combinedText.length,
      note:            buildNote(ctx),
    };

    if (config.cacheEnabled) {
      const cacheKey = getCacheKey('url', rawUrl);
      analysisCache.set(cacheKey, final);
    }

    logger.info('URL analysis completed', {
      url: rawUrl,
      canonicalUrl: ctx.canonicalUrl,
      status: final.status,
      riskScore: final.riskScore,
      mlAvailable: final.ml?.available,
      blendMethod: final.ml?.blendMethod,
      duration: Date.now() - startTime,
    });

    res.json(final);
  } catch (err) {
    logger.error('URL analysis error', { url: rawUrl, error: err.message, stack: err.stack });
    res.status(500).json({
      error: 'URL analysis failed',
      message: config.nodeEnv === 'development' ? err.message : 'Could not analyze the URL',
    });
  }
});

// ─────────────────────────────────────────────
// API — HISTORY
// ─────────────────────────────────────────────
app.get('/analyses', generalLimiter, (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const sanitizedLimit = Math.min(Math.max(limit, 1), 100);
    const analyses = getAllAnalyses(sanitizedLimit);
    logger.info('Analyses history retrieved', { count: analyses.length });
    res.json(analyses);
  } catch (err) {
    logger.error('Failed to retrieve analyses', { error: err.message });
    res.status(500).json({ error: 'Failed to retrieve analyses' });
  }
});

// ─────────────────────────────────────────────
// API — ANALYTICS DASHBOARD
// ─────────────────────────────────────────────
const {
  getFullAnalytics,
  runQuery,
  getModelMetrics,
  runABTest,
  runDifferenceInDifferences,
  getCohortAnalysis,
  getSegmentInsights,
  extractFeatures,
  predictScamProbability,
  loadAnalyses,
} = require('./engine/analytics');

app.get('/analytics', generalLimiter, (req, res) => {
  const startTime = Date.now();
  try {
    const analytics = getFullAnalytics();
    logger.info('Analytics dashboard generated', {
      recordCount: analytics.recordCount || 0,
      duration: Date.now() - startTime,
      isDemo: analytics.empty || false,
    });
    res.json(analytics);
  } catch (err) {
    logger.error('Analytics generation failed', { error: err.message, stack: err.stack });
    res.status(500).json({
      error: 'Analytics generation failed',
      message: config.nodeEnv === 'development' ? err.message : 'Internal server error',
    });
  }
});

app.post('/analytics/query', generalLimiter, (req, res) => {
  try {
    const { queryName, params } = req.body;
    if (!queryName || typeof queryName !== 'string') {
      return res.status(400).json({
        error: 'Query name is required',
        availableQueries: [
          'scam_rate_by_source', 'daily_volume', 'score_distribution',
          'high_risk_cases', 'top_red_flags', 'rolling_7day',
        ],
      });
    }
    const result = runQuery(queryName, params || {});
    if (result.error) return res.status(400).json(result);
    logger.info('Query executed', { queryName, params });
    res.json(result);
  } catch (err) {
    logger.error('Query execution failed', { error: err.message });
    res.status(500).json({ error: 'Query execution failed' });
  }
});

app.post('/analytics/predict', generalLimiter, (req, res) => {
  try {
    const { text, jobTitle, source } = req.body;
    if (!text || typeof text !== 'string') {
      return res.status(400).json({ error: 'Text is required for prediction' });
    }
    const analysis = analyzeJob(text, jobTitle || 'Untitled', source || 'API');
    const features = extractFeatures({ result: analysis });
    const mlProbability = predictScamProbability(features);
    res.json({
      ruleBasedScore: analysis.riskScore,
      mlProbability,
      mlPrediction: mlProbability >= 0.45 ? 'scam' : 'legitimate',
      confidence: Math.abs(mlProbability - 0.5) * 2,
      features: {
        redFlagCount: features.redFlagCount,
        positiveCount: features.positiveCount,
        hasFreeEmail: features.hasFreeEmail,
        hasURL: features.hasURL,
        wordCount: features.wordCount,
      },
      recommendation: analysis.status,
    });
  } catch (err) {
    logger.error('Prediction failed', { error: err.message });
    res.status(500).json({ error: 'Prediction failed' });
  }
});

app.get('/analytics/model-metrics', generalLimiter, (req, res) => {
  try {
    const records = loadAnalyses();
    const metrics = getModelMetrics(records);
    res.json(metrics);
  } catch (err) {
    logger.error('Model metrics failed', { error: err.message });
    res.status(500).json({ error: 'Failed to generate model metrics' });
  }
});

app.get('/analytics/ab-test', generalLimiter, (req, res) => {
  try {
    const records = loadAnalyses();
    const test = runABTest(records);
    res.json(test);
  } catch (err) {
    logger.error('A/B test failed', { error: err.message });
    res.status(500).json({ error: 'Failed to run A/B test' });
  }
});

app.get('/analytics/causal', generalLimiter, (req, res) => {
  try {
    const records = loadAnalyses();
    const causal = runDifferenceInDifferences(records);
    res.json(causal);
  } catch (err) {
    logger.error('Causal inference failed', { error: err.message });
    res.status(500).json({ error: 'Failed to run causal analysis' });
  }
});

app.get('/analytics/cohorts', generalLimiter, (req, res) => {
  try {
    const records = loadAnalyses();
    const cohorts = getCohortAnalysis(records);
    res.json(cohorts);
  } catch (err) {
    logger.error('Cohort analysis failed', { error: err.message });
    res.status(500).json({ error: 'Failed to run cohort analysis' });
  }
});

app.get('/analytics/segments', generalLimiter, (req, res) => {
  try {
    const records = loadAnalyses();
    const segments = getSegmentInsights(records);
    res.json(segments);
  } catch (err) {
    logger.error('Segment analysis failed', { error: err.message });
    res.status(500).json({ error: 'Failed to run segment analysis' });
  }
});

// ─────────────────────────────────────────────
// ERROR HANDLING
// ─────────────────────────────────────────────
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    logger.warn('Multer error', { error: err.message, code: err.code });
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        error: 'File too large',
        message: `Maximum file size is ${config.maxFileSize / 1024 / 1024}MB`,
      });
    }
    return res.status(400).json({ error: err.message });
  }

  if (err.message.includes('Only PDF and Word files')) {
    return res.status(400).json({ error: err.message });
  }

  logger.error('Unhandled error', { error: err.message, stack: err.stack, path: req.path });
  res.status(500).json({
    error: 'Internal server error',
    message: config.nodeEnv === 'development' ? err.message : 'Something went wrong',
  });
});

// ─────────────────────────────────────────────
// CATCH-ALL
// ─────────────────────────────────────────────
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─────────────────────────────────────────────
// GRACEFUL SHUTDOWN
// ─────────────────────────────────────────────
let server;

function gracefulShutdown(signal) {
  logger.info(`${signal} received, starting graceful shutdown`);
  server.close(() => {
    logger.info('HTTP server closed');
    analysisCache.close();
    logger.info('Cache closed');
    process.exit(0);
  });
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
}

// ─────────────────────────────────────────────
// START SERVER (CHANGE 2: ML health check)
// ─────────────────────────────────────────────
server = app.listen(config.port, () => {
  logger.info('🚀 VerifyJobs v2.0 started', {
    port: config.port,
    env: config.nodeEnv,
    root: __dirname,
    cacheEnabled: config.cacheEnabled,
  });

  console.log(`🚀 VerifyJobs v2.0 on http://localhost:${config.port}`);
  console.log(`📄 Root: ${__dirname}`);
  console.log(`✅ Health: http://localhost:${config.port}/health`);
  console.log(`📊 Analytics: http://localhost:${config.port}/analytics.html`);
  console.log(`🔒 Environment: ${config.nodeEnv}`);

  // Warm up ML server connection (non-blocking)
  if (process.env.ENABLE_ML !== 'false') {
    checkServerHealth().then(available => {
      if (available) console.log('🤖 ML inference server: connected');
      else console.log('⚠️  ML inference server: offline — rule engine only');
    });
  }
});

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception', { error: err.message, stack: err.stack });
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled rejection', { reason, promise });
});

module.exports = app;