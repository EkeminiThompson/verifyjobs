// server.js — VerifyJobs v2.0 — Production-Ready
// Enhanced with security, rate limiting, caching, logging, and robust error handling

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const https = require('https');
const http = require('http');
const zlib = require('zlib');
const crypto = require('crypto');
const fs     = require('fs');
const dns = require('dns').promises;
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const winston = require('winston');

const analyzeJob = require('./engine/analyzer');
let ensureStorage, getAllAnalyses, getStorageInfo;
try {
  const storageMod = require('./engine/storage');
  ensureStorage = storageMod.ensureStorage || (() => {});
  getAllAnalyses = storageMod.getAllAnalyses || (() => []);
  getStorageInfo = storageMod.getStorageInfo || (() => ({ analysesFile: 'n/a', recordCount: 0, writable: false, exists: false }));
} catch (e) {
  console.warn('[storage] module load failed:', e.message);
  ensureStorage = () => {};
  getAllAnalyses = () => [];
  getStorageInfo = () => ({ analysesFile: 'n/a', recordCount: 0, writable: false, exists: false });
}
const { enrichWithML, checkServerHealth } = require('./engine/ml_scorer');
const { buildDecision } = require('./engine/decision');

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

app.set('trust proxy', 1);

// ─────────────────────────────────────────────
// SECURITY MIDDLEWARE
// ─────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,
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
    const allowed = ['.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only PDF, Word (.pdf, .doc, .docx) and image files (.jpg, .jpeg, .png, .webp) allowed'));
    }
  },
});

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
  // Major job boards
  'linkedin.com',
  'indeed.com',
  'glassdoor.com',
  'monster.com',
  'ziprecruiter.com',
  'simplyhired.com',
  'careerbuilder.com',
  'dice.com',
  'wellfound.com',          // formerly AngelList
  'otta.com',
  'hired.com',
  'builtin.com',
  'weworkremotely.com',
  'remoteok.com',
  'flexjobs.com',
  'handshake.com',
  'verifyjobs.org',

  // Core ATS platforms
  'lever.co',
  'greenhouse.io',          // boards.greenhouse.io, job-boards.greenhouse.io
  'workday.com',
  'myworkdayjobs.com',      // *.wdN.myworkdayjobs.com
  'bamboohr.com',
  'ashbyhq.com',            // jobs.ashbyhq.com
  'icims.com',
  'taleo.net',              // Oracle Taleo
  'smartrecruiters.com',
  'jobvite.com',
  'successfactors.com',
  'successfactors.eu',
  'brassring.com',          // IBM Kenexa / BrassRing
  'ultipro.com',            // UKG
  'phenompeople.com',
  'applytojob.com',         // JazzHR
  'recruitee.com',
  'personio.com',
  'teamtailor.com',
  'workable.com',           // apply.workable.com
  'oraclecloud.com',        // *.fa.*.oraclecloud.com (Oracle HCM)
  'avature.net',
  'eightfold.ai',
  'pinpointhq.com',
  'comeet.co',
  'jazzhr.com',
  'breezy.hr',
  'rippling.com',
  'adp.com',                // myjobs.adp.com
  'jobs2web.com',           // older SuccessFactors RMK

  // Big tech / major company career sites
  'amazon.jobs',
  'careers.google.com',
  'jobs.apple.com',
  'jobs.microsoft.com',
  'meta.com',
  'careers.meta.com',
  'careers.microsoft.com',
  'careers.salesforce.com',
  'careers.adobe.com',
  'careers.ibm.com',
  'careers.oracle.com',
  'jobs.oracle.com',
  'careers.nvidia.com',
  'careers.intel.com',
  'careers.cisco.com',
  'careers.tesla.com',
  'careers.uber.com',
  'careers.airbnb.com',
  'careers.netflix.com',
  'careers.spotify.com',
  'careers.stripe.com',

  // UN / international organizations
  'un.org',
  'careers.un.org',
  'undp.org',
  'unicef.org',
  'who.int',
  'worldbank.org',
  'imf.org',
  'unhcr.org',
  'wfp.org',
  'ilo.org',
  'unesco.org',
  'unfpa.org',
  'unops.org',
  'fao.org',
  'ifad.org',
  'unwomen.org',
  'unodc.org',
  'ohchr.org',
];

const BLOCKED_DOMAINS = [
  'localhost', '127.0.0.1', '0.0.0.0',
];

function isKnownAggregator(hostname) {
  const h = hostname.replace(/^www\./, '');
  return KNOWN_AGGREGATORS.some(d => h === d || h.endsWith('.' + d));
}

function isCanonicalSource(hostname) {
  const h = hostname.replace(/^www\./, '').toLowerCase();
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

// Sync host-only safety for extractCanonical (must not use async isSafeUrl as boolean)
function isSafeUrlSync(rawUrl) {
  try {
    const url = new URL(rawUrl);
    if (!['http:', 'https:'].includes(url.protocol)) return false;
    const host = url.hostname.toLowerCase();
    if (BLOCKED_DOMAINS.some(d => host === d || host.endsWith('.' + d))) return false;
    const privatePatterns = [
      /^localhost$/i, /^127\./, /^0\./, /^10\./,
      /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^169\.254\./,
      /^::1$/, /^fc00:/, /^fe80:/, /^fd[0-9a-f]{2}:/i,
    ];
    if (privatePatterns.some(pat => pat.test(host))) return false;
    return true;
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────
// HTTP FETCHER WITH ABORT CONTROLLER
// ─────────────────────────────────────────────
// Browser-like UA rotation — reduces trivial bot blocks (not a Cloudflare bypass)
const FETCH_USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
];

function browserHeaders(targetUrl, ua, referer) {
  let origin = undefined;
  try {
    const u = new URL(targetUrl);
    origin = u.origin;
  } catch (_) {}
  return {
    'User-Agent': ua,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': referer ? 'same-origin' : 'none',
    'Sec-Fetch-User': '?1',
    'Sec-CH-UA': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
    'Sec-CH-UA-Mobile': '?0',
    'Sec-CH-UA-Platform': '"Windows"',
    'DNT': '1',
    'Connection': 'keep-alive',
    ...(referer ? { 'Referer': referer } : {}),
  };
}

function decodeBody(buf, encoding) {
  const enc = (encoding || '').toLowerCase();
  return new Promise((resolve, reject) => {
    if (!enc || enc === 'identity') return resolve(buf.toString('utf-8'));
    if (enc.includes('gzip')) {
      return zlib.gunzip(buf, (err, out) => err ? reject(err) : resolve(out.toString('utf-8')));
    }
    if (enc.includes('deflate')) {
      return zlib.inflate(buf, (err, out) => err ? reject(err) : resolve(out.toString('utf-8')));
    }
    if (enc.includes('br') && zlib.brotliDecompress) {
      return zlib.brotliDecompress(buf, (err, out) => err ? reject(err) : resolve(out.toString('utf-8')));
    }
    resolve(buf.toString('utf-8'));
  });
}

/**
 * Single attempt — browser-like headers, gzip, redirects.
 */
function fetchUrlOnce(rawUrl, redirectsLeft, signal, ua, referer) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(rawUrl);
    } catch {
      return reject(new Error('Invalid URL'));
    }

    const lib = url.protocol === 'https:' ? https : http;
    const headers = browserHeaders(rawUrl, ua, referer);

    const req = lib.get(rawUrl, {
      timeout: config.fetchTimeout || 20000,
      headers,
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
        return resolve(fetchUrlOnce(next, redirectsLeft - 1, signal, ua, rawUrl));
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

      const contentLength = parseInt(res.headers['content-length'] || '0', 10);
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
        const buf = Buffer.concat(chunks);
        decodeBody(buf, res.headers['content-encoding'])
          .then(html => resolve({ html, finalUrl: rawUrl, statusCode: 200 }))
          .catch(() => reject(new Error('Failed to decode response')));
      });

      res.on('error', reject);
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });

    req.on('error', reject);

    if (signal) {
      if (signal.aborted) {
        req.destroy();
        return reject(new Error('Request aborted'));
      }
      signal.addEventListener('abort', () => {
        req.destroy();
        reject(new Error('Request aborted'));
      }, { once: true });
    }
  });
}

/**
 * Fetch with one retry on 403/429/503 using a different User-Agent.
 * Improves success vs naive bots; cannot defeat hard Cloudflare challenges.
 */
function fetchUrl(rawUrl, redirectsLeft = config.maxRedirects, signal = null) {
  const maxAttempts = 2;
  const startUa = Math.floor(Math.random() * FETCH_USER_AGENTS.length);

  async function attempt(i) {
    const ua = FETCH_USER_AGENTS[(startUa + i) % FETCH_USER_AGENTS.length];
    try {
      return await fetchUrlOnce(rawUrl, redirectsLeft, signal, ua, null);
    } catch (err) {
      const msg = String(err.message || err);
      const retryable = /HTTP 403|HTTP 429|HTTP 503|timed out/i.test(msg);
      if (retryable && i + 1 < maxAttempts) {
        await new Promise(r => setTimeout(r, 400 + Math.random() * 600));
        return attempt(i + 1);
      }
      throw err;
    }
  }

  return attempt(0);
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
    if (u && !isSameHost(u, pageUrl) && isSafeUrlSync(u)) {
      candidates.push({ url: u, strategy: 'canonical-link', priority: 1 });
    }
  }

  const og = html.match(/<meta[^>]+property=["']og:url["'][^>]+content=["']([^"']+)["']/i) ||
    html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:url["']/i);
  if (og) {
    const u = resolveUrl(og[1], pageUrl);
    if (u && !isSameHost(u, pageUrl) && isSafeUrlSync(u)) {
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
              if (u && !isSameHost(u, pageUrl) && isSafeUrlSync(u)) {
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
      if (u && !isSameHost(u, pageUrl) && isSafeUrlSync(u)) {
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
      if (u && !isSameHost(u, pageUrl) && isSafeUrlSync(u)) {
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
        if (u && !isSameHost(u, pageUrl) && isSafeUrlSync(u)) {
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
  // Metadata only — never inject synthetic scam phrases.
  // Scoring must not run on this alone as if it were a job ad.
  const urlObj = new URL(rawUrl);
  const hostname = urlObj.hostname.replace(/^www\./, '');
  return [
    `Job posting URL: ${rawUrl}`,
    `Domain: ${hostname}`,
    `Path: ${urlObj.pathname}`,
  ].join('\n');
}

function buildInsufficientFetchResult(ctx, rawUrl) {
  const err = ctx.fetchError || 'page content unavailable';
  const summary =
    'We could not download the page content (often blocked bots, login walls, or HTTP 403/401). ' +
    'Without the posting text we will not invent a scam score from the URL alone.';
  return {
    status: 'insufficient_data',
    statusLabel: 'Could not read page',
    riskScore: 0,
    legitimacyScore: null,
    redFlags: [],
    positiveIndicators: [],
    explanation: summary,
    recommendation:
      'Paste the job / fellowship text from the page, or try again later. A blocked fetch is not evidence of fraud.',
    actionItems: [
      'Open the link in your browser and copy the full description',
      'Use the Paste Text tab for a reliable check',
      'If the site blocks automated access, URL mode cannot score it fairly',
    ],
    note: `Page fetch failed (${err}). No risk score from URL structure alone.`,
    metadata: {
      notAJob: false,
      insufficientData: true,
      fetchError: err,
      submittedUrl: rawUrl,
      analysisTimestamp: new Date().toISOString(),
    },
    ml: { available: false, reason: 'Skipped — no page text to score' },
    decision: {
      verdict: 'insufficient_data',
      verdictLabel: 'Could not read page',
      verdictTone: 'neutral',
      summary: summary,
      topReasons: [
        `Fetch failed: ${err}`,
        'Scoring URL path alone would produce false alarms or false confidence',
      ],
      nextSteps: [
        'Paste the visible job text into VerifyJobs',
        'Or re-try URL analysis later if the site allows crawlers',
        'Do not treat a failed fetch as proof the posting is a scam',
      ],
      scamPattern: null,
      confidenceNote: 'No content-based assessment was possible.',
      riskScore: 0,
    },
    submittedUrl: rawUrl,
    canonicalUrl: null,
    fetchedPages: [],
    fetchSuccess: false,
    fetchError: err,
    extractedLength: 0,
  };
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
    parts.push(`Page fetch failed (${ctx.fetchError}). No content-based score was produced.`);
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
// ANALYTICS MODULE
// ─────────────────────────────────────────────
const {
  getFullAnalytics,
  runQuery,
  getModelMetrics,
  getTrainedModelMetrics,
  runABTest,
  runDifferenceInDifferences,
  getCohortAnalysis,
  getSegmentInsights,
  extractFeatures,
  loadAnalyses,
} = require('./engine/analytics');

// ─────────────────────────────────────────────
// GROWTH ENGINE
// Shareable results, company pages, dynamic sitemap, share API
// These must come before static file serving
// ─────────────────────────────────────────────

// ── Persistent flat-JSON result store ─────────────────────────────────────────
// Survives server restarts. Falls back to {} if the file is missing or corrupt.
const STORE_PATH = path.join(__dirname, 'data', 'shares.json');
const STORE_TTL  = 7 * 24 * 60 * 60 * 1000; // 7 days in ms

function loadStore() {
  try {
    const raw = fs.readFileSync(STORE_PATH, 'utf8');
    return JSON.parse(raw);
  } catch (_) {
    return {};
  }
}

function saveStore(store) {
  try {
    fs.mkdirSync(path.dirname(STORE_PATH), { recursive: true });
    fs.writeFileSync(STORE_PATH, JSON.stringify(store), 'utf8');
  } catch (err) {
    logger.error('shares.json write failed', { error: err.message });
  }
}

function storeGet(id) {
  const store = loadStore();
  const entry = store[id];
  if (!entry) return undefined;
  if (Date.now() - new Date(entry.createdAt).getTime() > STORE_TTL) {
    // expired — clean up lazily
    delete store[id];
    saveStore(store);
    return undefined;
  }
  return entry;
}

function storeSet(id, payload) {
  const store = loadStore();
  store[id] = payload;
  saveStore(store);
}

const resultStore = { get: storeGet, set: storeSet };

// ── Slugify helper ─────────────────────────────────────────────────────────────
function slugify(str) {
  return (str || '').toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
}

// ── OG HTML builder — used by /r/:id and /scam/:company ──────────────────────
function buildOgPage({ title, description, url, verdict, riskScore, canonical }) {
  const verdictColor = riskScore >= 70 ? '#dc2626' : riskScore >= 45 ? '#d97706' : '#16a34a';
  const safeTitle = title.replace(/"/g, '&quot;').replace(/</g, '&lt;');
  const safeDesc  = description.replace(/"/g, '&quot;').replace(/</g, '&lt;');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${safeTitle} | VerifyJobs</title>
<meta name="description" content="${safeDesc}">
<link rel="canonical" href="${canonical || url}">
<meta property="og:type" content="article">
<meta property="og:url" content="${url}">
<meta property="og:title" content="${safeTitle}">
<meta property="og:description" content="${safeDesc}">
<meta property="og:image" content="https://verifyjobs.org/og-image.png">
<meta property="og:site_name" content="VerifyJobs.org">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:site" content="@verifyjobs">
<meta name="twitter:title" content="${safeTitle}">
<meta name="twitter:description" content="${safeDesc}">
<meta name="twitter:image" content="https://verifyjobs.org/og-image.png">
<style>
  *{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:system-ui,-apple-system,sans-serif;min-height:100vh;background:#f3f4f6;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px;}
  .card{background:#fff;border-radius:16px;box-shadow:0 4px 32px rgba(0,0,0,.10);padding:40px 36px;max-width:520px;width:100%;text-align:center;}
  .logo{font-size:13px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#6b7280;margin-bottom:28px;}
  .verdict{font-size:2.2rem;font-weight:800;color:${verdictColor};margin-bottom:6px;line-height:1.15;}
  .score{font-size:15px;color:#6b7280;margin-bottom:20px;}
  .score b{color:#111;font-size:17px;}
  .divider{height:1px;background:#e5e7eb;margin:20px 0;}
  .desc{font-size:14px;color:#374151;line-height:1.7;margin-bottom:28px;text-align:left;}
  .actions{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;}
  .btn-primary{display:inline-block;background:#2563eb;color:#fff;text-decoration:none;padding:11px 26px;border-radius:8px;font-weight:600;font-size:14px;transition:opacity .15s;}
  .btn-primary:hover{opacity:.88;}
  .btn-secondary{display:inline-block;background:#f3f4f6;color:#374151;text-decoration:none;padding:11px 26px;border-radius:8px;font-weight:600;font-size:14px;border:1px solid #e5e7eb;}
  .footer-note{margin-top:24px;font-size:12px;color:#9ca3af;}
  @media(max-width:480px){.card{padding:28px 20px;}.verdict{font-size:1.7rem;}}
</style>
</head>
<body>
<div class="card">
  <div class="logo">VerifyJobs · Job Scam Checker</div>
  <div class="verdict">${verdict}</div>
  ${riskScore != null ? `<div class="score">Risk score: <b>${riskScore}/100</b></div>` : ''}
  <div class="divider"></div>
  <p class="desc">${safeDesc}</p>
  <div class="actions">
    <a class="btn-primary" href="/">Check another job →</a>
    <a class="btn-secondary" href="https://verifyjobs.org">verifyjobs.org</a>
  </div>
  <p class="footer-note">Advisory only · Never pay fees to get a job · verifyjobs.org is free</p>
</div>
</body>
</html>`;
}

// ── POST /share — save a result and return a shareable ID ────────────────────
// Called by the frontend after analysis; returns { id, url }
app.post('/share', generalLimiter, (req, res) => {
  try {
    const { result, jobTitle, source } = req.body;
    if (!result || typeof result !== 'object') {
      return res.status(400).json({ error: 'result object required' });
    }
    const id = crypto.randomBytes(8).toString('hex'); // 16-char URL-safe ID
    const payload = {
      id,
      jobTitle: (jobTitle || 'Job Posting').slice(0, 120),
      source: (source || 'Manual').slice(0, 60),
      riskScore: result.riskScore,
      legitimacyScore: result.legitimacyScore,
      status: result.status,
      verdict: result.decision?.verdictLabel || result.statusLabel || result.status,
      redFlagCount: (result.redFlags || []).length,
      explanation: (result.explanation || '').slice(0, 300),
      createdAt: new Date().toISOString(),
    };
    resultStore.set(id, payload);
    logger.info('Result shared', { id, status: payload.status, riskScore: payload.riskScore });
    // Derive host from request so local dev shares resolve on localhost, not verifyjobs.org
    const host  = req.headers['x-forwarded-host'] || req.headers['host'] || 'verifyjobs.org';
    const proto = req.headers['x-forwarded-proto'] || (req.secure ? 'https' : 'http');
    res.json({ id, url: `${proto}://${host}/r/${id}` });
  } catch (err) {
    logger.error('Share failed', { error: err.message });
    res.status(500).json({ error: 'Share failed' });
  }
});

// ── GET /r/:id — shareable result permalink with full OG tags ─────────────────
// This is the viral hook: WhatsApp, Twitter, LinkedIn unfurl it with a verdict card
app.get('/r/:id([0-9a-f]{16})', (req, res) => {
  const payload = resultStore.get(req.params.id);
  if (!payload) {
    return res.redirect('/');
  }
  const riskScore = payload.riskScore;
  const verdict   = payload.verdict || payload.status;
  const title     = `${verdict}: "${payload.jobTitle}" — VerifyJobs Result`;
  const desc      = payload.explanation
    ? `Risk score ${riskScore}/100. ${payload.explanation}`
    : `Risk score ${riskScore}/100 · ${payload.redFlagCount} red flag(s) detected. Checked on VerifyJobs.`;
  const pageUrl   = `https://verifyjobs.org/r/${payload.id}`;
  res.type('text/html').send(buildOgPage({ title, description: desc, url: pageUrl, verdict, riskScore, canonical: 'https://verifyjobs.org/' }));
});

// ── GET /r/:id/json — machine-readable result (for embeds, browser extensions) ─
app.get('/r/:id([0-9a-f]{16})/json', generalLimiter, (req, res) => {
  const payload = resultStore.get(req.params.id);
  if (!payload) return res.status(404).json({ error: 'Result not found or expired' });
  res.json(payload);
});

// ── Company scam pages: /scam/[company-name] ─────────────────────────────────
// e.g. /scam/amazon, /scam/deloitte-nigeria
// These are data-rich pages Google indexes; each answers "[company] job scam" queries
const KNOWN_COMPANY_VERDICTS = {
  // Entries injected by your analytics pipeline over time.
  // Seed a few major targets so the route works immediately.
};

app.get('/scam/:company([a-z0-9-]{2,60})', (req, res) => {
  const companySlug = req.params.company;
  const companyName = companySlug.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  const pageUrl     = `https://verifyjobs.org/scam/${companySlug}`;

  // Try to load a static HTML page first (hand-crafted wins over template)
  const staticPath = path.join(__dirname, 'public', 'scam', `${companySlug}.html`);
  const fs = require('fs');
  if (fs.existsSync(staticPath)) return res.sendFile(staticPath);

  // Fallback: dynamic template page with full OG + schema
  const title = `Is "${companyName}" Job Real or Fake? — Scam Check | VerifyJobs`;
  const desc  = `Wondering if a ${companyName} job offer is legitimate? VerifyJobs checks for fake ${companyName} recruiters, impersonation scams, and advance-fee fraud. Free, instant, no sign-up.`;

  const schemaMarkup = JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    'mainEntity': [
      {
        '@type': 'Question',
        'name': `Is this ${companyName} job offer real?`,
        'acceptedAnswer': {
          '@type': 'Answer',
          'text': `Paste the ${companyName} job description into VerifyJobs to get an instant scam risk score. Common red flags include upfront payment requests, free email domain recruiters, and WhatsApp-only contact.`,
        },
      },
      {
        '@type': 'Question',
        'name': `How do I verify a ${companyName} job offer?`,
        'acceptedAnswer': {
          '@type': 'Answer',
          'text': `Visit ${companyName}'s official careers page and verify the role exists. Paste the job description into VerifyJobs for a fraud indicator check. Legitimate ${companyName} recruiters use company email addresses and never ask for money.`,
        },
      },
    ],
  });

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<meta name="description" content="${desc}">
<link rel="canonical" href="${pageUrl}">
<meta property="og:type" content="article">
<meta property="og:url" content="${pageUrl}">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${desc}">
<meta property="og:image" content="https://verifyjobs.org/og-image.png">
<meta property="og:site_name" content="VerifyJobs.org">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${title}">
<meta name="twitter:description" content="${desc}">
<script type="application/ld+json">${schemaMarkup}</script>
<meta http-equiv="refresh" content="0;url=/?company=${encodeURIComponent(companyName)}">
</head>
<body>
<p>Checking ${companyName} job offers for scam indicators — <a href="/?company=${encodeURIComponent(companyName)}">open VerifyJobs</a>.</p>
</body>
</html>`;

  res.type('text/html').send(html);
  logger.info('Company scam page served', { company: companySlug });
});

// ── GET /sitemap-dynamic.xml — company + result pages for Google ──────────────
// Merge with your static sitemap.xml via <sitemapindex>
app.get('/sitemap-dynamic.xml', (req, res) => {
  const baseUrl = 'https://verifyjobs.org';
  const now     = new Date().toISOString().slice(0, 10);

  // Top scam-search companies — extend this list from your analytics data
  const topCompanies = [
    'amazon', 'microsoft', 'google', 'deloitte', 'kpmg', 'pwc', 'unilever',
    'shell', 'chevron', 'exxonmobil', 'dangote', 'gtbank', 'access-bank',
    'zenith-bank', 'unicef', 'undp', 'world-bank', 'african-development-bank',
    'jim-leech-mastercard-foundation', 'mastercard-foundation', 'tony-elumelu-foundation',
    'coca-cola', 'nestle', 'procter-gamble', 'airtel', 'mtn', 'glo',
  ];

  const companyUrls = topCompanies.map(slug =>
    `  <url><loc>${baseUrl}/scam/${slug}</loc><lastmod>${now}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>`
  ).join('\n');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${baseUrl}/</loc><lastmod>${now}</lastmod><changefreq>daily</changefreq><priority>1.0</priority></url>
  <url><loc>${baseUrl}/how-it-works</loc><lastmod>${now}</lastmod><changefreq>monthly</changefreq><priority>0.7</priority></url>
  <url><loc>${baseUrl}/report-a-scam</loc><lastmod>${now}</lastmod><changefreq>monthly</changefreq><priority>0.6</priority></url>
${companyUrls}
</urlset>`;

  res.type('application/xml').send(xml);
});

// ── GET /api/trending-scams — powers "trending" widget on homepage ─────────────
// Feed it from your analytics data; stub returns structure for now
app.get('/api/trending-scams', generalLimiter, (req, res) => {
  try {
    // Pull top red flags / company names from analytics if available
    let trending = [];
    try {
      const records = require('./engine/analytics').loadAnalyses();
      const companyFreq = {};
      for (const r of records) {
        if (r.jobTitle) {
          const key = r.jobTitle.toLowerCase().replace(/[^a-z0-9 ]/g, '').trim().slice(0, 40);
          companyFreq[key] = (companyFreq[key] || 0) + 1;
        }
      }
      trending = Object.entries(companyFreq)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([name, count]) => ({ name, count, slug: slugify(name) }));
    } catch (_) {}

    if (!trending.length) {
      trending = [
        { name: 'Amazon Remote Jobs', count: null, slug: 'amazon' },
        { name: 'UNICEF Fellowship', count: null, slug: 'unicef' },
        { name: 'Shell Nigeria', count: null, slug: 'shell' },
        { name: 'Mastercard Foundation', count: null, slug: 'mastercard-foundation' },
        { name: 'Google Work From Home', count: null, slug: 'google' },
      ];
    }

    res.json({ trending, generatedAt: new Date().toISOString() });
  } catch (err) {
    logger.error('Trending scams failed', { error: err.message });
    res.status(500).json({ error: 'Failed' });
  }
});

// ── GET /api/stats — public social-proof numbers (for homepage badge) ──────────
app.get('/api/stats', generalLimiter, (req, res) => {
  try {
    let recordCount = 0;
    let scamRate    = null;
    try {
      const s = getStorageInfo();
      recordCount = s.recordCount || 0;
      const records = require('./engine/analytics').loadAnalyses();
      const flagged = records.filter(r => r.riskScore >= 45).length;
      scamRate = records.length ? Math.round((flagged / records.length) * 100) : null;
    } catch (_) {}

    res.json({
      checksPerformed: recordCount,
      scamRatePercent: scamRate,
      countriesServed: 30,
      fraudIndicators: 50,
      generatedAt: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ── POST /api/scrape-jobs — scrape job boards and classify fake vs real ────────
// Results cached to data/scraped-jobs.json; only re-runs when manually triggered
const SCRAPED_JOBS_PATH = path.join(__dirname, 'data', 'scraped-jobs.json');

// Red-flag patterns applied to scraped job metadata
const SCRAPE_RED_FLAGS = [
  { id: 'free_email',    label: 'Free email recruiter',      pattern: /\b(gmail|yahoo|hotmail|outlook\.com|yandex)\b/i },
  { id: 'upfront_fee',  label: 'Upfront payment required',   pattern: /\b(pay|payment|fee|deposit|registration fee|training fee|processing fee)\b/i },
  { id: 'whatsapp',     label: 'WhatsApp-only contact',       pattern: /\bwhatsapp\b/i },
  { id: 'no_experience',label: 'No experience required (suspicious salary)', pattern: /no experience.{0,40}(salary|\$|£|₦|monthly|weekly)/i },
  { id: 'work_from_home_urgent', label: 'Urgent WFH with vague role', pattern: /\b(urgent|immediately|urgently).{0,30}(work from home|remote|wfh)\b/i },
  { id: 'too_good',     label: 'Unrealistically high pay',   pattern: /\b(\$[5-9]\d{3,}|\$[1-9]\d{4,}|₦[5-9]\d{5,}|earn up to|make up to)\b/i },
  { id: 'vague_company',label: 'Vague or missing company',   pattern: /^(n\/a|not specified|confidential|undisclosed|a reputable company)$/i },
  { id: 'money_transfer',label: 'Money transfer / forex',    pattern: /\b(money transfer|forex|crypto|bitcoin|wire transfer|western union)\b/i },
];

function scoreScrapedJob(job) {
  const haystack = [job.title, job.company, job.description, job.location, job.tags].filter(Boolean).join(' ');
  const flags = SCRAPE_RED_FLAGS.filter(f => f.pattern.test(haystack)).map(f => f.label);
  return flags;
}

async function fetchRemotiveJobs() {
  return new Promise((resolve) => {
    const req = https.get('https://remotive.com/api/remote-jobs?limit=60', { headers: { 'User-Agent': 'VerifyJobs/2.0' } }, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try {
          const data = JSON.parse(body);
          resolve((data.jobs || []).map(j => ({
            title:       j.title,
            company:     j.company_name,
            location:    j.candidate_required_location || 'Remote',
            description: (j.description || '').replace(/<[^>]+>/g, ' ').slice(0, 1000),
            tags:        (j.tags || []).join(' '),
            url:         j.url,
            source:      'Remotive',
          })));
        } catch (_) { resolve([]); }
      });
    });
    req.on('error', () => resolve([]));
    req.setTimeout(8000, () => { req.destroy(); resolve([]); });
  });
}

async function fetchAdzunaJobs() {
  // Adzuna public search — no key needed for basic queries
  return new Promise((resolve) => {
    const url = 'https://api.adzuna.com/v1/api/jobs/ng/search/1?app_id=00000000&app_key=00000000&results_per_page=40&what=jobs&content-type=application/json';
    // Adzuna requires a key — fallback to a curated set of high-risk job patterns instead
    resolve([]);
  });
}

// Supplementary realistic-looking fake job stubs (for padding when scraped data is thin)
const SYNTHETIC_SUSPICIOUS = [
  { title: 'Remote Data Entry Clerk – $5,000/month',      company: 'Global Outsource Ltd', location: 'Remote', description: 'No experience needed. Pay upfront $50 training fee. Contact us on WhatsApp only.', url: null, source: 'Pattern Library' },
  { title: 'Online Customer Service Rep – Earn $800/week', company: 'N/A',                  location: 'Work From Home', description: 'Urgently hiring. Must have Gmail. Send CV to hr.recruit2024@gmail.com', url: null, source: 'Pattern Library' },
  { title: 'Forex Trading Assistant – Part Time',          company: 'Confidential',          location: 'Remote', description: 'Help clients with crypto and wire transfers. Earn $3,000 weekly. No experience needed.', url: null, source: 'Pattern Library' },
];

app.post('/api/scrape-jobs', generalLimiter, async (req, res) => {
  try {
    logger.info('Scrape-jobs triggered manually');

    // Fetch from job boards
    const remotive = await fetchRemotiveJobs();
    const extra    = await fetchAdzunaJobs();

    // Cap pool at 25 jobs — running the full engine on every job is expensive
    const pool = [...remotive, ...extra].slice(0, 25);

    // ── Run full engine in batches of 5 ──────────────────────────────────────
    // analyzeJob(text, jobTitle, source) → enrichWithML(text, ruleResult)
    // mirrors the exact path taken by POST /analyze
    const suspicious = [];
    const legitimate = [];

    async function analyseJobBatch(batch) {
      return Promise.all(batch.map(async (job) => {
        const text = [job.title, job.company, job.description, job.location, job.tags]
          .filter(Boolean).join('\n');
        try {
          const ruleResult = analyzeJob(text, job.title || 'Untitled', job.source || 'Scraped');
          const result     = await enrichWithML(text, ruleResult);
          return { job, result };
        } catch (err) {
          logger.warn('Engine failed for scraped job', { title: job.title, error: err.message });
          // Fallback: lightweight regex so one bad job doesn't abort the batch
          const flags = scoreScrapedJob(job);
          return {
            job,
            result: {
              riskScore:    flags.length >= 2 ? 55 : flags.length === 1 ? 35 : 10,
              statusLabel:  flags.length >= 2 ? 'Suspicious' : flags.length === 1 ? 'Review' : 'Likely Legitimate',
              redFlags:     flags,
              status:       flags.length >= 2 ? 'suspicious' : flags.length === 1 ? 'review' : 'legitimate',
            },
          };
        }
      }));
    }

    const BATCH_SIZE = 5;
    for (let i = 0; i < pool.length; i += BATCH_SIZE) {
      const batch   = pool.slice(i, i + BATCH_SIZE);
      const results = await analyseJobBatch(batch);

      for (const { job, result } of results) {
        const entry = {
          ...job,
          riskScore:   result.riskScore,
          statusLabel: result.statusLabel || result.status,
          redFlags:    (result.redFlags || []).map(f => (typeof f === 'object' ? f.label || f.description : f)),
        };
        if (result.riskScore >= 45) {
          suspicious.push(entry);
        } else {
          legitimate.push(entry);
        }
      }

      // Brief pause between batches — avoids hammering ML scorer
      if (i + BATCH_SIZE < pool.length) {
        await new Promise(r => setTimeout(r, 300));
      }
    }

    const result = {
      suspicious: suspicious.slice(0, 10),
      legitimate: legitimate.slice(0, 10),
      scrapedAt:  new Date().toISOString(),
      total:      pool.length,
    };

    // Persist to flat JSON
    try {
      fs.mkdirSync(path.dirname(SCRAPED_JOBS_PATH), { recursive: true });
      fs.writeFileSync(SCRAPED_JOBS_PATH, JSON.stringify(result), 'utf8');
    } catch (writeErr) {
      logger.error('scraped-jobs.json write failed', { error: writeErr.message });
    }

    res.json(result);
  } catch (err) {
    logger.error('scrape-jobs failed', { error: err.message });
    res.status(500).json({ error: 'Scrape failed' });
  }
});

// ── GET /api/scrape-jobs — return last cached scrape result ────────────────────
app.get('/api/scrape-jobs', generalLimiter, (req, res) => {
  try {
    const raw = fs.readFileSync(SCRAPED_JOBS_PATH, 'utf8');
    res.json(JSON.parse(raw));
  } catch (_) {
    res.json({ suspicious: [], legitimate: [], scrapedAt: null, total: 0 });
  }
});

// ─────────────────────────────────────────────
// SEO-CRITICAL STATIC FILES
// Must be first — before all other routes
// ─────────────────────────────────────────────
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.sendFile(path.join(__dirname, 'robots.txt'), (err) => {
    if (err) { logger.error('robots.txt not found'); res.status(404).send('Not found'); }
  });
});

app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml');
  res.sendFile(path.join(__dirname, 'sitemap.xml'), (err) => {
    if (err) { logger.error('sitemap.xml not found'); res.status(404).send('Not found'); }
  });
});

app.get('/structured-data.json', (req, res) => {
  res.type('application/json');
  res.sendFile(path.join(__dirname, 'structured-data.json'), (err) => {
    if (err) { logger.error('structured-data.json not found'); res.status(404).send('Not found'); }
  });
});

app.get('/llms.txt', (req, res) => {
  res.type('text/plain');
  res.sendFile(path.join(__dirname, 'llms.txt'), (err) => {
    if (err) { logger.error('llms.txt not found'); res.status(404).send('Not found'); }
  });
});

// ─────────────────────────────────────────────
// AI / LLM FILES
// ─────────────────────────────────────────────

// AI Usage permissions and policy (critical for crawler permissions)
app.get('/ai.txt', (req, res) => {
  res.type('text/plain');
  res.sendFile(path.join(__dirname, 'ai.txt'), (err) => {
    if (err) { 
      logger.error('ai.txt not found'); 
      res.status(404).send('Not found'); 
    }
  });
});

// Full LLM knowledge base (comprehensive content)
app.get('/llms-full.txt', (req, res) => {
  res.type('text/plain');
  res.sendFile(path.join(__dirname, 'llms-full.txt'), (err) => {
    if (err) { 
      logger.error('llms-full.txt not found'); 
      res.status(404).send('Not found'); 
    }
  });
});


app.get('/ai-sitemap.xml', (req, res) => {
  res.type('application/xml');
  res.sendFile(path.join(__dirname, 'ai-sitemap.xml'), (err) => {
    if (err) { logger.error('ai-sitemap.xml not found'); res.status(404).send('Not found'); }
  });
});

app.get('/google6c2364060583a1e1.html', (req, res) => {
  res.type('text/html');
  res.sendFile(path.join(__dirname, 'google6c2364060583a1e1.html'), (err) => {
    if (err) { logger.error('Google verification file not found'); res.status(404).send('Not found'); }
  });
});

// ─────────────────────────────────────────────
// API ROUTES
// ALL API routes must be registered BEFORE express.static
// to prevent analytics.html from shadowing GET /analytics
// ─────────────────────────────────────────────

// Health check
app.get('/health', (req, res) => {
  // Keep this fast — Render uses it for deploy readiness
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '2.0',
  });
});

// Analyses history
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

// Analytics dashboard — must be before express.static or analytics.html wins
app.get('/analytics', generalLimiter, async (req, res) => {
  const startTime = Date.now();
  try {
    const analytics = await getFullAnalytics();
    logger.info('Analytics dashboard generated', {
      recordCount: analytics.recordCount || 0,
      duration: Date.now() - startTime,
      isDemo: analytics.empty || false,
      modelAvailable: !!(analytics.model && analytics.model.available),
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

app.post('/analytics/predict', generalLimiter, async (req, res) => {
  try {
    const { text, jobTitle, source } = req.body || {};
    if (!text || typeof text !== 'string') {
      return res.status(400).json({ error: 'text is required' });
    }
    // Use the same product path as /analyze (rules + optional real ML blend)
    const analysis = analyzeJob(text, jobTitle || 'Untitled', source || 'API');
    let result = analysis;
    try {
      const { enrichWithML } = require('./engine/ml_scorer');
      result = await enrichWithML(text, analysis);
    } catch (e) {
      logger.warn('ML enrich skipped on /analytics/predict', { error: e.message });
    }
    res.json({
      ruleBasedScore: analysis.riskScore,
      finalScore: result.riskScore,
      ml: result.ml || null,
      status: result.status,
      decision: result.decision || null,
      recommendation: result.recommendation,
    });
  } catch (err) {
    logger.error('Prediction failed', { error: err.message });
    res.status(500).json({ error: 'Prediction failed' });
  }
});


app.get('/analytics/model-metrics', generalLimiter, async (req, res) => {
  try {
    const metrics = await getTrainedModelMetrics();
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

// Analyze — text
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

// Analyze — file
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
    } else if (['.jpg', '.jpeg', '.png', '.webp'].includes(ext)) {
      if (!tesseract) {
        return res.status(400).json({
          error: 'Image OCR not available on this server',
          message: 'Please install tesseract.js: npm install tesseract.js',
        });
      }
      try {
        const { data } = await tesseract.recognize(file.buffer, 'eng', {
          logger: () => {},
        });
        text = data.text || '';
        logger.info('OCR completed', {
          filename: file.originalname,
          confidence: data.confidence,
          extractedLength: text.length,
        });
      } catch (ocrErr) {
        logger.error('OCR failed', { error: ocrErr.message, filename: file.originalname });
        throw new Error(`Image OCR failed: ${ocrErr.message}`);
      }
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

// Analyze — URL
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

    const ctx = await scrapeAndAnalyze(rawUrl);

    const wordCount = (ctx.combinedText || '').trim().split(/\s+/).filter(Boolean).length;
    const hostname = (() => {
      try { return new URL(ctx.submittedUrl || rawUrl).hostname.toLowerCase(); }
      catch { return ''; }
    })();
    const isTrustedHost = isCanonicalSource(hostname);
    const isOwnSiteEarly = hostname === 'verifyjobs.org' || hostname.endsWith('.verifyjobs.org');

    // Trusted ATS (Oracle HCM, Workday, Greenhouse, …): JS shells / soft blocks
    // are normal — do NOT return insufficient_data or invent a scam score.
    if ((ctx.fetchError || wordCount < 40) && isTrustedHost && !isOwnSiteEarly) {
      const portalResult = {
        status: 'likely_legitimate',
        statusLabel: 'Likely Legitimate (Trusted Career Portal)',
        riskScore: 0,
        legitimacyScore: 85,
        redFlags: [],
        positiveIndicators: [
          `Official career portal domain (${hostname})`,
          'Known ATS / HCM host (content often loads in the browser only)',
        ],
        explanation:
          'This URL is on a known official career system (e.g. Oracle Cloud HCM, Workday, Greenhouse). ' +
          'Little or no text could be extracted because these sites are JavaScript apps or restrict bots. ' +
          'That is expected and is not a scam signal. We still cannot verify the specific vacancy wording without the full description.',
        recommendation:
          'Treat the host as a real career portal. Open the link yourself, confirm the vacancy, and never pay any fee to apply. ' +
          'For a full automated check, paste the job text from the page.',
        actionItems: [
          'Open the posting in your browser and confirm employer, title, and closing date',
          'Apply only through this official portal — ignore WhatsApp / payment side channels',
          'Optional: paste the full description into VerifyJobs for a content-based score',
        ],
        note: ctx.fetchError
          ? `Trusted host ${hostname}; fetch issue (${ctx.fetchError}). Portal trust applied — not scored as fraud.`
          : `Trusted host ${hostname}; only ${wordCount} words extracted (typical for JS ATS). Portal trust applied.`,
        metadata: {
          trustedCareerPortal: true,
          hostname,
          wordCount,
          fetchError: ctx.fetchError || null,
          analysisTimestamp: new Date().toISOString(),
        },
        ml: { available: false, reason: 'Skipped — insufficient extractable text on trusted ATS' },
        decision: {
          verdict: 'looks_ok',
          verdictLabel: 'Trusted career portal',
          verdictTone: 'safe',
          summary:
            'Hosted on a known official careers system. Limited page text is normal for Oracle/Workday-style sites — not evidence of a scam.',
          topReasons: [
            `Domain matches known ATS/HCM: ${hostname}`,
            wordCount < 40
              ? 'Job details are usually filled in by JavaScript after load'
              : 'Partial extract only',
          ],
          nextSteps: [
            'Review the vacancy in your browser on this same official URL',
            'Never pay to apply or move the process solely to WhatsApp/Telegram',
            'Paste the description here if you want a full text-based risk score',
          ],
          scamPattern: null,
          confidenceNote:
            'Host trust only — we did not read full JD text. Unusual for a scam to sit on real Oracle/UNDP HCM, but always read the posting yourself.',
          riskScore: 0,
        },
        submittedUrl: rawUrl,
        canonicalUrl: ctx.canonicalUrl || null,
        fetchedPages: ctx.fetchedPages || [],
        fetchSuccess: !ctx.fetchError,
        fetchError: ctx.fetchError || null,
        extractedLength: (ctx.combinedText || '').length,
        pageTitle: ctx.pageTitle || hostname,
      };
      logger.info('Trusted ATS with thin/failed extract — portal trust result', {
        url: rawUrl,
        hostname,
        wordCount,
        fetchError: ctx.fetchError,
      });
      return res.json(portalResult);
    }

    // Non-trusted hosts: never invent a scam score from a bare URL / failed fetch
    if (ctx.fetchError || wordCount < 40) {
      const insufficient = buildInsufficientFetchResult(ctx, rawUrl);
      logger.warn('URL analysis aborted — insufficient page text', {
        url: rawUrl,
        fetchError: ctx.fetchError,
        wordCount,
      });
      return res.json(insufficient);
    }

    const ruleResult = analyzeJob(ctx.combinedText, ctx.pageTitle, 'URL');
    const result     = await enrichWithML(ctx.combinedText, ruleResult);
    
    // ========== TRUSTED DOMAIN SAFEGUARD ==========
    // hostname / isTrustedHost / isOwnSiteEarly already computed above
    const isTrusted = isTrustedHost;
    const isOwnSite = isOwnSiteEarly;

    if (isTrusted || isOwnSite) {
      result.positiveIndicators = result.positiveIndicators || [];
      if (!result.positiveIndicators.some(p => /official career portal|verifyjobs/i.test(String(p)))) {
        result.positiveIndicators.unshift(
          isOwnSite
            ? 'Official VerifyJobs.org page (not a job posting)'
            : `Official career portal domain (${hostname})`
        );
      }

      // Own marketing/docs site should never be scored as a job scam
      if (isOwnSite) {
        result.riskScore = 0;
        result.legitimacyScore = 0;
        result.redFlags = [];
        result.status = 'not_a_job';
        result.statusLabel = 'Not a job posting — VerifyJobs site';
        result.explanation = 'This URL is the VerifyJobs website itself (educational / marketing content), not a job advertisement. Scam-related phrases on this page are examples used to educate users.';
        result.recommendation = 'This is not a job to apply for. Use the tool to check actual job postings.';
        result.metadata = result.metadata || {};
        result.metadata.notAJob = true;
        result.jobLikelihood = { isJob: false, confidence: 'high', score: 0, reasons: ['Official VerifyJobs site'], signals: { positive: [], negative: ['Educational / tool content'] } };
      } else if ((ctx.combinedText || '').trim().split(/\s+/).length < 40) {
        // Short text on trusted ATS = JS-rendered portal
        result.redFlags = (result.redFlags || []).filter(f =>
          !/short|placeholder|very short/i.test(typeof f === 'string' ? f : f.signal || f.label || '')
        );
        result.riskScore = Math.min(result.riskScore, 25);
        result.legitimacyScore = Math.max(result.legitimacyScore || 0, 75);
        result.status = 'likely_legitimate';
        result.statusLabel = '✅ Likely Legitimate (Trusted Career Portal)';
        result.explanation = 'This job is hosted on a known official career system (Oracle Cloud / Workday / Greenhouse / etc.). Short extracted text is normal for these JavaScript-heavy portals and is not treated as a scam signal.';
        result.recommendation = 'This appears to be a genuine posting on an official career portal. Still verify the specific vacancy and never pay any fees.';
      } else {
        // Full text on trusted domain — boost legitimacy and RECOMPUTE status
        result.riskScore = Math.max(0, result.riskScore - 25);
        result.legitimacyScore = Math.min(100, (result.legitimacyScore || 0) + 25);

        // Re-map status from adjusted score — thresholds match engine/scorer.js
        const s = result.riskScore;
        if (s >= 80) {
          result.status = 'definite_scam';
          result.statusLabel = '🚨 DEFINITE SCAM';
        } else if (s >= 65) {
          result.status = 'very_high_risk';
          result.statusLabel = '🔴 VERY HIGH RISK';
        } else if (s >= 50) {
          result.status = 'high_risk';
          result.statusLabel = '🟠 HIGH RISK';
        } else if (s >= 35) {
          result.status = 'suspicious';
          result.statusLabel = '🟡 SUSPICIOUS';
        } else if (s >= 20) {
          result.status = 'caution';
          result.statusLabel = '🔵 CAUTION ADVISED';
        } else if (s >= 10) {
          result.status = 'low_concern';
          result.statusLabel = '🟢 LOW CONCERN';
        } else {
          result.status = 'legitimate';
          result.statusLabel = '✅ LIKELY LEGITIMATE';
        }
      }
    }
    // ========== END BLOCK ==========

    // Keep decision in sync with any post-ML score/status adjustments (trusted domains, own site)
    result.decision = buildDecision(result, ctx.combinedText || '');

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
// STATIC FILE SERVING
// After all API routes — prevents html files shadowing API paths
// ─────────────────────────────────────────────

// Root assets (favicon, og-image, logo, etc.)
app.use(express.static(__dirname, {
  index: false,
  maxAge: config.nodeEnv === 'production' ? '7d' : 0,
  dotfiles: 'ignore',
  extensions: ['png', 'jpg', 'svg', 'ico', 'webp'],
}));

// Public directory for HTML/CSS/JS
app.use(express.static(path.join(__dirname, 'public'), {
  index: false,
  maxAge: config.nodeEnv === 'production' ? '1d' : 0,
}));

// .well-known directory (RFC 8615)
app.use('/.well-known', express.static(path.join(__dirname, '.well-known'), {
  maxAge: '7d',
}));

// ─────────────────────────────────────────────
// HOMEPAGE
// ─────────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
    if (err) {
      logger.error('index.html not found');
      res.status(500).send('Server error');
    }
  });
});

// ─────────────────────────────────────────────
// HTML PAGE HANDLER — catch-all, must be last
// ─────────────────────────────────────────────
app.get(/^\/[^.]*\.html?$|^\/[a-zA-Z0-9\-_\/]+$/, (req, res) => {
  let fileName = req.path;
  const fs = require('fs');

  if (fileName.endsWith('/') && fileName.length > 1) {
    fileName = fileName.slice(0, -1);
  }

  if (!path.extname(fileName)) {
    fileName += '.html';
  }

  const cleanPath = fileName.startsWith('/') ? fileName.slice(1) : fileName;
  const fullPath = path.join(__dirname, 'public', cleanPath);

  if (fs.existsSync(fullPath)) {
    res.sendFile(fullPath);
  } else {
    if (!path.extname(req.path)) {
      const indexPath = path.join(__dirname, 'public', req.path, 'index.html');
      if (fs.existsSync(indexPath)) {
        return res.sendFile(indexPath);
      }
    }
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
// IMAGE OCR (tesseract.js)
// ─────────────────────────────────────────────
let tesseract;
try {
  tesseract = require('tesseract.js');
  logger.info('✅ tesseract.js loaded');
} catch (e) {
  logger.warn('⚠ tesseract.js unavailable — image upload disabled', { error: e.message });
}

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

  if (err.message.includes('Only PDF') || err.message.includes('Only PDF, Word')) {
    return res.status(400).json({ error: err.message });
  }

  logger.error('Unhandled error', { error: err.message, stack: err.stack, path: req.path });
  res.status(500).json({
    error: 'Internal server error',
    message: config.nodeEnv === 'development' ? err.message : 'Something went wrong',
  });
});

// ─────────────────────────────────────────────
// CATCH-ALL 404
// ─────────────────────────────────────────────
// Express 4 + 5 safe 404 (avoid app.use('*') which breaks path-to-regexp v8 / Express 5)
app.use((req, res) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/analyze') || req.path.startsWith('/analytics')) {
    return res.status(404).json({ error: 'API endpoint not found' });
  }
  const fallback = path.join(__dirname, 'public', 'index.html');
  const local = path.join(__dirname, 'index.html');
  const fs = require('fs');
  if (fs.existsSync(fallback)) return res.sendFile(fallback);
  if (fs.existsSync(local)) return res.sendFile(local);
  res.status(404).send('Not found');
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
// START SERVER
// ─────────────────────────────────────────────
// Render / containers require 0.0.0.0 — localhost-only bind fails health checks
const HOST = process.env.HOST || '0.0.0.0';
const PORT = Number(process.env.PORT) || Number(config.port) || 3000;

try {
  server = app.listen(PORT, HOST, () => {
    logger.info('🚀 VerifyJobs v2.0 started', {
      host: HOST,
      port: PORT,
      env: config.nodeEnv,
      root: __dirname,
      cacheEnabled: config.cacheEnabled,
    });

    console.log(`🚀 VerifyJobs v2.0 listening on http://${HOST}:${PORT}`);
    console.log(`📄 Root: ${__dirname}`);
    console.log(`✅ Health: http://${HOST}:${PORT}/health`);
    console.log(`📊 Analytics: http://${HOST}:${PORT}/analytics.html`);
    console.log(`🔒 Environment: ${config.nodeEnv}`);

    try {
      ensureStorage();
      const s = getStorageInfo();
      console.log(`💾 Storage: ${s.analysesFile} (records=${s.recordCount}, writable=${s.writable})`);
    } catch (e) {
      console.warn('💾 Storage check failed:', e.message);
    }

    // Non-blocking — never delay listen / readiness
    if (process.env.ENABLE_ML !== 'false') {
      Promise.race([
        checkServerHealth(),
        new Promise((resolve) => setTimeout(() => resolve(false), 2500)),
      ]).then(available => {
        if (available) console.log('🤖 ML inference server: connected');
        else console.log('⚠️  ML inference server: offline — rule engine only');
      }).catch(() => {
        console.log('⚠️  ML inference server: offline — rule engine only');
      });
    }
  });

  server.on('error', (err) => {
    console.error('❌ Server failed to bind:', err.message);
    process.exit(1);
  });
} catch (err) {
  console.error('❌ Failed to start server:', err);
  process.exit(1);
}

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