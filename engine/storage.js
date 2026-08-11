// engine/storage.js — durable analysis log for the intelligence dashboard
const fs = require('fs');
const path = require('path');

/**
 * Resolve data directory robustly.
 * Prefer VERIFYJOBS_DATA_DIR, then project-root/data next to engine/, then cwd/data.
 */
function resolveDataDir() {
  if (process.env.VERIFYJOBS_DATA_DIR) {
    return path.resolve(process.env.VERIFYJOBS_DATA_DIR);
  }
  // engine/ → project root → data/
  const fromEngine = path.resolve(__dirname, '..', 'data');
  const fromCwd = path.resolve(process.cwd(), 'data');
  // Prefer existing dir with analyses.json
  for (const candidate of [fromEngine, fromCwd]) {
    const file = path.join(candidate, 'analyses.json');
    if (fs.existsSync(file)) return candidate;
  }
  for (const candidate of [fromEngine, fromCwd]) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return fromEngine;
}

const DATA_DIR = resolveDataDir();
const ANALYSES_FILE = path.join(DATA_DIR, 'analyses.json');

function ensureStorage() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      console.log('[storage] Created data folder:', DATA_DIR);
    }
    if (!fs.existsSync(ANALYSES_FILE)) {
      fs.writeFileSync(ANALYSES_FILE, '[]', 'utf8');
      console.log('[storage] Created analyses.json at', ANALYSES_FILE);
    }
  } catch (err) {
    console.error('[storage] init failed:', err.message);
  }
}

ensureStorage();

function loadAnalyses() {
  try {
    if (!fs.existsSync(ANALYSES_FILE)) return [];
    const data = fs.readFileSync(ANALYSES_FILE, 'utf8');
    const parsed = JSON.parse(data || '[]');
    return Array.isArray(parsed) ? parsed : (parsed.analyses || []);
  } catch (err) {
    console.error('[storage] load failed:', err.message);
    return [];
  }
}

function saveAnalyses(analyses) {
  try {
    ensureStorage();
    fs.writeFileSync(ANALYSES_FILE, JSON.stringify(analyses, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('[storage] save failed:', err.message);
    return false;
  }
}

/**
 * Persist one analysis for the dashboard.
 * Keeps a short text snippet only (privacy-conscious).
 */
function addAnalysis(analysisResult, jobTitle = 'Untitled Job', source = 'Unknown', originalText = '') {
  try {
    const analyses = loadAnalyses();
    const newEntry = {
      id: `anal_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      timestamp: new Date().toISOString(),
      jobTitle: String(jobTitle || 'Untitled Job').trim().slice(0, 200),
      source: String(source || 'Unknown').trim().slice(0, 80),
      // flatten key fields so analytics extractFeatures always finds them
      status: analysisResult.status,
      riskScore: analysisResult.riskScore,
      legitimacyScore: analysisResult.legitimacyScore,
      redFlags: analysisResult.redFlags || [],
      positiveIndicators: analysisResult.positiveIndicators || [],
      metadata: analysisResult.metadata || {},
      ml: analysisResult.ml || null,
      decision: analysisResult.decision || null,
      // keep full result for debugging (bounded)
      result: {
        status: analysisResult.status,
        riskScore: analysisResult.riskScore,
        legitimacyScore: analysisResult.legitimacyScore,
        redFlags: analysisResult.redFlags || [],
        positiveIndicators: analysisResult.positiveIndicators || [],
        metadata: analysisResult.metadata || {},
      },
      originalText: originalText ? String(originalText).substring(0, 400) : '',
    };

    analyses.unshift(newEntry);
    // Cap history so the file cannot grow forever
    const capped = analyses.slice(0, 5000);
    const ok = saveAnalyses(capped);
    if (!ok) {
      console.error('[storage] addAnalysis could not write file', ANALYSES_FILE);
    } else if (process.env.NODE_ENV !== 'production') {
      console.log('[storage] saved analysis', newEntry.id, 'total=', capped.length, 'path=', ANALYSES_FILE);
    }
    return newEntry;
  } catch (err) {
    console.error('[storage] addAnalysis error:', err.message);
    return null;
  }
}

function getAllAnalyses(limit = 50) {
  return loadAnalyses().slice(0, limit);
}

function clearAnalyses() {
  return saveAnalyses([]);
}

function getStorageInfo() {
  let count = 0;
  try {
    count = loadAnalyses().length;
  } catch (_) {}
  return {
    dataDir: DATA_DIR,
    analysesFile: ANALYSES_FILE,
    exists: fs.existsSync(ANALYSES_FILE),
    recordCount: count,
    writable: (() => {
      try {
        fs.accessSync(DATA_DIR, fs.constants.W_OK);
        return true;
      } catch {
        return false;
      }
    })(),
  };
}

module.exports = {
  ensureStorage,
  loadAnalyses,
  saveAnalyses,
  addAnalysis,
  getAllAnalyses,
  clearAnalyses,
  getStorageInfo,
  ANALYSES_FILE,
  DATA_DIR,
};
