// engine/storage.js
const fs = require('fs');
const path = require('path');

// Go UP one level from engine/ to reach the root 'data' folder

// ALWAYS resolve from project root (safer approach)
const ROOT_DIR = path.resolve(__dirname, '..');
const DATA_DIR = path.join(ROOT_DIR, 'data');
const ANALYSES_FILE = path.join(DATA_DIR, 'analyses.json');
/**
 * Ensure data directory and analyses.json exist
 */
function ensureStorage() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      console.log('✅ Created data folder at root');
    }

    if (!fs.existsSync(ANALYSES_FILE)) {
      fs.writeFileSync(ANALYSES_FILE, '[]', 'utf8');
      console.log('✅ Created analyses.json');
    }
  } catch (err) {
    console.error('❌ Storage initialization failed:', err.message);
  }
}

// Initialize storage
ensureStorage();

/**
 * Load analyses
 */
function loadAnalyses() {
  try {
    const data = fs.readFileSync(ANALYSES_FILE, 'utf8');
    return JSON.parse(data || '[]');
  } catch (err) {
    console.error('Error loading analyses:', err.message);
    return [];
  }
}

/**
 * Save analyses
 */
function saveAnalyses(analyses) {
  try {
    fs.writeFileSync(ANALYSES_FILE, JSON.stringify(analyses, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('Error saving analyses:', err.message);
    return false;
  }
}

/**
 * Add new analysis
 */
function addAnalysis(analysisResult, jobTitle = "Untitled Job", source = "Unknown", originalText = "") {
  const analyses = loadAnalyses();

  const newEntry = {
    id: `anal_${Date.now()}`,
    timestamp: new Date().toISOString(),
    jobTitle: jobTitle.trim(),
    source: source.trim(),
    ...analysisResult,
    originalText: originalText ? originalText.substring(0, 650) : ""
  };

  analyses.unshift(newEntry); // newest first
  saveAnalyses(analyses);
  
  return newEntry;
}

/**
 * Get recent analyses
 */
function getAllAnalyses(limit = 50) {
  return loadAnalyses().slice(0, limit);
}

/**
 * Clear history
 */
function clearAnalyses() {
  return saveAnalyses([]);
}

module.exports = {
  ensureStorage,
  loadAnalyses,
  saveAnalyses,
  addAnalysis,
  getAllAnalyses,
  clearAnalyses
};