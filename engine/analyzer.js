const { redFlags, positiveSignals } = require('./rules');
const { normalizeScore, getStatus, getStatusLabel } = require('./scorer');
const { addAnalysis } = require('./storage');

/**
 * Context-based additional penalties
 */
function contextPenalty(text) {
  let penalty = 0;

  if (/whatsapp/i.test(text)) penalty += 25;
  if (/telegram/i.test(text)) penalty += 25;
  if (/signal|discord/i.test(text)) penalty += 15;

  if (/source:\s*(whatsapp|telegram|dm)/i.test(text)) penalty += 22;

  if (!/(www\.|\.com|\.org|\.net|linkedin\.com|official)/i.test(text)) penalty += 15;

  // Very short or low-content remote job
  if (text.length < 150 && /work from home|remote|earn|data entry|typing/i.test(text)) penalty += 18;

  return penalty;
}

/**
 * Clean text before analysis (especially useful for PDF/Word extracted text)
 */
function cleanText(text) {
  return text
    .replace(/\s+/g, ' ')           // normalize whitespace
    .replace(/\n+/g, ' ')
    .trim();
}

/**
 * Main Job Analysis Function
 */
function analyzeJob(text, jobTitle = "Untitled Job", source = "Unknown") {
  if (!text || typeof text !== 'string' || text.trim().length === 0) {
    return { 
      error: 'Invalid or empty job description',
      status: 'unverified',
      riskScore: 0
    };
  }

  // Clean the text (important for PDF/Word extraction)
  const clean = cleanText(text);

  let riskScore = 0;
  const redFlagsFound = [];
  const positivesFound = [];

  // === Process Red Flags ===
  for (const rule of redFlags) {
    if (rule.pattern.test(clean)) {
      riskScore += rule.score;
      redFlagsFound.push(rule.reason);
    }
  }

  // === Process Positive Signals ===
  for (const rule of positiveSignals) {
    if (rule.pattern.test(clean)) {
      riskScore += rule.score;
      positivesFound.push(rule.reason);
    }
  }

  // === Apply Contextual Penalties ===
  const extraPenalty = contextPenalty(clean);
  riskScore += extraPenalty;

  // Normalize score
  riskScore = normalizeScore(riskScore);

  const status = getStatus(riskScore);

  const result = {
    status,
    statusLabel: getStatusLabel(riskScore),
    riskScore,
    legitimacyScore: 100 - riskScore,

    redFlags: redFlagsFound,
    positiveIndicators: positivesFound,

    explanation: getExplanation(riskScore),
    recommendation: getRecommendation(riskScore),

    actionItems: [
      'Verify the company on their official website',
      'Check LinkedIn company page and real employees',
      'Google the exact job posting text',
      'Never pay any upfront fees or send money',
      'Confirm recruiter via official company email'
    ],

    metadata: {
      redFlagCount: redFlagsFound.length,
      positiveCount: positivesFound.length,
      contextPenalty: extraPenalty,
      originalLength: text.length,
      cleanedLength: clean.length
    }
  };

  // === Save to History ===
  try {
    addAnalysis(result, jobTitle, source, text);
  } catch (err) {
    console.error('Failed to save analysis to storage:', err.message);
  }

  return result;
}

// Helper Functions
function getExplanation(score) {
  if (score >= 75) return 'Multiple strong scam indicators detected. This matches common employment fraud patterns.';
  if (score >= 55) return 'Several red flags present. This opportunity carries high risk.';
  if (score >= 40) return 'Mixed signals with notable concerns. Caution is strongly advised.';
  if (score >= 20) return 'Some minor concerns detected. Additional verification recommended.';
  return 'No major red flags found. Appears relatively safe.';
}

function getRecommendation(score) {
  if (score >= 75) return 'Avoid completely. Very likely a scam.';
  if (score >= 55) return 'Do not proceed without thorough verification.';
  if (score >= 40) return 'Proceed with extreme caution and independent research.';
  if (score >= 20) return 'Looks potentially okay but still verify the company.';
  return 'Appears legitimate, but always perform standard due diligence.';
}

module.exports = analyzeJob;