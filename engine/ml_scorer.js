// engine/ml_scorer.js
// VerifyJobs — Hybrid ML + Rule Engine Score Blending
// =====================================================
// Calls the Python FastAPI inference server (ml/serve.py) and blends
// its output with the existing rule engine score.
//
// Blending strategy:
//   - If ML is confident AND agrees with rules → weighted average
//   - If ML is confident BUT disagrees with rules → trust ML more
//   - If ML is low confidence → fall back to rules
//   - If ML server is unreachable → fall back to rules silently
//
// The rule engine is a hard floor for known scam patterns:
//   Some patterns (upfront fee, crypto wallet, WhatsApp-only + ₦500k/day)
//   are SO strongly scam-indicative that we never score them below 60
//   regardless of what the ML model says.

'use strict';

const axios = require('axios');

// ── CONFIG ────────────────────────────────────────────────────────────────────

const ML_SERVER_URL =
  process.env.ML_SERVER_URL ||
  'http://localhost:8001';

const ML_TIMEOUT =
  parseInt(process.env.ML_TIMEOUT || '5000');

// Cached server availability (avoid hammering a dead server)
let _serverAvailable = null;      // null = unknown, true/false = checked
let _lastHealthCheck = 0;
const HEALTH_CHECK_INTERVAL = 60_000;  // re-check every 30 seconds

// ── HTTP HELPERS ──────────────────────────────────────────────────────────────

async function httpPost(path, body) {
  const response = await axios.post(
    `${ML_SERVER_URL}${path}`,
    body,
    {
      timeout: ML_TIMEOUT,
      headers: { 'Content-Type': 'application/json' },
    }
  );
  return response.data;
}

async function httpGet(path) {
  const response = await axios.get(
    `${ML_SERVER_URL}${path}`,
    { timeout: 2000 }
  );
  return response.data;
}

// ── SERVER HEALTH CHECK ───────────────────────────────────────────────────────

async function checkServerHealth() {
  const now = Date.now();
  if (now - _lastHealthCheck < HEALTH_CHECK_INTERVAL && _serverAvailable !== null) {
    return _serverAvailable;
  }
  try {
    await httpGet('/health');
    if (!_serverAvailable) {
      console.log('[ML] ✅ ML inference server connected');
    }
    _serverAvailable = true;
  } catch {
    if (_serverAvailable !== false) {
      console.warn('[ML] ⚠ ML server unreachable — using rule engine only');
    }
    _serverAvailable = false;
  }
  _lastHealthCheck = now;
  return _serverAvailable;
}

// ── HARD FLOOR RULES ─────────────────────────────────────────────────────────
// These patterns are SO clear-cut that we enforce a minimum score
// regardless of model output. This prevents ML from under-scoring
// absolute scam patterns it hasn't seen enough of in training.

const HARD_FLOOR_RULES = [
  {
    name:     'upfront_fee',
    pattern:  /pay\s+(registration|fee|upfront|deposit|training|equipment)|registration\s+fee|activation\s+fee/i,
    minScore: 68,
  },
  {
    name:     'crypto_payment',
    pattern:  /send\s+(bitcoin|usdt|ethereum|crypto)|pay\s+(via|with|in)\s+(bitcoin|crypto|usdt)/i,
    minScore: 72,
  },
  {
    name:     'wallet_fund_task',
    pattern:  /fund\s+(your|the)\s+(task|trading|account|wallet)|deposit\s+(to\s+)?(start|begin|activate)/i,
    minScore: 80,
  },
  {
    name:     'naira_impossible_daily',
    // ₦500,000+ per day for any role is impossible in the Nigerian market
    pattern:  /₦\s*[5-9]\d{5,}|₦\s*[1-9]\d{6,}.*?(daily|per\s+day|\/day)/i,
    minScore: 65,
  },
];

function applyHardFloors(text, score) {
  let floored = score;
  const floorsTriggered = [];

  for (const rule of HARD_FLOOR_RULES) {
    if (rule.pattern.test(text) && score < rule.minScore) {
      floored = Math.max(floored, rule.minScore);
      floorsTriggered.push(rule.name);
    }
  }

  return { floored, floorsTriggered };
}

// ── BLEND LOGIC ───────────────────────────────────────────────────────────────

/**
 * Blend rule-based score with ML probability into a final risk score.
 *
 * @param {number} ruleScore      - Rule engine output (0–100)
 * @param {number} mlProb         - ML calibrated probability (0–1)
 * @param {string} mlConfidence   - 'very_high' | 'high' | 'medium' | 'low'
 * @returns {{ finalScore, blendWeights, method }}
 */
function blendScores(ruleScore, mlProb, mlConfidence) {
  const mlScore = Math.round(mlProb * 100);

  // Agreement: both say scam (>50) or both say legit (≤50)
  const bothScam  = ruleScore > 50 && mlScore > 50;
  const bothLegit = ruleScore <= 50 && mlScore <= 50;
  const agree     = bothScam || bothLegit;

  // Blending weights by confidence level
  const weights = {
    very_high: { ml: 0.70, rules: 0.30 },
    high:      { ml: 0.55, rules: 0.45 },
    medium:    { ml: 0.35, rules: 0.65 },
    low:       { ml: 0.15, rules: 0.85 },
  };

  let w = weights[mlConfidence] || weights.medium;

  // If they agree, trust ML a bit more (it confirms what rules say)/
  if (agree) {
    w = { ml: Math.min(w.ml + 0.10, 0.80), rules: Math.max(w.rules - 0.10, 0.20) };
  }

  // If they strongly disagree (difference > 35 points) on classification direction,
  // use a more conservative blend to flag for human review
  const disagreement = Math.abs(ruleScore - mlScore);
  let method = 'weighted_blend';

  if (!agree && disagreement > 35) {
    // Conservative: take higher score to err on side of user safety
    // BUT cap at 80 to avoid over-triggering on legitimate posts
    const conservative = Math.min(Math.max(ruleScore, mlScore), 80);
    return {
      finalScore:   conservative,
      blendWeights: w,
      method:       'conservative_max',
      disagreement,
    };
  }

  const blended = Math.round(w.ml * mlScore + w.rules * ruleScore);

  return {
    finalScore:   Math.max(0, Math.min(100, blended)),
    blendWeights: w,
    method,
    disagreement,
  };
}

// ── MAIN EXPORT ───────────────────────────────────────────────────────────────

/**
 * Get ML-enhanced score for a job posting.
 *
 * @param {string} text       - Raw job posting text
 * @param {number} ruleScore  - Score from existing rule engine (0–100)
 * @returns {Promise<object>}
 */
async function getMLScore(text, ruleScore) {
  const available = await checkServerHealth();

  if (!available) {
    // Hard floors still apply even in fallback mode
    const { floored, floorsTriggered } = applyHardFloors(text, ruleScore);
    return {
      finalScore:     floored,
      ruleScore,
      mlScore:        null,
      mlProb:         null,
      mlConfidence:   null,
      mlAvailable:    false,
      method:         floorsTriggered.length ? 'rules_with_floor' : 'rules_only',
      floorsTriggered,
      blendWeights:   { ml: 0, rules: 1 },
      signalsFired:   [],
    };
  }

  try {
    const mlResult = await httpPost('/predict', {
      text,
      job_title: '',
      source:    '',
    });

    const { floored, floorsTriggered } = applyHardFloors(text, ruleScore);
    const effectiveRuleScore           = floored;

    const { finalScore, blendWeights, method, disagreement } = blendScores(
      effectiveRuleScore,
      mlResult.ml_prob,
      mlResult.confidence,
    );

    // Final floor pass on the blended score too
    const { floored: finalFloored, floorsTriggered: finalFloors } =
      applyHardFloors(text, finalScore);

    return {
      finalScore:     finalFloored,
      ruleScore,
      mlScore:        mlResult.ml_score,
      mlProb:         mlResult.ml_prob,
      mlConfidence:   mlResult.confidence,
      mlAvailable:    true,
      useBert:        mlResult.use_bert,
      prediction:     mlResult.prediction,
      method,
      disagreement,
      floorsTriggered: [...new Set([...floorsTriggered, ...finalFloors])],
      blendWeights,
      signalsFired:   mlResult.signals_fired || [],
      latencyMs:      mlResult.latency_ms,
    };

  } catch (err) {
    console.error(`[ML] Prediction error: ${err.message}`);
    _serverAvailable = false;  // Force health re-check next time

    // Graceful fallback
    const { floored, floorsTriggered } = applyHardFloors(text, ruleScore);
    return {
      finalScore:     floored,
      ruleScore,
      mlScore:        null,
      mlProb:         null,
      mlConfidence:   null,
      mlAvailable:    false,
      method:         'rules_fallback_error',
      floorsTriggered,
      blendWeights:   { ml: 0, rules: 1 },
      signalsFired:   [],
      error:          err.message,
    };
  }
}

/**
 * Enrich the full analyzeJob() result with ML scoring.
 * Drop-in wrapper around the rule engine output.
 *
 * Usage in server.js:
 *   const { enrichWithML } = require('./engine/ml_scorer');
 *   const ruleResult = analyzeJob(text, jobTitle, source);
 *   const result     = await enrichWithML(text, ruleResult);
 *   res.json(result);
 */
/**
 * Enrich the full analyzeJob() result with ML scoring.
 * Drop-in wrapper around the rule engine output.
 */
async function enrichWithML(text, ruleResult) {
  const mlData = await getMLScore(text, ruleResult.riskScore);

  function scoreToStatus(s) {
    if (s >= 80) return 'definite_scam';
    if (s >= 65) return 'very_high_risk';
    if (s >= 50) return 'high_risk';
    if (s >= 35) return 'suspicious';
    if (s >= 20) return 'caution';
    if (s >= 10) return 'low_concern';
    return 'legitimate';
  }

  function scoreToLabel(s) {
    if (s >= 80) return '🚨 DEFINITE SCAM';
    if (s >= 65) return '🔴 VERY HIGH RISK - Likely Scam';
    if (s >= 50) return '🟠 HIGH RISK';
    if (s >= 35) return '🟡 SUSPICIOUS';
    if (s >= 20) return '🔵 CAUTION ADVISED';
    if (s >= 10) return '🟢 LOW CONCERN';
    return '✅ LIKELY LEGITIMATE';
  }

  // Generate consistent explanation + recommendation based on final score
  function getConsistentText(score, originalExplanation, originalRecommendation, redFlags = []) {
    if (score < 50) {
      return {
        explanation: originalExplanation,
        recommendation: originalRecommendation,
      };
    }

    const flagCount = redFlags.length;
    const hasFlags = flagCount > 0;

    let explanation = '';
    let recommendation = '';

    if (score >= 80) {
      explanation = hasFlags
        ? `This posting shows multiple clear scam patterns (${flagCount} red flags detected). The combination of signals is strongly associated with employment fraud. Do not send any money, documents, or personal information.`
        : `This posting contains strong indicators of employment fraud. The overall risk level is very high. Do not proceed or share any personal details.`;

      recommendation = '⚠ DEFINITE HIGH RISK — Treat this as a scam. Do not apply, pay anything, or send documents. Verify the company independently only if you have a strong reason to believe it is genuine.';
    } else if (score >= 65) {
      explanation = hasFlags
        ? `Several serious warning signs were found (${flagCount} red flags). While not 100% conclusive, the pattern is commonly seen in fake job offers. Exercise extreme caution.`
        : `Multiple concerning signals were detected. This posting carries a high risk of being fraudulent. Proceed only after thorough independent verification.`;

      recommendation = '⚠ VERY HIGH RISK — Do not send money or sensitive documents. Contact the company through their official website (not links in the posting) before taking any further steps.';
    } else {
      // 50–64
      explanation = hasFlags
        ? `Some concerning elements were detected (${flagCount} red flags). The posting is not clearly a scam, but the risk is elevated enough to warrant careful checking.`
        : `A few risk indicators are present. The posting may still be legitimate, but extra verification is strongly recommended before applying.`;

      recommendation = '⚠ CAUTION ADVISED — Verify the company on its official website and LinkedIn, and never pay for training, equipment, or background checks upfront.';
    }

    return { explanation, recommendation };
  }

  const finalScore = mlData.finalScore;
  const consistent = getConsistentText(
    finalScore,
    ruleResult.explanation,
    ruleResult.recommendation,
    ruleResult.redFlags || []
  );

  return {
    // Original rule result (fully preserved)
    ...ruleResult,

    // Override the top-level score fields with blended values
    riskScore:       finalScore,
    legitimacyScore: Math.max(0, 100 - finalScore),
    status:          scoreToStatus(finalScore),
    statusLabel:     scoreToLabel(finalScore),

    // Force consistent wording
    explanation:     consistent.explanation,
    recommendation:  consistent.recommendation,

    // ML enrichment block
    ml: {
      available:       mlData.mlAvailable,
      score:           mlData.mlScore,
      probability:     mlData.mlProb,
      confidence:      mlData.mlConfidence,
      prediction:      mlData.prediction,
      useBert:         mlData.useBert,
      blendMethod:     mlData.method,
      blendWeights:    mlData.blendWeights,
      floorsTriggered: mlData.floorsTriggered,
      signalsFired:    mlData.signalsFired,
      latencyMs:       mlData.latencyMs,
      ruleScore:       ruleResult.riskScore,
      finalScore,
    },
  };
}

module.exports = { getMLScore, enrichWithML, checkServerHealth };