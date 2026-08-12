// scorer.js
//
// Design contract:
//   - Score 0–100 where 100 = certain scam, 0 = certainly legitimate
//   - Every tier (status / severity / urgency / action / color) must be
//     consistent at every score value — no cross-tier mismatches
//   - jobFlavour ('formal' | 'informal' | 'mixed' | 'none') from job-likelihood
//     is accepted as an optional input and used to sharpen messaging for
//     WhatsApp / Telegram / task-farm scams vs. formal posting fraud
//   - All edge cases handled: score=-5, score=105, threshold=0, previousScore=0
//
// Tier map (thresholds are inclusive-lower, exclusive-upper):
//
//   Score     Status          Severity   Urgency     Action
//   ──────────────────────────────────────────────────────────────
//   0–9       legitimate      minimal    none        proceed
//   10–19     low_concern     low        routine     proceed_with_awareness
//   20–34     caution         minor      low         verify_normally
//   35–49     suspicious      moderate   moderate    verify_carefully
//   50–64     high_risk       major      high        verify_extensively
//   65–79     very_high_risk  severe     urgent      avoid
//   80–100    definite_scam   critical   immediate   reject

'use strict';

// ---------------------------------------------------------------------------
// TIER TABLE — single source of truth for all threshold-based functions.
// All functions below derive from this; changing a threshold here propagates
// to status, label, color, severity, urgency, action, and description.
// ---------------------------------------------------------------------------

const TIERS = [
  {
    min: 80,
    status:          'definite_scam',
    label:           '🚨 DEFINITE SCAM',
    labelPlain:      'DEFINITE SCAM',
    color:           '#DC2626', // Red 600
    colorClass:      'risk-definite-scam',
    severity:        'critical',
    urgency:         'immediate',
    action:          'reject',
    description:     'Multiple critical fraud patterns matched. Automated evidence is very strong against engaging — still not a legal determination. Do not send money or sensitive data.',
    informalDesc:    'This informal offer matches known WhatsApp/Telegram/social scam formats with very strong automated evidence. Do not respond with money, documents, or personal financial details.',
  },
  {
    min: 65,
    status:          'very_high_risk',
    label:           '🔴 VERY HIGH RISK',
    labelPlain:      'VERY HIGH RISK',
    color:           '#EA580C', // Orange 600
    colorClass:      'risk-very-high',
    severity:        'severe',
    urgency:         'urgent',
    action:          'avoid',
    description:     'Numerous serious red flags. Treat as high risk unless you can independently verify the employer and the role through official channels.',
    informalDesc:    'Multiple fraud markers common in WhatsApp / task-farm / reshipping scams. Avoid fees and financial details until independently verified.',
  },
  {
    min: 50,
    status:          'high_risk',
    label:           '🟠 HIGH RISK',
    labelPlain:      'HIGH RISK',
    color:           '#F59E0B', // Amber 500
    colorClass:      'risk-high',
    severity:        'major',
    urgency:         'high',
    action:          'verify_extensively',
    description:     'Significant warning signs. Probability of fraud is elevated — verify extensively through official channels before engaging.',
    informalDesc:    'This informal offer raises significant red flags. Verify the employer or recruiter through official channels before responding — never pay any upfront fee.',
  },
  {
    min: 35,
    status:          'suspicious',
    label:           '🟡 SUSPICIOUS',
    labelPlain:      'SUSPICIOUS',
    color:           '#EAB308', // Yellow 500
    colorClass:      'risk-suspicious',
    severity:        'moderate',
    urgency:         'moderate',
    action:          'verify_carefully',
    description:     'This posting contains several concerning elements that warrant careful investigation before proceeding.',
    informalDesc:    'This informal offer has some concerning signals. Research the company or individual independently and never send money or personal documents upfront.',
  },
  {
    min: 20,
    status:          'caution',
    label:           '🔵 CAUTION ADVISED',
    labelPlain:      'CAUTION ADVISED',
    color:           '#3B82F6', // Blue 500
    colorClass:      'risk-caution',
    severity:        'minor',
    urgency:         'low',
    action:          'verify_normally',
    description:     'This posting has some minor concerns. Standard due diligence — research the company and confirm the role through official channels — is advised.',
    informalDesc:    'This offer has some minor concerns. Verify through the official company website or a known contact before engaging.',
  },
  {
    min: 10,
    status:          'low_concern',
    label:           '🟢 LOW CONCERN',
    labelPlain:      'LOW CONCERN',
    color:           '#10B981', // Emerald 500
    colorClass:      'risk-low',
    severity:        'low',
    urgency:         'routine',
    action:          'proceed_with_awareness',
    description:     'This posting appears mostly legitimate with only minimal concerns. Proceed with normal awareness.',
    informalDesc:    'This offer appears mostly credible with only minor concerns. Proceed with normal awareness and standard caution.',
  },
  {
    min: 0,
    status:          'legitimate',
    label:           '✅ LIKELY LEGITIMATE',
    labelPlain:      'LIKELY LEGITIMATE',
    color:           '#059669', // Emerald 600
    colorClass:      'risk-legitimate',
    severity:        'minimal',
    urgency:         'none',
    action:          'proceed',
    description:     'No significant automated red flags. Professional signals lean legitimate — still confirm the employer through official channels.',
    informalDesc:    'No significant automated red flags on this informal offer — still confirm who is behind it before sharing sensitive data.',
  },
];

// ---------------------------------------------------------------------------
// CORE TIER LOOKUP — used by every public function
// ---------------------------------------------------------------------------

/**
 * Returns the tier object for a given score.
 * Internal use only.
 */
function _tier(score) {
  const s = _clamp(score);
  return TIERS.find(t => s >= t.min);
}

/**
 * Clamps a numeric score to [0, 100]. Handles NaN, null, undefined.
 */
function _clamp(score) {
  const n = Number(score);
  if (!isFinite(n)) return 0;
  return Math.max(0, Math.min(100, n));
}

// ---------------------------------------------------------------------------
// NORMALISATION
// ---------------------------------------------------------------------------

/**
 * Clamps score to [0, 100] and rounds to `precision` decimal places.
 * Clamping happens BEFORE rounding so 100.4 → 100, not 100.
 * @param {number} score
 * @param {number} [precision=0]
 * @returns {number}
 */
function normalizeScore(score, precision = 0) {
  return parseFloat(_clamp(score).toFixed(precision));
}

// ---------------------------------------------------------------------------
// TIER-DERIVED GETTERS
// All operate from the TIERS table — no duplicated threshold logic.
// ---------------------------------------------------------------------------

/** Internal status key, e.g. 'definite_scam' */
function getStatus(score) {
  return _tier(score).status;
}

/** Emoji status label for UI */
function getStatusLabel(score) {
  return _tier(score).label;
}

/** Plain-text label for emails / reports */
function getStatusLabelPlain(score) {
  return _tier(score).labelPlain;
}

/** Hex color for UI */
function getRiskColor(score) {
  return _tier(score).color;
}

/** CSS class name */
function getRiskColorClass(score) {
  return _tier(score).colorClass;
}

/** Severity string */
function getSeverityLevel(score) {
  return _tier(score).severity;
}

/** Action urgency string */
function getActionUrgency(score) {
  return _tier(score).urgency;
}

/** Recommended action string */
function getRecommendedAction(score) {
  return _tier(score).action;
}

/**
 * Human-readable description of the risk level.
 * Optionally tailored to jobFlavour from job-likelihood.js.
 *
 * @param {number} score
 * @param {'formal'|'informal'|'mixed'|'none'} [jobFlavour='formal']
 * @returns {string}
 */
function getScoreDescription(score, jobFlavour = 'formal') {
  const t = _tier(score);
  return (jobFlavour === 'informal' || jobFlavour === 'mixed')
    ? t.informalDesc
    : t.description;
}

// ---------------------------------------------------------------------------
// CONFIDENCE
// ---------------------------------------------------------------------------

/**
 * Calculates analysis confidence from signal counts and text length.
 * Returns a label: 'very_high' | 'high' | 'medium' | 'low' | 'very_low'
 *
 * @param {number} redFlagCount
 * @param {number} positiveCount
 * @param {number} textLength  character count of the analysed text
 * @returns {string}
 */
function calculateConfidence(redFlagCount, positiveCount, textLength) {
  let c = 50;

  // Red flags contribute most — the more we found, the more certain we are
  if (redFlagCount >= 5)      c += 30;
  else if (redFlagCount >= 3) c += 20;
  else if (redFlagCount >= 1) c += 10;

  // Positive indicators also add signal
  if (positiveCount >= 5)      c += 20;
  else if (positiveCount >= 3) c += 15;
  else if (positiveCount >= 1) c += 10;

  // Text length: more text = more opportunity for signals to surface
  if (textLength > 1000)       c += 15;
  else if (textLength > 500)   c += 10;
  else if (textLength > 200)   c += 5;
  else if (textLength < 100)   c -= 15; // very short = unreliable

  c = Math.max(0, Math.min(100, c));

  if (c >= 80) return 'very_high';
  if (c >= 60) return 'high';
  if (c >= 40) return 'medium';
  if (c >= 20) return 'low';
  return 'very_low';
}

/**
 * Maps a confidence label to a representative percentage (for display).
 * @param {string} confidence
 * @returns {number}
 */
function getConfidencePercentage(confidence) {
  const map = {
    very_high: 90,
    high:      75,
    medium:    55,
    low:       35,
    very_low:  15,
  };
  // Graceful fallback for unknown labels — return 50 rather than silently wrong
  if (!(confidence in map)) {
    console.warn(`[scorer] Unknown confidence label: "${confidence}". Defaulting to 50.`);
    return 50;
  }
  return map[confidence];
}

// ---------------------------------------------------------------------------
// BREAKDOWN & COMPREHENSIVE
// ---------------------------------------------------------------------------

/**
 * Returns a structured breakdown of the score.
 * @param {number} score
 * @param {'formal'|'informal'|'mixed'|'none'} [jobFlavour]
 */
function getRiskBreakdown(score, jobFlavour) {
  const n = normalizeScore(score);
  return {
    overall:         n,
    category:        getStatus(n),
    severity:        getSeverityLevel(n),
    trustworthiness: 100 - n,
    actionRequired:  getActionUrgency(n),
    jobFlavour:      jobFlavour || 'formal',
  };
}

/**
 * Returns a full analysis object suitable for API responses / UI rendering.
 *
 * @param {number} score              Raw risk score (0–100)
 * @param {number} [redFlagCount=0]   Number of red flags found
 * @param {number} [positiveCount=0]  Number of positive indicators found
 * @param {number} [textLength=0]     Character length of analysed text
 * @param {'formal'|'informal'|'mixed'|'none'} [jobFlavour='formal']
 *        jobFlavour from assessJobLikelihood() in job-likelihood.js
 */
function getComprehensiveAnalysis(
  score,
  redFlagCount  = 0,
  positiveCount = 0,
  textLength    = 0,
  jobFlavour    = 'formal',
) {
  const n          = normalizeScore(score);
  const confidence = calculateConfidence(redFlagCount, positiveCount, textLength);

  return {
    score:               n,
    status:              getStatus(n),
    statusLabel:         getStatusLabel(n),
    statusLabelPlain:    getStatusLabelPlain(n),
    color:               getRiskColor(n),
    colorClass:          getRiskColorClass(n),
    confidence,
    confidencePercentage: getConfidencePercentage(confidence),
    breakdown:           getRiskBreakdown(n, jobFlavour),
    severity:            getSeverityLevel(n),
    actionUrgency:       getActionUrgency(n),
    recommendedAction:   getRecommendedAction(n),
    description:         getScoreDescription(n, jobFlavour),
    formattedScore:      formatScore(n),
    jobFlavour,
  };
}

// ---------------------------------------------------------------------------
// UTILITY FUNCTIONS
// ---------------------------------------------------------------------------

/**
 * Compares a score to a threshold.
 * Handles threshold=0 safely (no divide-by-zero → Infinity/NaN).
 *
 * @param {number} score
 * @param {number} threshold
 */
function compareToThreshold(score, threshold) {
  const s = normalizeScore(score);
  const t = Number(threshold);
  return {
    score:                s,
    threshold:            t,
    exceeds:              s >= t,
    difference:           s - t,
    // Return null when threshold is 0 rather than Infinity
    percentageOfThreshold: t === 0 ? null : parseFloat(((s / t) * 100).toFixed(1)),
  };
}

/**
 * Formats score for display.
 * @param {number} score
 * @param {boolean} [includePercent=true]
 */
function formatScore(score, includePercent = true) {
  const n = normalizeScore(score);
  return includePercent ? `${n}%` : String(n);
}

/**
 * Returns a trend label comparing current score to a previous score.
 * Handles previousScore=0 correctly (0 IS a valid prior score, not "no data").
 *
 * @param {number} currentScore
 * @param {number|null|undefined} previousScore  Pass null/undefined for no prior data
 * @returns {'no_comparison'|'stable'|'increasing_risk'|'decreasing_risk'}
 */
function getScoreTrend(currentScore, previousScore) {
  // Only treat as "no comparison" when caller explicitly passes null/undefined —
  // NOT when previousScore is 0 (which is a real, valid prior score).
  if (previousScore === null || previousScore === undefined) return 'no_comparison';

  const diff = _clamp(currentScore) - _clamp(previousScore);

  if (Math.abs(diff) < 5) return 'stable';
  return diff > 0 ? 'increasing_risk' : 'decreasing_risk';
}

/**
 * Returns the full TIERS table, useful for rendering a legend or key in the UI.
 * Strips internal-only properties.
 */
function getTierMap() {
  return TIERS.map(t => ({
    min:        t.min,
    max:        t === TIERS[0] ? 100 : TIERS[TIERS.indexOf(t) - 1].min - 1,
    status:     t.status,
    label:      t.labelPlain,
    color:      t.color,
    colorClass: t.colorClass,
    action:     t.action,
  }));
}

// ---------------------------------------------------------------------------
// EXPORTS
// ---------------------------------------------------------------------------

module.exports = {
  // Core normalisation
  normalizeScore,

  // Tier-derived getters (all consistent with each other at every score value)
  getStatus,
  getStatusLabel,
  getStatusLabelPlain,
  getRiskColor,
  getRiskColorClass,
  getSeverityLevel,
  getActionUrgency,
  getRecommendedAction,
  getScoreDescription,    // accepts optional jobFlavour

  // Confidence
  calculateConfidence,
  getConfidencePercentage,

  // Compound / breakdown
  getRiskBreakdown,       // accepts optional jobFlavour
  getComprehensiveAnalysis, // accepts optional jobFlavour

  // Utilities
  compareToThreshold,
  formatScore,
  getScoreTrend,
  getTierMap,             // new — render a legend / key in the UI
};