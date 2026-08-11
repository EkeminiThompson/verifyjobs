// enhanced-scorer.js

/**
 * Normalizes the risk score to a 0-100 range with decimal precision control
 */
function normalizeScore(score, precision = 0) {
  if (score < 0) return 0;
  if (score > 100) return 100;
  
  // Round to specified decimal places (default: whole numbers)
  return parseFloat(score.toFixed(precision));
}

/**
 * Returns risk status with more nuanced, granular levels
 */
function getStatus(score) {
  if (score >= 80) return 'definite_scam';
  if (score >= 65) return 'very_high_risk';
  if (score >= 50) return 'high_risk';
  if (score >= 35) return 'suspicious';
  if (score >= 20) return 'caution';
  if (score >= 10) return 'low_concern';
  return 'legitimate';
}

/**
 * Returns human-readable status label with emojis for UI
 */
function getStatusLabel(score) {
  if (score >= 80) return '🚨 DEFINITE SCAM';
  if (score >= 65) return '🔴 VERY HIGH RISK - Likely Scam';
  if (score >= 50) return '🟠 HIGH RISK';
  if (score >= 35) return '🟡 SUSPICIOUS';
  if (score >= 20) return '🔵 CAUTION ADVISED';
  if (score >= 10) return '🟢 LOW CONCERN';
  return '✅ LIKELY LEGITIMATE';
}

/**
 * Returns plain text status label without emojis (for email, reports, etc.)
 */
function getStatusLabelPlain(score) {
  if (score >= 80) return 'CRITICAL RISK';
  if (score >= 65) return 'VERY HIGH RISK';
  if (score >= 50) return 'HIGH RISK';
  if (score >= 35) return 'SUSPICIOUS';
  if (score >= 20) return 'CAUTION ADVISED';
  if (score >= 10) return 'LOW CONCERN';
  return 'LOW RISK SIGNALS';
}

/**
 * Returns color code for UI styling (hex colors)
 */
function getRiskColor(score) {
  if (score >= 80) return '#DC2626'; // Red 600
  if (score >= 65) return '#EA580C'; // Orange 600
  if (score >= 50) return '#F59E0B'; // Amber 500
  if (score >= 35) return '#EAB308'; // Yellow 500
  if (score >= 20) return '#3B82F6'; // Blue 500
  if (score >= 10) return '#10B981'; // Green 500
  return '#059669'; // Green 600
}

/**
 * Returns CSS color class name for styling
 */
function getRiskColorClass(score) {
  if (score >= 80) return 'risk-definite-scam';
  if (score >= 65) return 'risk-very-high';
  if (score >= 50) return 'risk-high';
  if (score >= 35) return 'risk-suspicious';
  if (score >= 20) return 'risk-caution';
  if (score >= 10) return 'risk-low';
  return 'risk-legitimate';
}

/**
 * Calculate confidence level based on number of indicators
 */
function calculateConfidence(redFlagCount, positiveCount, textLength) {
  let confidenceScore = 50; // Base confidence

  // More indicators = higher confidence
  if (redFlagCount >= 5) confidenceScore += 30;
  else if (redFlagCount >= 3) confidenceScore += 20;
  else if (redFlagCount >= 1) confidenceScore += 10;

  if (positiveCount >= 5) confidenceScore += 20;
  else if (positiveCount >= 3) confidenceScore += 15;
  else if (positiveCount >= 1) confidenceScore += 10;

  // Longer text = more data = higher confidence
  if (textLength > 1000) confidenceScore += 15;
  else if (textLength > 500) confidenceScore += 10;
  else if (textLength > 200) confidenceScore += 5;
  else if (textLength < 100) confidenceScore -= 15; // Very short = less reliable

  // Normalize to 0-100
  confidenceScore = Math.max(0, Math.min(100, confidenceScore));

  // Convert to label
  if (confidenceScore >= 80) return 'very_high';
  if (confidenceScore >= 60) return 'high';
  if (confidenceScore >= 40) return 'medium';
  if (confidenceScore >= 20) return 'low';
  return 'very_low';
}

/**
 * Get confidence percentage
 */
function getConfidencePercentage(confidence) {
  const mapping = {
    'very_high': 90,
    'high': 75,
    'medium': 50,
    'low': 30,
    'very_low': 15
  };
  return mapping[confidence] || 50;
}

/**
 * Returns detailed risk breakdown by category
 */
function getRiskBreakdown(score) {
  return {
    overall: score,
    category: getStatus(score),
    severity: getSeverityLevel(score),
    trustworthiness: 100 - score,
    actionRequired: getActionUrgency(score)
  };
}

/**
 * Get severity level
 */
function getSeverityLevel(score) {
  if (score >= 80) return 'critical';
  if (score >= 65) return 'severe';
  if (score >= 50) return 'major';
  if (score >= 35) return 'moderate';
  if (score >= 20) return 'minor';
  return 'minimal';
}

/**
 * Get action urgency
 */
function getActionUrgency(score) {
  if (score >= 80) return 'immediate'; // Do not proceed under any circumstances
  if (score >= 65) return 'urgent';    // Avoid unless extraordinary circumstances
  if (score >= 50) return 'high';      // Extensive verification required
  if (score >= 35) return 'moderate';  // Careful verification needed
  if (score >= 20) return 'low';       // Standard due diligence
  return 'routine';                     // Normal application process
}

/**
 * Generate a risk score description for reports
 */
function getScoreDescription(score) {
  const descriptions = {
    'definite_scam': 'This posting exhibits overwhelming evidence of fraudulent intent with multiple critical scam indicators.',
    'very_high_risk': 'This posting contains numerous serious red flags strongly suggesting it is a scam.',
    'high_risk': 'This posting shows significant warning signs that indicate a high probability of fraud.',
    'suspicious': 'This posting contains several concerning elements that warrant careful investigation.',
    'caution': 'This posting has some minor concerns that should be verified before proceeding.',
    'low_concern': 'This posting appears mostly legitimate with only minimal concerns.',
    'legitimate': 'This posting shows strong indicators of legitimacy with no major red flags.'
  };
  
  return descriptions[getStatus(score)] || 'Unable to determine risk level.';
}

/**
 * Compare risk score to threshold
 */
function compareToThreshold(score, threshold) {
  return {
    score,
    threshold,
    exceeds: score >= threshold,
    difference: score - threshold,
    percentageOfThreshold: (score / threshold) * 100
  };
}

/**
 * Get recommended action based on score
 */
function getRecommendedAction(score) {
  if (score >= 80) return 'reject';
  if (score >= 65) return 'avoid';
  if (score >= 50) return 'verify_extensively';
  if (score >= 35) return 'verify_carefully';
  if (score >= 20) return 'verify_normally';
  return 'proceed_with_caution';
}

/**
 * Format score for display with appropriate precision
 */
function formatScore(score, includePercent = true) {
  const formatted = normalizeScore(score, 0);
  return includePercent ? `${formatted}%` : formatted.toString();
}

/**
 * Get score trend indication (for comparing multiple analyses)
 */
function getScoreTrend(currentScore, previousScore) {
  if (!previousScore) return 'no_comparison';
  
  const difference = currentScore - previousScore;
  
  if (Math.abs(difference) < 5) return 'stable';
  if (difference > 0) return 'increasing_risk';
  return 'decreasing_risk';
}

/**
 * Export comprehensive score analysis
 */
function getComprehensiveAnalysis(score, redFlagCount = 0, positiveCount = 0, textLength = 0) {
  const confidence = calculateConfidence(redFlagCount, positiveCount, textLength);
  
  return {
    score: normalizeScore(score),
    status: getStatus(score),
    statusLabel: getStatusLabel(score),
    statusLabelPlain: getStatusLabelPlain(score),
    color: getRiskColor(score),
    colorClass: getRiskColorClass(score),
    confidence,
    confidencePercentage: getConfidencePercentage(confidence),
    breakdown: getRiskBreakdown(score),
    severity: getSeverityLevel(score),
    actionUrgency: getActionUrgency(score),
    recommendedAction: getRecommendedAction(score),
    description: getScoreDescription(score),
    formattedScore: formatScore(score)
  };
}

module.exports = {
  // Core functions
  normalizeScore,
  getStatus,
  getStatusLabel,
  getStatusLabelPlain,
  getRiskColor,
  getRiskColorClass,
  
  // Confidence functions
  calculateConfidence,
  getConfidencePercentage,
  
  // Analysis functions
  getRiskBreakdown,
  getSeverityLevel,
  getActionUrgency,
  getScoreDescription,
  getRecommendedAction,
  
  // Utility functions
  compareToThreshold,
  formatScore,
  getScoreTrend,
  getComprehensiveAnalysis
};