// scorer.js

/**
 * Normalizes the risk score to a 0-100 range
 */
function normalizeScore(score) {
    if (score < 0) return 0;
    if (score > 100) return 100;
    return Math.round(score); // Round for cleaner output
  }
  
  /**
   * Returns risk status with more nuanced levels
   */
  function getStatus(score) {
    if (score >= 75) return 'scam';
    if (score >= 55) return 'high_risk';
    if (score >= 40) return 'suspicious';
    if (score >= 20) return 'caution';
    return 'legitimate';
  }
  
  /**
   * Returns human-readable status label
   */
  function getStatusLabel(score) {
    if (score >= 75) return 'VERY HIGH RISK - Likely Scam';
    if (score >= 55) return 'HIGH RISK';
    if (score >= 40) return 'SUSPICIOUS';
    if (score >= 20) return 'CAUTION';
    return 'LOW RISK - Likely Legitimate';
  }
  
  /**
   * Returns color/code for UI purposes
   */
  function getRiskColor(score) {
    if (score >= 75) return 'red';
    if (score >= 55) return 'orange';
    if (score >= 40) return 'yellow';
    if (score >= 20) return 'blue';
    return 'green';
  }
  
  module.exports = {
    normalizeScore,
    getStatus,
    getStatusLabel,
    getRiskColor
  };