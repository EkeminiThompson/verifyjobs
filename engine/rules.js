// rules.js
const redFlags = [
    // === HIGH RISK (40+) ===
    {
      pattern: /pay (upfront|fee|registration|processing|training|deposit|equipment|setup)/i,
      score: 45,
      reason: 'Requests upfront payment'
    },
    {
      pattern: /bitcoin|usdt|crypto|wallet address|crypto payment|send (crypto|bitcoin)/i,
      score: 50,
      reason: 'Requests cryptocurrency payment'
    },
    {
      pattern: /telegram only|whatsapp only|contact (only )?on (telegram|whatsapp|signal)/i,
      score: 40,
      reason: 'Requires off-platform communication'
    },
    {
      pattern: /interview (via|on|through) (whatsapp|telegram)/i,
      score: 38,
      reason: 'Interview conducted on messaging app'
    },
  
    // === MEDIUM-HIGH RISK (25-39) ===
    {
      pattern: /easy money|make money (fast|quick|overnight)|get rich quick|financial freedom/i,
      score: 32,
      reason: 'Promises unrealistic easy earnings'
    },
    {
      pattern: /\$\d{3,}\s*per day|\d{3,}k?\s*per (day|week)|earn \$\d{4,}/i,
      score: 30,
      reason: 'Unrealistically high daily/weekly pay'
    },
    {
      pattern: /task|mission|package|reshipping|money (transfer|flipping|mul(e|ing))|gift card/i,
      score: 38,
      reason: 'Mentions reshipping, tasks, or money movement'
    },
    {
      pattern: /urgent hiring|limited slots|apply (now|immediately|fast|today)|few positions left|closing soon/i,
      score: 22,
      reason: 'High-pressure urgency tactics'
    },
  
    // === MEDIUM RISK (15-24) ===
    {
      pattern: /gmail\.com|yahoo\.com|hotmail\.com|outlook\.com|protonmail/i,
      score: 20,
      reason: 'Uses free/personal email domain'
    },
    {
      pattern: /no (experience|qualification|degree|background) (needed|required)/i,
      score: 18,
      reason: 'No experience required'
    },
    {
      pattern: /data entry|copy paste|typing|survey|review.*(task|daily)|amazon (task|customer)/i,
      score: 20,
      reason: 'Common scam job categories'
    },
    {
      pattern: /work from home|remote (job|position).*no (interview|meeting)/i,
      score: 23,
      reason: 'Suspiciously easy remote job'
    },
    {
      pattern: /your (own|personal) (computer|laptop|phone|device).*work/i,
      score: 18,
      reason: 'Requires use of personal devices'
    },
  
    // === SUPPORTING SIGNALS (8-15) ===
    {
      pattern: /guaranteed (income|salary|payment|earnings)|100% (guaranteed|secure)/i,
      score: 15,
      reason: 'Guarantees income or success'
    },
    {
      pattern: /investment|capital|fund your account|bring your own capital/i,
      score: 42,
      reason: 'Asks for investment or capital'
    },
    {
      pattern: /\b(poor|bad|broken) (english|grammar)|broken english/i,
      score: 12,
      reason: 'Poor grammar (common in scams)'
    }
  ];
  
  const positiveSignals = [
    {
      pattern: /linkedin\.com\/(company|in|jobs|company\/[^\/\s]+)/i,
      score: -15,
      reason: 'LinkedIn company or professional profile'
    },
    {
      pattern: /https?:\/\/(www\.)?[^.\s]+\.(com|org|net|co|io)\/(careers?|jobs?|about|team)/i,
      score: -13,
      reason: 'Official company career page'
    },
    {
      pattern: /health insurance|dental|vision|401k|pension|pto|paid leave|paid time off/i,
      score: -10,
      reason: 'Mentions standard professional benefits'
    },
    {
      pattern: /interview (process|stages?|via zoom|teams|google meet|in[- ]?person)/i,
      score: -10,
      reason: 'Structured professional interview process'
    },
    {
      pattern: /\.(com|org|net|co)\b.*@(?!(gmail|yahoo|hotmail|protonmail))[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}/i,
      score: -9,
      reason: 'Uses proper company email domain'
    },
    {
      pattern: /equal opportunity|diversity|inclusive|eeo|affirmative action/i,
      score: -5,
      reason: 'Standard corporate compliance language'
    }
  ];
  
  // Enhanced Analysis Function
  function analyzeJobPost(text) {
    if (!text || typeof text !== 'string') {
      return { error: 'Invalid input' };
    }
  
    let totalScore = 0;
    const triggers = [];
  
    // Red Flags
    for (const flag of redFlags) {
      if (flag.pattern.test(text)) {
        totalScore += flag.score;
        triggers.push({ type: 'red', score: flag.score, reason: flag.reason });
      }
    }
  
    // Positive Signals
    for (const signal of positiveSignals) {
      if (signal.pattern.test(text)) {
        totalScore += signal.score;
        triggers.push({ type: 'positive', score: signal.score, reason: signal.reason });
      }
    }
  
    // Clamp score
    totalScore = Math.max(0, Math.min(100, Math.round(totalScore)));
  
    // Risk Level
    let riskLevel = 'LOW';
    if (totalScore >= 65) riskLevel = 'VERY HIGH';
    else if (totalScore >= 50) riskLevel = 'HIGH';
    else if (totalScore >= 35) riskLevel = 'MEDIUM';
    else if (totalScore >= 15) riskLevel = 'SUSPICIOUS';
  
    return {
      totalScore,
      riskLevel,
      isLikelyScam: totalScore >= 45,
      triggers: triggers.slice(0, 15),
      redFlagCount: triggers.filter(t => t.type === 'red').length,
      positiveCount: triggers.filter(t => t.type === 'positive').length
    };
  }
  
  module.exports = {
    redFlags,
    positiveSignals,
    analyzeJobPost
  };