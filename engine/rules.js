// rules.js — Pattern library for employment-scam signals
// Design: prefer precision over recall on soft language (investment, passport, task).
// Critical rules should describe *fraud behaviour*, not everyday career-site words.
// Scores are evidence weights — not proof. Final guidance stays advisory.

// enhanced-rules.js - Comprehensive Job Scam Detection Rules

const redFlags = [
  // ========================================
  // === CRITICAL RISK (45-55 points) ===
  // ========================================
  {
    pattern: /bitcoin|usdt|tether|ethereum|crypto(currency)?|blockchain wallet|digital (currency|wallet)|binance|coinbase/i,
    score: 52,
    reason: 'Requests cryptocurrency payment or mentions crypto wallets',
    severity: 'critical'
  },
  {
    pattern: /earn\s+\d{2,}\s*%|\d{2,}\s*%\s*(weekly|daily|per\s+week|per\s+day|monthly)|returns?\s+paid\s+every\s+(friday|week|day)|guaranteed\s+(weekly|daily)\s+(return|profit|income)/i,
    score: 48,
    reason: 'Unrealistic percentage returns (weekly/daily profit promises)',
    severity: 'critical'
  },
  {
    pattern: /(?:minimum\s*(?:investment|capital|deposit)?\s*:?\s*[$£€₦]\s*[\d,]+|your\s+capital\s+is\s+protected|insurance\s+fund|capital\s+protection)/i,
    score: 44,
    reason: 'Requires personal capital with guaranteed protection claims',
    severity: 'high'
  },
  {
    pattern: /contact\s+(?:us|me|hr)?\s+on\s+telegram|telegram\s+only|message\s+(?:us|me)\s+on\s+telegram/i,
    score: 36,
    reason: 'Recruitment contact only via Telegram',
    severity: 'high'
  },

  {
    pattern: /pay (upfront|fee|registration|processing|training|deposit|equipment|setup|starter|kit|membership)/i,
    score: 48,
    reason: 'Requests upfront payment for job-related expenses',
    severity: 'critical'
  },
  {
    pattern: /(?:application|processing|medical|screening|portal|form|admission)\s+fees?|fees?\s+for\s+(?:processing|medical|screening|application|background)/i,
    score: 50,
    reason: 'Charges an application, processing, or medical fee to apply',
    severity: 'critical'
  },
  {
    pattern: /pay\s+to\s*:|pay\s+into\s*:|make\s+payment\s+to|acct?\.?\s*name\s*:|account\s+name\s*:|account\s+(?:number|no)\s*:/i,
    score: 46,
    reason: 'Instructs payment to a named bank account for the job',
    severity: 'critical'
  },
  {
    pattern: /\b(nnpc|n\.?n\.?p\.?c|shell|chevron|exxon\s*mobil|totalenergies|undp|unicef|who\b|world\s+bank|imf\b|mtn|airtel|dangote)\b[\s\S]{0,200}(?:application\s+fee|processing\s+fee|medical\s+fee|registration\s+fee|pay\s+to\s*:|acct?\.?\s*name\s*:)/i,
    score: 52,
    reason: 'Major organisation name used with a demand for application/processing payment',
    severity: 'critical'
  },

  {
    pattern: /western union|moneygram|wire transfer|gift card|steam card|itunes card|google play card/i,
    score: 50,
    reason: 'Requests untraceable payment methods',
    severity: 'critical'
  },
  // Identity / financial docs: only when "send/provide" + doc + scammy timing/channel
  // Bare "passport" on fellowship/visa pages is normal and must NOT critical-fire alone.
  {
    pattern: /(?:send|share|provide|upload|submit|email|forward).{0,50}(?:bank\s*account(?:\s*number)?|routing\s*number|bvn|nin|ssn|social\s*security(?:\s*number)?|(?:copy\s+of\s+)?passport|driver'?s?\s*licen[cs]e(?:\s*number)?).{0,40}(?:before\s+(?:you\s+)?(?:start|begin|apply|get\s+hired)|prior\s+to\s+(?:employment|starting|interview)|via\s+(?:whatsapp|telegram|signal)|in\s+order\s+to\s+(?:apply|start|begin|get\s+hired|receive))/i,
    score: 46,
    reason: 'Requests sensitive financial or identity documents prematurely',
    severity: 'critical'
  },
  {
    pattern: /(?:whatsapp|telegram|signal).{0,40}(?:bank\s*account|bvn|nin|ssn|passport|driver'?s?\s*licen[cs]e)|(?:bank\s*account|bvn|nin|ssn|passport\s*copy).{0,40}(?:whatsapp|telegram|signal)/i,
    score: 48,
    reason: 'Asks for identity or bank details via messaging app',
    severity: 'critical'
  },
  {
    pattern: /reshipp?ing|package forwarding|money mul(e|ing)|transfer agent|payment processor|check cashing/i,
    score: 50,
    reason: 'Classic reshipping or money mule scam pattern',
    severity: 'critical'
  },

  // ========================================
  // === HIGH RISK (35-44 points) ===
  // ========================================
  {
    pattern: /telegram only|whatsapp only|signal only|contact (only )?on (telegram|whatsapp|signal)/i,
    score: 42,
    reason: 'Requires communication exclusively through messaging apps',
    severity: 'high'
  },
  {
    pattern: /interview (via|on|through|over) (whatsapp|telegram|signal)/i,
    score: 40,
    reason: 'Conducts interviews via messaging apps instead of professional platforms',
    severity: 'high'
  },
  // Investment: require scam phrasing — NOT bare "investment" / "capital"
  // (those appear in development finance, impact investing, fellowship copy)
  {
    pattern: /(?:bring|provide|require[sd]?|need(?:s)?|must\s+have)\s+(?:your\s+own\s+)?(?:capital|investment)|personal\s+investment|fund\s+your\s+(?:own\s+)?account|capital\s+contribution|invest\s+(?:\$|£|€|₦)?\s*\d|you\s+(?:must|need\s+to)\s+invest/i,
    score: 44,
    reason: 'Requires personal investment or capital contribution',
    severity: 'high'
  },
  {
    pattern: /mlm|multi-?level marketing|network marketing|pyramid|downline|upline|recruit friends/i,
    score: 38,
    reason: 'Multi-level marketing or pyramid scheme indicators',
    severity: 'high'
  },
  {
    pattern: /commission only.*buy|purchase (inventory|products|samples)|sell our products/i,
    score: 36,
    reason: 'Commission-only with required product purchases',
    severity: 'high'
  },

  // ========================================
  // === MEDIUM-HIGH RISK (25-34 points) ===
  // ========================================
  {
    pattern: /easy money|make money (fast|quick|overnight)|get rich quick|financial freedom|passive income/i,
    score: 32,
    reason: 'Promises unrealistic easy earnings or wealth',
    severity: 'medium-high'
  },
  {
    pattern: /\$\d{3,}\s*(per|\/)\s*day|\$?\d{3,}k?\s*(per|\/)\s*(day|week)|earn \$\d{4,}\s*(daily|weekly|per (day|week))/i,
    score: 30,
    reason: 'Unrealistically high daily or weekly pay promises',
    severity: 'medium-high'
  },
  {
    pattern: /₦\d{3,}k\s*(per|\/)\s*(day|week)|₦\d{6,}\s*(daily|weekly|per (day|week))/i,
    score: 30,
    reason: 'Unrealistically high pay in Naira (Nigerian scam indicator)',
    severity: 'medium-high'
  },
  {
    pattern: /(?:daily\s+(?:task|mission|assignment)s?|complete\s+tasks?\s+to\s+earn|task\s*-?\s*based\s+(?:job|work|earning)|earn\s+by\s+complet(?:e|ing)\s+tasks?|amazon\s+(?:review\s+)?tasks?)/i,
    score: 28,
    reason: 'Task-based commission scam pattern (common in WhatsApp scams)',
    severity: 'medium-high'
  },
  {
    pattern: /urgent hiring|limited slots|only \d+ (positions?|slots?)|apply (now|immediately|fast|today)|few positions? left|closing (soon|today)/i,
    score: 26,
    reason: 'High-pressure urgency tactics to prevent careful consideration',
    severity: 'medium-high'
  },
  {
    pattern: /no interview|hired immediately|instant hire|start (today|now|immediately)|job guaranteed/i,
    score: 28,
    reason: 'Promises immediate hiring without proper vetting',
    severity: 'medium-high'
  },
  {
    pattern: /amazon (review|task|customer)|google opinion|product test(ing|er)|app test(ing|er)/i,
    score: 27,
    reason: 'Fake review or testing scam pattern',
    severity: 'medium-high'
  },

  // ========================================
  // === MEDIUM RISK (15-24 points) ===
  // ========================================
  {
    pattern: /gmail\.com|yahoo\.com|hotmail\.com|outlook\.com|protonmail\.com|mail\.com|yandex/i,
    score: 22,
    reason: 'Uses free personal email domain instead of company domain',
    severity: 'medium'
  },
  {
    pattern: /no (?:prior\s+)?(experience|qualification|degree|background|skills?)(?:\s+(needed|required|necessary))?|anyone can (do|apply)/i,
    score: 18,
    reason: 'No experience or qualifications required (common in scams)',
    severity: 'medium'
  },
  {
    pattern: /data entry|copy[\s-]?paste|typing|survey|form filling|ad posting|click ads|copy ads|paste them on/i,
    score: 20,
    reason: 'Common scam job categories (data entry, typing, surveys)',
    severity: 'medium'
  },
  {
    pattern: /work from home|remote (job|position).*no (interview|meeting|experience)/i,
    score: 24,
    reason: 'Remote job with suspiciously easy requirements',
    severity: 'medium'
  },
  {
    pattern: /(your|personal|own) (computer|laptop|phone|device|smartphone).*provide/i,
    score: 16,
    reason: 'Requires use of personal devices without reimbursement',
    severity: 'medium'
  },
  {
    pattern: /part[- ]?time.*\$\d{3,}|side (hustle|income).*\$\d{3,}/i,
    score: 20,
    reason: 'Part-time work with unrealistically high pay',
    severity: 'medium'
  },
  {
    pattern: /work\s+\d+\s*(hours?|hrs?)\s*(daily|a\s+day|per\s+day).{0,40}earn|earn.{0,40}work\s+\d+\s*(hours?|hrs?)/i,
    score: 24,
    reason: 'Unrealistically short work hours with pay claims',
    severity: 'medium-high'
  },
  {
    pattern: /virtual assistant.*no experience|personal assistant.*immediate start/i,
    score: 22,
    reason: 'Fake virtual/personal assistant scam pattern',
    severity: 'medium'
  },
  {
    pattern: /secret shopper|mystery shopp(er|ing)|shop(per)? eval/i,
    score: 24,
    reason: 'Mystery shopper scam (often involves fake checks)',
    severity: 'medium'
  },

  // ========================================
  // === LOW-MEDIUM RISK (8-14 points) ===
  // ========================================
  {
    pattern: /guaranteed (income|salary|payment|earnings)|100% (guaranteed|secure|success)/i,
    score: 14,
    reason: 'Guarantees income or success (unrealistic promise)',
    severity: 'low-medium'
  },
  {
    pattern: /training (fee|cost|payment)|certification (fee|cost)|background check fee/i,
    score: 12,
    reason: 'Mentions training or certification fees',
    severity: 'low-medium'
  },
  {
    pattern: /act (now|fast|quick)|don'?t miss|limited time|expires? (soon|today)/i,
    score: 10,
    reason: 'Creates false sense of urgency',
    severity: 'low-medium'
  },
  {
    pattern: /work (whenever|anywhere)|set your own (hours|schedule)|be your own boss/i,
    score: 8,
    reason: 'Overly flexible work promises (common in MLM)',
    severity: 'low-medium'
  },
  {
    pattern: /congratulations|you('ve| have) been selected|chosen (candidate|applicant)/i,
    score: 12,
    reason: 'Unsolicited congratulations or selection (you didn\'t apply)',
    severity: 'low-medium'
  },

  // ========================================
  // === LINGUISTIC & QUALITY INDICATORS ===
  // ========================================
  {
    pattern: /dear (sir|madam|applicant)|to whom it may concern/i,
    score: 8,
    reason: 'Generic greeting instead of personalized contact',
    severity: 'low'
  },
  {
    pattern: /kindly|needful|revert back|do the needful|at the earliest/i,
    score: 10,
    reason: 'Non-native English patterns common in overseas scams',
    severity: 'low-medium'
  },
  {
    pattern: /!!!|!!|\?\?|ALL CAPS.*ALL CAPS/i,
    score: 6,
    reason: 'Excessive punctuation or all-caps text',
    severity: 'low'
  },

  // ========================================
  // === SPECIFIC SCAM TYPES ===
  // ========================================
  {
    pattern: /car wrap|vehicle wrap|decal|sticker.*advertis/i,
    score: 34,
    reason: 'Car wrap advertising scam pattern',
    severity: 'high'
  },
  {
    pattern: /nanny|caregiver|babysitter.*start immediately.*no interview/i,
    score: 30,
    reason: 'Fake childcare position scam',
    severity: 'medium-high'
  },
  {
    pattern: /house sit(ter|ting)|pet sit(ter|ting).*advance payment/i,
    score: 28,
    reason: 'Fake house/pet sitting scam',
    severity: 'medium-high'
  },
  {
    pattern: /online (tutor|teacher).*no (degree|certification|experience)/i,
    score: 18,
    reason: 'Fake online tutoring opportunity',
    severity: 'medium'
  },
  {
    pattern: /freight forwarder|shipping coordinator.*personal account/i,
    score: 42,
    reason: 'Freight forwarding scam (money laundering)',
    severity: 'high'
  },
  {
    pattern: /insurance claim|claim processor.*work from home/i,
    score: 26,
    reason: 'Fake insurance processing job',
    severity: 'medium-high'
  },
  {
    pattern: /medical billing.*no (experience|certification).*work from home/i,
    score: 20,
    reason: 'Fake medical billing job',
    severity: 'medium'
  }
];

const positiveSignals = [
  // ========================================
  // === STRONG LEGITIMACY INDICATORS ===
  // ========================================
  {
    pattern: /linkedin\.com\/(company|in|jobs)\/[a-zA-Z0-9\-]+/i,
    score: -18,
    reason: 'Includes verified LinkedIn company or job posting URL',
    severity: 'strong-positive'
  },
  {
    pattern: /indeed\.com|glassdoor\.com|monster\.com|ziprecruiter\.com/i,
    score: -16,
    reason: 'Posted on reputable job board platform',
    severity: 'strong-positive'
  },
  {
    pattern: /https?:\/\/(www\.)?[a-z0-9\-]+\.(com|org|net|co|io)\/(careers?|jobs?|about|team|employment)/i,
    score: -14,
    reason: 'Links to official company career or about page',
    severity: 'strong-positive'
  },
  {
    pattern: /equal opportunity employer|eeo|affirmative action|diversity|inclusive workplace/i,
    score: -12,
    reason: 'Includes standard equal opportunity or diversity statements',
    severity: 'strong-positive'
  },

  // ========================================
  // === PROFESSIONAL BENEFITS ===
  // ========================================
  {
    pattern: /health insurance|medical coverage|dental|vision|401k|pension|retirement plan/i,
    score: -14,
    reason: 'Mentions standard professional benefits package',
    severity: 'positive'
  },
  {
    pattern: /pto|paid time off|paid leave|vacation days|sick leave|parental leave/i,
    score: -10,
    reason: 'Specifies paid time off benefits',
    severity: 'positive'
  },
  {
    pattern: /stock options|equity|employee stock purchase|espp/i,
    score: -12,
    reason: 'Offers equity or stock options (typical of legitimate companies)',
    severity: 'positive'
  },
  {
    pattern: /tuition reimbursement|professional development|continuing education|learning budget/i,
    score: -8,
    reason: 'Provides professional development opportunities',
    severity: 'positive'
  },

  // ========================================
  // === STRUCTURED HIRING PROCESS ===
  // ========================================
  {
    pattern: /interview (process|stages?|rounds?)|phone screen|technical interview|panel interview/i,
    score: -12,
    reason: 'Describes structured, professional interview process',
    severity: 'positive'
  },
  {
    pattern: /(zoom|teams|google meet|webex) interview|video interview|in[- ]?person interview/i,
    score: -10,
    reason: 'Uses professional video conferencing for interviews',
    severity: 'positive'
  },
  {
    pattern: /background check|reference check|employment verification|credit check/i,
    score: -8,
    reason: 'Conducts standard background or reference checks',
    severity: 'positive'
  },
  {
    pattern: /onboarding|orientation|training program|probation(ary)? period/i,
    score: -10,
    reason: 'Mentions formal onboarding or training process',
    severity: 'positive'
  },

  // ========================================
  // === PROFESSIONAL EMAIL & CONTACT ===
  // ========================================
  {
    pattern: /@(?!gmail|yahoo|hotmail|outlook|protonmail)[a-zA-Z0-9.\-]+\.(com|org|net|co|io)\b/i,
    score: -12,
    reason: 'Uses professional company email domain (not free email)',
    severity: 'positive'
  },
  {
    pattern: /contact us at.*@[a-zA-Z0-9.\-]+\.(com|org|net)|email.*hr@/i,
    score: -8,
    reason: 'Provides official HR or company contact email',
    severity: 'positive'
  },
  {
    pattern: /apply through our (website|portal|careers page)|visit (our|the) careers page/i,
    score: -10,
    reason: 'Directs applicants to official company application portal',
    severity: 'positive'
  },

  // ========================================
  // === JOB DETAILS & REQUIREMENTS ===
  // ========================================
  {
    pattern: /bachelor'?s? degree|master'?s? degree|mba|phd|professional (certification|license)/i,
    score: -10,
    reason: 'Requires formal education or professional certifications',
    severity: 'positive'
  },
  {
    pattern: /\d+[\+]? years? (of )?experience|minimum \d+ years?|at least \d+ years?/i,
    score: -8,
    reason: 'Specifies minimum years of experience required',
    severity: 'positive'
  },
  {
    pattern: /job description|responsibilities|qualifications|requirements|duties/i,
    score: -6,
    reason: 'Contains detailed job description sections',
    severity: 'positive'
  },
  {
    pattern: /competitive salary|salary range|compensation package|\$\d{2},\d{3}\s*-\s*\$\d{2},\d{3}/i,
    score: -8,
    reason: 'Provides specific, reasonable salary range',
    severity: 'positive'
  },
  {
    pattern: /full[- ]?time|part[- ]?time|contract|temporary|permanent|w-?2|1099/i,
    score: -5,
    reason: 'Specifies standard employment type',
    severity: 'positive'
  },

  // ========================================
  // === COMPANY INFORMATION ===
  // ========================================
  {
    pattern: /fortune \d{3}|nasdaq|nyse|publicly traded|s&p \d{3}/i,
    score: -15,
    reason: 'References major stock exchange or Fortune ranking',
    severity: 'strong-positive'
  },
  {
    pattern: /established \d{4}|since \d{4}|founded in \d{4}|over \d+ years in business/i,
    score: -8,
    reason: 'Mentions company founding date or years in business',
    severity: 'positive'
  },
  {
    pattern: /office locations?|headquarters|branch office|regional office/i,
    score: -6,
    reason: 'References physical office locations',
    severity: 'positive'
  },

  // ========================================
  // === LEGAL & COMPLIANCE ===
  // ========================================
  {
    pattern: /drug[- ]?free workplace|smoke[- ]?free|background check required/i,
    score: -5,
    reason: 'Standard workplace policy statements',
    severity: 'positive'
  },
  {
    pattern: /confidentiality agreement|nda|non[- ]?disclosure|proprietary information/i,
    score: -6,
    reason: 'Mentions standard confidentiality or NDA requirements',
    severity: 'positive'
  },
  {
    pattern: /apply before|application deadline|position closes|accepting applications until/i,
    score: -5,
    reason: 'Provides clear application deadline',
    severity: 'positive'
  }
];

/**
 * Enhanced Analysis Function with severity tracking
 */
function analyzeJobPost(text) {
  if (!text || typeof text !== 'string') {
    return { error: 'Invalid input' };
  }

  let totalScore = 0;
  const triggers = [];
  const severityCounts = {
    critical: 0,
    high: 0,
    'medium-high': 0,
    medium: 0,
    'low-medium': 0,
    low: 0
  };

  // Red Flags
  for (const flag of redFlags) {
    if (flag.pattern.test(text)) {
      totalScore += flag.score;
      triggers.push({ 
        type: 'red', 
        score: flag.score, 
        reason: flag.reason,
        severity: flag.severity 
      });
      if (severityCounts.hasOwnProperty(flag.severity)) {
        severityCounts[flag.severity]++;
      }
    }
  }

  // Positive Signals
  for (const signal of positiveSignals) {
    if (signal.pattern.test(text)) {
      totalScore += signal.score;
      triggers.push({ 
        type: 'positive', 
        score: signal.score, 
        reason: signal.reason,
        severity: signal.severity 
      });
    }
  }

  // Clamp score
  totalScore = Math.max(0, Math.min(100, Math.round(totalScore)));

  // Enhanced Risk Level with more granular classification
  let riskLevel = 'LOW';
  let confidence = 'medium';

  if (totalScore >= 70) {
    riskLevel = 'VERY HIGH';
    confidence = 'high';
  } else if (totalScore >= 55) {
    riskLevel = 'HIGH';
    confidence = 'high';
  } else if (totalScore >= 40) {
    riskLevel = 'MEDIUM-HIGH';
    confidence = 'medium';
  } else if (totalScore >= 25) {
    riskLevel = 'MEDIUM';
    confidence = 'medium';
  } else if (totalScore >= 15) {
    riskLevel = 'SUSPICIOUS';
    confidence = 'low';
  }

  return {
    totalScore,
    riskLevel,
    confidence,
    isLikelyScam: totalScore >= 50,
    isDefiniteScam: totalScore >= 70,
    triggers: triggers.slice(0, 20), // Increased limit
    redFlagCount: triggers.filter(t => t.type === 'red').length,
    positiveCount: triggers.filter(t => t.type === 'positive').length,
    severityCounts,
    criticalFlags: severityCounts.critical,
    highFlags: severityCounts.high
  };
}

module.exports = {
  redFlags,
  positiveSignals,
  analyzeJobPost
};