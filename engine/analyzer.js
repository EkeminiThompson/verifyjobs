// enhanced-analyzer.js — VerifyJobs v1.4
// Rewritten for real-world accuracy. Fixes over-penalising of legitimate postings.

const { redFlags, positiveSignals } = require('./rules');
const { analyzeJobFreshness } = require('./job-freshness');
const { normalizeScore, getStatus, getStatusLabel } = require('./scorer');
const { addAnalysis } = require('./storage');
const { buildDecision } = require('./decision');

// ─────────────────────────────────────────────
// JOB STATUS DETECTION
// ─────────────────────────────────────────────

/**
 * STATUS_COLORS maps job status to a hex colour and icon for the UI.
 * Export these so index.html's showResults() can use them directly.
 */
const JOB_STATUS_META = {
  'Open':           { color: '#1a7a45', icon: '🟢', badge: 'Accepting Applications' },
  'Under Review':   { color: '#2563eb', icon: '🔵', badge: 'Applications Under Review' },
  'Interviewing':   { color: '#7c3aed', icon: '🟣', badge: 'Interviewing Candidates' },
  'Offer Sent':     { color: '#d97706', icon: '🟡', badge: 'Offer Extended' },
  'Filled':         { color: '#4b5563', icon: '⚫', badge: 'Position Filled' },
  'Closed':         { color: '#dc2626', icon: '🔴', badge: 'No Longer Accepting Applications' },
  'On Hold':        { color: '#ea580c', icon: '🟠', badge: 'Hiring Paused' },
  'Cancelled':      { color: '#991b1b', icon: '🚫', badge: 'Position Cancelled' },
  'Expired':        { color: '#9ca3af', icon: '⬜', badge: 'Posting Expired' },
  'Unknown':        { color: '#d1d5db', icon: '❓', badge: 'Status Unknown' },
};

function detectJobStatus(text) {
  const patterns = {
    'Open':         /\b(accepting applications?|now hiring|currently hiring|we('re| are) hiring|apply now|positions? (available|open)|open role|open position)\b/i,
    'Under Review': /\b(applications? under review|currently reviewing|reviewing (candidates|applications?))\b/i,
    'Interviewing': /\b(currently interviewing|scheduling interviews?|interview stage|actively interviewing)\b/i,
    'Offer Sent':   /\b(offer (extended|sent|made)|in the offer stage)\b/i,
    'Filled':       /\b(position (has been )?filled|role (has been )?filled|no longer (accepting|hiring)|successfully filled)\b/i,
    'Closed':       /\b(position closed|applications? closed|no longer available|posting closed|this (role|position) is closed)\b/i,
    'On Hold':      /\b(on hold|hiring (on hold|paused|suspended)|temporarily (paused|suspended|on hold))\b/i,
    'Cancelled':    /\b((position|job|opening|role) cancelled|we('ve| have) cancelled)\b/i,
    'Expired':      /\b(expired|posting expired|deadline (passed|has passed|expired))\b/i,
  };

  for (const [status, pattern] of Object.entries(patterns)) {
    if (pattern.test(text)) {
      const isAccepting = ['Open', 'Under Review'].includes(status);
      return { status, isAcceptingApplications: isAccepting, confidence: 'medium', meta: JOB_STATUS_META[status] };
    }
  }

  return {
    status: 'Unknown',
    isAcceptingApplications: true, // safe assumption: assume open unless stated
    confidence: 'low',
    meta: JOB_STATUS_META['Unknown'],
  };
}

// ─────────────────────────────────────────────
// CONTEXT ANALYSIS — real-world calibrated
// ─────────────────────────────────────────────

function contextAnalysis(text) {
  let penalty = 0;
  let bonus = 0;
  const contextFlags = [];

  // ── MESSAGING APP SIGNALS ──────────────────
  // WhatsApp as ONLY channel is a major red flag.
  // WhatsApp mentioned alongside legitimate context is less so.
  const hasWhatsApp   = /whatsapp/i.test(text);
  const hasTelegram   = /telegram/i.test(text);
  const hasSignal     = /\bsignal\b/i.test(text);

  // Strong penalty only when messaging app is the *primary* or *only* contact method
  if (/contact\s+(only|us)?\s*(via|on|through|over)\s*whatsapp/i.test(text) ||
      /whatsapp\s+only/i.test(text) ||
      /reach\s+(us|out|me)?\s*(via|on|at)?\s*whatsapp/i.test(text)) {
    penalty += 30;
    contextFlags.push('WhatsApp listed as sole contact channel');
  } else if (hasWhatsApp) {
    // Mentioned in passing — mild concern
    penalty += 10;
    contextFlags.push('WhatsApp mentioned');
  }

  if (/contact\s+(only|us)?\s*(via|on|through|over)\s*telegram/i.test(text) ||
      /telegram\s+only/i.test(text)) {
    penalty += 30;
    contextFlags.push('Telegram listed as sole contact channel');
  } else if (hasTelegram) {
    penalty += 10;
    contextFlags.push('Telegram mentioned');
  }

  if (hasSignal) {
    penalty += 8;
    contextFlags.push('Signal mentioned');
  }

  // Source field – job received via messaging app
  if (/source:\s*(whatsapp|telegram|dm|direct message)/i.test(text)) {
    penalty += 20;
    contextFlags.push('Job received via messaging app');
  }

  // ── ONLINE PRESENCE CHECK — FIXED FOR .ai, .io, .co etc ──
  // Only penalise if there is genuinely *no* web/URL signal at all.
  const hasOnlinePresence = /(https?:\/\/|www\.|\.com|\.org|\.net|\.io|\.ai|\.co\b|\.gov|\.edu|linkedin\.com|official|careers|website|our\s+site|apply\s+at)/i.test(text);
  if (!hasOnlinePresence) {
    penalty += 14;
    contextFlags.push('No official website or online presence mentioned');
  }

  // ── DESCRIPTION LENGTH vs REMOTE/ENTRY CLAIMS ──
  if (text.length < 120 && /work from home|remote|earn|data entry|typing/i.test(text)) {
    penalty += 20;
    contextFlags.push('Very short description for a remote/entry-level posting');
  } else if (text.length < 250 && /earn|make money|income|payment/i.test(text)) {
    penalty += 8;
    contextFlags.push('Brief posting with income claims');
  }

  // ── EMOJI OVERUSE (scam posts often loaded with emojis) ──
  const emojiCount = (text.match(/[\u{1F300}-\u{1F9FF}]|[\u{2600}-\u{26FF}]/gu) || []).length;
  if (emojiCount > 10) {
    penalty += 12;
    contextFlags.push(`Heavy emoji use (${emojiCount} emojis detected)`);
  } else if (emojiCount > 5) {
    penalty += 5;
    contextFlags.push(`Elevated emoji count (${emojiCount})`);
  }

  // ── GRAMMAR / QUALITY SIGNALS ──
  const grammarIssues = [
    /[a-z]{20,}/i,           // implausibly long words (bad translation artifacts)
    /\.{4,}|!{3,}/,          // excessive ellipsis or exclamation
    /\b(kindly|revert back|do the needful|at the earliest)\b/i, // non-native phrases
  ];
  const grammarErrorCount = grammarIssues.filter(p => p.test(text)).length;
  if (grammarErrorCount >= 2) {
    penalty += 8;
    contextFlags.push('Multiple grammar or translation quality issues');
  }

  // ── POSITIVE CONTEXT INDICATORS ──

  // Physical address
  if (/\d+\s+[A-Z][a-z]+\s+(street|st\.?|avenue|ave\.?|road|rd\.?|boulevard|blvd\.?|lane|drive|dr\.?)/i.test(text)) {
    bonus += 10;
    contextFlags.push('Specific physical address mentioned');
  }

  // Industry-standard tooling (real companies name their stack)
  if (/(salesforce|microsoft|oracle|aws|azure|google cloud|sap|workday|slack|jira|zendesk)/i.test(text)) {
    bonus += 8;
    contextFlags.push('Industry-standard tools or platforms referenced');
  }

  // Team / reporting structure
  if (/(report(s)? (to|directly)|direct reports?|team of \d+|join (our|a) team of|collaborate with)/i.test(text)) {
    bonus += 6;
    contextFlags.push('Team structure or reporting line described');
  }

  // Comprehensive job post structure (all three sections present)
  const hasRequirements    = /requirements?:/i.test(text);
  const hasQualifications  = /qualifications?:/i.test(text);
  const hasResponsibilities = /responsibilities:/i.test(text);
  if (hasRequirements && hasResponsibilities) {
    bonus += 8;
    contextFlags.push('Structured job posting with dedicated sections');
  }
  if (hasQualifications) {
    bonus += 4;
    contextFlags.push('Qualifications section present');
  }

  // Legitimate major careers domains
  if (/(linkedin\.com\/(jobs|company)|greenhouse\.io|lever\.co|workday\.com|bamboohr\.com|ashbyhq\.com|jobs\.lever\.co)/i.test(text)) {
    bonus += 14;
    contextFlags.push('Listed on known legitimate ATS or job platform');
  }

  // Company tenure / founding info
  if (/(founded|established|since)\s+\d{4}/i.test(text)) {
    bonus += 5;
    contextFlags.push('Company founding date mentioned');
  }

  return {
    netPenalty: penalty - bonus,
    penalty,
    bonus,
    contextFlags,
  };
}

// ─────────────────────────────────────────────
// TEXT UTILITIES
// ─────────────────────────────────────────────

function cleanText(text) {
  return text
    .replace(/\r\n|\r/g, '\n')
    .replace(/\t+/g, ' ')
    .replace(/[ ]{2,}/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function extractMetadata(text) {
  return {
    hasEmail:       /@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/.test(text),
    hasFreeEmail:   /@(gmail|yahoo|hotmail|outlook|protonmail|mail\.com|yandex)\./i.test(text),
    hasPhone:       /(\+?\d[\d\s\-().]{7,}\d)/.test(text),
    hasURL:         /https?:\/\/[^\s]+/.test(text),
    hasSalary:      /\$\d{2,3}[,k]|\bsalary\b|\bcompensation\b|\bpay\b/i.test(text),
    hasLocation:    /\b[A-Z][a-z]+,\s*[A-Z]{2}\b|remote|work from home|hybrid/i.test(text),
    hasCompanyName: /company[:\s]|employer[:\s]|organization[:\s]|about\s+us/i.test(text),
    wordCount:      text.split(/\s+/).filter(Boolean).length,
  };
}

// ─────────────────────────────────────────────
// EXPLANATION & RECOMMENDATION GENERATORS
// ─────────────────────────────────────────────

function buildExplanation(score, redCount, positiveCount, contextResult) {
  const contextSummary = contextResult.contextFlags.length
    ? ` Context flags: ${contextResult.contextFlags.slice(0, 3).join('; ')}.`
    : '';

  if (score >= 75) {
    return `This posting has ${redCount} serious red flag${redCount !== 1 ? 's' : ''} and matches well-documented employment fraud patterns.${contextSummary} The combination of indicators makes this almost certainly a scam.`;
  }
  if (score >= 55) {
    return `This posting has ${redCount} significant warning sign${redCount !== 1 ? 's' : ''}.${contextSummary}${positiveCount > 0 ? ` While ${positiveCount} positive indicator${positiveCount !== 1 ? 's were' : ' was'} found, the red flags outweigh them substantially.` : ''} Extreme caution is warranted.`;
  }
  if (score >= 40) {
    return `This posting shows ${redCount} concern${redCount !== 1 ? 's' : ''} that warrant careful verification.${contextSummary}${positiveCount >= 3 ? ` Some legitimate signals (${positiveCount}) are present, but risks remain.` : ''} Do not proceed without independent research.`;
  }
  if (score >= 20) {
    return `This posting has ${redCount} minor concern${redCount !== 1 ? 's' : ''}.${contextSummary}${positiveCount >= 2 ? ` Positive indicators (${positiveCount}) suggest this may be legitimate.` : ''} Standard due diligence is recommended.`;
  }
  return `This posting appears relatively safe — ${redCount === 0 ? 'no' : redCount} red flag${redCount !== 1 ? 's were' : ' was'} detected.${positiveCount >= 3 ? ` Multiple positive signals (${positiveCount}) indicate professional legitimacy.` : ''} Always verify company information independently before accepting any offer.`;
}

function buildRecommendation(score, jobStatus) {
  let rec;
  if (score >= 75) {
    rec = '🚨 AVOID COMPLETELY. Do not respond, send money, or share personal information. This posting exhibits overwhelming scam indicators.';
  } else if (score >= 55) {
    rec = '⚠️ HIGH RISK. Do not proceed without verifying the company through its official website — not the contact details in this posting. Never pay fees of any kind.';
  } else if (score >= 40) {
    rec = '⚡ CAUTION. Verify the company through independent sources before engaging. Never pay upfront fees for training, equipment, or background checks.';
  } else if (score >= 20) {
    rec = '✓ POTENTIALLY LEGITIMATE. Verify the company on Glassdoor and LinkedIn, and confirm job details through the official company website.';
  } else {
    rec = '✓ APPEARS LEGITIMATE. Conduct standard due diligence: confirm the company website, read reviews, and verify the recruiter on LinkedIn.';
  }

  if (!jobStatus.isAcceptingApplications && jobStatus.status !== 'Unknown') {
    rec += ` ⚠️ Note: This position appears to be ${jobStatus.status.toUpperCase()} and may not be accepting applications.`;
  }

  return rec;
}

function buildActionItems(score, metadata, jobStatus) {
  const actions = [];

  if (score >= 55) {
    actions.push('🛑 DO NOT send money, gift cards, or cryptocurrency under any circumstances');
    actions.push('🛑 DO NOT share your bank account, BVN, NIN, or passport details');
    actions.push('📱 Report this posting to the platform where you found it');
    actions.push('🚔 File a report: FTC (USA) · EFCC / NITDA (Nigeria) · Action Fraud (UK)');
  }

  if (score >= 40) {
    actions.push('⚠️ Search "[company name] scam" on Google and check ScamPulse, BBB Scam Tracker');
  }

  if (metadata.hasCompanyName || score < 55) {
    actions.push('🔍 Verify the company on its official website — search for it independently, don\'t use links in the posting');
    actions.push('💼 Find the company on LinkedIn and check whether employees list it on their profiles');
  }

  actions.push('🔎 Paste the job title + key phrases in quotes into Google to detect copy-paste scam postings');

  if (metadata.hasFreeEmail) {
    actions.push('📧 The email domain is a free provider (Gmail/Yahoo/etc.) — legitimate companies use branded email');
  } else if (metadata.hasEmail) {
    actions.push('📧 Confirm the email domain matches the company\'s official website exactly');
  }

  if (score < 40) {
    actions.push('⭐ Read company reviews on Glassdoor, Indeed, and Google before accepting any offer');
    actions.push('🤝 Contact the company directly through its official website to confirm this posting is genuine');
  }

  if (['Filled', 'Closed', 'Expired', 'Cancelled'].includes(jobStatus.status)) {
    actions.push(`📅 This position appears ${jobStatus.status.toLowerCase()} — check the company's careers page for current openings`);
  }

  actions.push('❌ Never pay for training, equipment, starter kits, or background checks before your first day of work');

  return actions;
}

// ─────────────────────────────────────────────
// MAIN ANALYSIS FUNCTION
// ─────────────────────────────────────────────

function analyzeJob(text, jobTitle = 'Untitled Job', source = 'Unknown') {
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      return {
        error: 'Invalid or empty job description',
        status: 'unverified',
        riskScore: 0,
      };
    }
   
    const clean = cleanText(text);
    let riskScore = 0;
    const redFlagsFound  = [];
    const positivesFound = [];
   
    // ── Red Flags ──────────────────────────────────
    for (const rule of redFlags) {
      if (rule.pattern.test(clean)) {
        riskScore += rule.score;
        redFlagsFound.push(rule.reason);
      }
    }
   
    // ── Positive Signals ────────────────────────────
    for (const rule of positiveSignals) {
      if (rule.pattern.test(clean)) {
        riskScore += rule.score;
        positivesFound.push(rule.reason);
      }
    }
   
    // ── Context Adjustments ─────────────────────────
    const contextResult = contextAnalysis(clean);
    riskScore += contextResult.netPenalty;
   
    // ── Freshness / Staleness Detection ─────────────
    // This runs AFTER context so it operates on clean text.
    // It is separate from fraud scoring — a stale job is not necessarily a scam.
    const freshness = analyzeJobFreshness(clean);
   
    // If the freshness detector is highly confident the role is closed,
    // override explicit-pattern jobStatus rather than leaving it Unknown.
    // detectJobStatus() still runs first for explicit signals ("position filled", etc.)
    const explicitStatus = detectJobStatus(clean);
   
    // Merge: explicit text signals win; freshness fills the gap when status is Unknown
    let jobStatus;
    if (explicitStatus.status !== 'Unknown') {
      // Trust explicit text patterns absolutely
      jobStatus = explicitStatus;
    } else {
      // Use freshness inference
      jobStatus = {
        status:                  freshness.status,
        isAcceptingApplications: freshness.isAccepting,
        confidence:              freshness.confidence,
        meta: {
          color: freshness.color,
          icon:  freshness.icon,
          badge: freshness.label,
        },
        inferred:        true,   // flag so UI can show "inferred" qualifier
        freshnessScore:  freshness.freshnessScore,
        stalenessScore:  freshness.stalenessScore,
        freshnessSignals: freshness.signals,
      };
    }
   
    // ── Metadata ────────────────────────────────────
    const metadata = extractMetadata(clean);
   
    // ── Normalise risk score ─────────────────────────
    riskScore = normalizeScore(riskScore);
   
    const status         = getStatus(riskScore);
    const explanation    = buildExplanation(riskScore, redFlagsFound.length, positivesFound.length, contextResult);
    const recommendation = buildRecommendation(riskScore, jobStatus);
    const actionItems    = buildActionItems(riskScore, metadata, jobStatus);
   
    const result = {
      status,
      statusLabel:     getStatusLabel(riskScore),
      riskScore,
      legitimacyScore: Math.max(0, 100 - riskScore),
   
      // Job status — now freshness-aware
      jobStatus:               jobStatus.status,
      jobStatusMeta:           jobStatus.meta,
      isAcceptingApplications: jobStatus.isAcceptingApplications,
      jobStatusConfidence:     jobStatus.confidence,
      jobStatusInferred:       jobStatus.inferred || false,
   
      // Freshness details (for UI display)
      freshness: {
        score:    freshness.freshnessScore,  // 0 = stale, 100 = very fresh
        staleness: freshness.stalenessScore, // 0 = fresh, 100 = stale
        label:    freshness.label,
        signals:  freshness.signals,         // top signals driving the verdict
      },
   
      redFlags:           redFlagsFound,
      positiveIndicators: positivesFound,
   
      explanation,
      recommendation,
      actionItems,
   
      metadata: {
        redFlagCount:         redFlagsFound.length,
        positiveCount:        positivesFound.length,
        contextPenalty:       contextResult.penalty,
        contextBonus:         contextResult.bonus,
        netContextAdjustment: contextResult.netPenalty,
        contextFlags:         contextResult.contextFlags,
        originalLength:       text.length,
        cleanedLength:        clean.length,
        wordCount:            metadata.wordCount,
        hasEmail:             metadata.hasEmail,
        hasFreeEmail:         metadata.hasFreeEmail,
        hasPhone:             metadata.hasPhone,
        hasURL:               metadata.hasURL,
        hasSalary:            metadata.hasSalary,
        hasLocation:          metadata.hasLocation,
        hasCompanyName:       metadata.hasCompanyName,
        analysisTimestamp:    new Date().toISOString(),
      },
    };

    // Customer-facing decision (verdict, top reasons, next steps, scam pattern)
    result.decision = buildDecision(result, clean);
   
    try {
      addAnalysis(result, jobTitle, source, text);
    } catch (err) {
      console.error('Storage error:', err.message);
    }
   
    return result;
  }  

module.exports = analyzeJob;
module.exports.JOB_STATUS_META = JOB_STATUS_META;
module.exports.detectJobStatus  = detectJobStatus;