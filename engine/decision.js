// decision.js — Calibrated guidance from analysis (truth-seeking)
// Prefer under-claiming over false certainty. Pattern labels need evidence.

'use strict';

/**
 * Primary scam pattern — first solid match wins.
 * Tests are intentionally stricter than loose keyword lists.
 */
const SCAM_PATTERNS = [
  {
    id: 'advance_fee',
    label: 'Advance-fee scam',
    test: (text, flags) =>
      /(?:pay|paid?|send).{0,24}(?:registration|training|equipment|starter|background\s*check|application|processing|medical)\s*fee|upfront\s+(?:fee|payment)|application\s+fee|processing\s+fee|medical\s+fee|starter\s+kit|western\s+union|moneygram|gift\s*cards?|pay\s+to\s*:|acct?\.?\s*name\s*:/i.test(text) ||
      flags.some(f => /upfront payment|registration fee|training fee|application, processing, or medical fee|payment to a named bank|untraceable payment|gift card|major organisation name used with a demand/i.test(f)),
  },
  {
    id: 'task_scam',
    label: 'Task / micro-job scam',
    test: (text, flags) =>
      /complete\s+tasks?\s+to\s+earn|daily\s+tasks?\s+to\s+earn|earn\s+\$?\d+\s+per\s+(?:task|day)|amazon\s+review\s+tasks?/i.test(text) ||
      flags.some(f => /task-based commission|daily task/i.test(f)),
  },
  {
    id: 'fake_recruiter',
    label: 'Fake recruiter pattern',
    test: (text, flags) =>
      /whatsapp\s+only|telegram\s+only|contact\s+(?:me|us)\s+only\s+on\s+whatsapp|interview\s+(?:via|on)\s+whatsapp/i.test(text) ||
      flags.some(f => /exclusively through messaging|interview.*messaging app/i.test(f)),
  },
  {
    id: 'identity_harvest',
    label: 'Identity / document harvest',
    test: (text, flags) =>
      /(?:send|share|upload).{0,40}(?:passport|bvn|nin|ssn|bank\s*account).{0,30}(?:whatsapp|telegram|before\s+you\s+start)/i.test(text) ||
      flags.some(f => /prematurely|via messaging app|identity or bank details via/i.test(f)),
  },
  {
    id: 'crypto_job',
    label: 'Crypto / trading job scam',
    test: (text, flags) =>
      /(?:guaranteed\s+(?:return|profit)|trading\s+signals?|forex\s+trading\s+job|crypto(?:currency)?\s+(?:trading\s+)?(?:job|work))/i.test(text) ||
      flags.some(f => /cryptocurrency payment|crypto wallets|guaranteed (?:return|profit)/i.test(f)),
  },
  {
    id: 'urgency_pressure',
    label: 'High-pressure urgency',
    test: (text, flags) =>
      /(?:urgent\s+hiring|limited\s+slots?|only\s+\d+\s+(?:positions?|slots?)|few\s+positions?\s+left).{0,40}(?:pay|fee|whatsapp|telegram)/i.test(text) ||
      (flags.filter(f => /urgenc|pressure|immediate hiring/i.test(f)).length >= 1 &&
        flags.some(f => /fee|whatsapp|telegram|payment|capital/i.test(f))),
  },
];

function normalizeFlags(list) {
  if (!Array.isArray(list)) return [];
  return list
    .map(f => (typeof f === 'string' ? f : f.signal || f.label || f.reason || f.message || ''))
    .filter(Boolean);
}

function plainReason(s, kind) {
  let t = String(s || '').trim();
  t = t.replace(/^[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\s]+/u, '');
  t = t.replace(/^[🚨⚠️✓✅🛑📱🚔🔍💼🔎📧⭐🤝❌📅]+\s*/u, '');
  if (t.length > 120) t = t.slice(0, 117) + '…';
  return t;
}

function detectPattern(text, flags) {
  for (const p of SCAM_PATTERNS) {
    try {
      if (p.test(text, flags)) return { id: p.id, label: p.label };
    } catch (_) { /* ignore bad regex edge */ }
  }
  return null;
}

/**
 * Build customer-facing decision. Language stays advisory — never omniscient.
 */
function buildDecision(result, rawText = '') {
  const risk = Number(result.riskScore ?? result.risk_score ?? 0);
  const flags = normalizeFlags(result.redFlags || result.red_flags || []);
  const positives = normalizeFlags(
    result.positiveIndicators || result.positiveSignals || result.positives || []
  );
  const text = String(
    rawText || result.originalText || result.metadata?.snippet || result.explanation || ''
  ).slice(0, 20000);

  const statusStr = String(result.status || '').toLowerCase();
  const notAJob =
    statusStr === 'not_a_job' ||
    statusStr === 'not_a_job_posting' ||
    result.metadata?.notAJob === true ||
    (result.jobLikelihood && result.jobLikelihood.isJob === false);

  if (notAJob) {
    const why = (result.jobLikelihood?.reasons || result.metadata?.contextFlags || []).slice(0, 3);
    return {
      verdict: 'not_applicable',
      verdictLabel: 'Not a job posting',
      verdictTone: 'neutral',
      topReasons: why.length
        ? why.map(r => plainReason(r))
        : ['The text does not look like a job or opportunity ad.'],
      nextSteps: [
        'Paste a full job, fellowship, or vacancy description.',
        'Or upload a PDF / Word posting.',
        'Or submit a direct careers / ATS URL (not only a homepage).',
        'Scam checks apply to job-like ads — not pure policy pages or resumes.',
      ],
      scamPattern: null,
      summary: 'Not a job posting — scam checks are for jobs and similar opportunities only.',
      confidenceNote: 'Classification is rule-based and can be wrong on unusual pages.',
    };
  }

  let verdict;
  let verdictLabel;
  let verdictTone;

  // Thresholds match product bands; labels avoid "proven scam" without hard proof
  if (risk >= 70) {
    verdict = 'dont_apply';
    verdictLabel = "Don't apply";
    verdictTone = 'danger';
  } else if (risk >= 45) {
    verdict = 'verify_first';
    verdictLabel = 'Verify first';
    verdictTone = 'warn';
  } else {
    verdict = 'looks_ok';
    verdictLabel = 'No strong scam signals';
    verdictTone = 'safe';
  }

  if ((statusStr.includes('definite') || statusStr === 'definite_scam') && risk >= 70) {
    verdict = 'dont_apply';
    verdictLabel = "Don't apply";
    verdictTone = 'danger';
  }

  const pattern = detectPattern(text, flags);

  // Reasons: evidence first, then calibrated synthesis
  const topReasons = [];
  flags.slice(0, 4).forEach(f => topReasons.push(plainReason(f, 'flag')));
  if (pattern && topReasons.length < 5) {
    topReasons.push('Pattern resembles: ' + pattern.label);
  }
  if (risk >= 45 && flags.length >= 2) {
    topReasons.push('Several warning signs appear together — verify independently before trusting the ad.');
  } else if (risk >= 45 && flags.length === 1) {
    topReasons.push('One strong warning sign — confirm through official channels before sharing data or money.');
  }
  if (risk < 45 && positives.length) {
    topReasons.push(plainReason(positives[0], 'positive'));
  }
  if (risk < 30 && flags.length === 0) {
    topReasons.push('No high-weight scam rules matched this text.');
  }
  if (!topReasons.length) {
    topReasons.push('Limited automated evidence either way — manual checks still matter.');
  }

  // Next steps by band — always include "we can be wrong"
  let nextSteps;
  if (verdict === 'dont_apply') {
    nextSteps = [
      'Do not send money, gift cards, crypto, or bank/ID details based on this ad.',
      'Ignore pressure to "pay to start" or to move the chat only to WhatsApp/Telegram.',
      'If you already paid or shared data, contact your bank and local fraud reporting channel.',
      'Search the organisation name + "scam" on an independent browser search.',
      'This is an automated assessment — rare false alarms exist; official career pages can still be checked carefully.',
    ];
  } else if (verdict === 'verify_first') {
    nextSteps = [
      'Find the organisation via an independent search — do not rely only on links inside the message.',
      'Prefer official careers / ATS domains (or known organisers for fellowships).',
      'Confirm any email domain matches the official website.',
      'Never pay for training, equipment, or "background checks" before a verified start.',
      'Automated flags can be wrong on unusual but real programmes — verify, then decide.',
    ];
  } else {
    nextSteps = [
      'Still confirm the employer or organiser on their official site or known channels.',
      'Be wary if contact suddenly moves to WhatsApp-only or asks for fees.',
      'Do not send ID or bank details until you are sure who you are dealing with.',
      'Absence of automated red flags is not a guarantee of legitimacy.',
    ];
  }

  let summary;
  if (verdict === 'dont_apply') {
    summary = pattern
      ? `High risk signals — pattern looks like: ${pattern.label}. Do not pay or share sensitive data.`
      : 'High risk signals from the rule engine. Do not pay or share sensitive data until independently verified.';
  } else if (verdict === 'verify_first') {
    summary = pattern
      ? `Verify first — possible ${pattern.label.toLowerCase()}. Confirm via official channels.`
      : 'Verify first — some warning signs need independent confirmation.';
  } else {
    summary = 'No strong automated scam signals — still do basic verification before applying or sharing data.';
  }

  // Soften if positives heavily outweigh few soft flags
  if (verdict === 'verify_first' && positives.length >= 4 && flags.length <= 1 && risk < 55) {
    summary += ' Several professional signals are also present.';
  }

  return {
    verdict,
    verdictLabel,
    verdictTone,
    topReasons: topReasons.slice(0, 5),
    nextSteps,
    scamPattern: pattern,
    summary,
    confidenceNote:
      'Advisory only. Rules and models miss some scams and occasionally flag real posts. Seek truth via official sources.',
    riskScore: risk,
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { buildDecision, SCAM_PATTERNS };
}
if (typeof globalThis !== 'undefined') {
  globalThis.VerifyJobsDecision = { buildDecision, SCAM_PATTERNS };
}
