// decision.js — Turn risk scores into clear customer guidance
// Use from analyzer.js after scoring, or from the frontend as a fallback.

/**
 * Known scam pattern detectors (plain-language labels for users).
 * Order matters: first match wins as primary pattern.
 */
const SCAM_PATTERNS = [
  {
    id: 'advance_fee',
    label: 'Advance-fee scam',
    test: (text, flags) =>
      /upfront|registration fee|training fee|starter kit|equipment fee|background check fee|pay (to |before )?(apply|start|work)|gift ?card|western union|moneygram/i.test(text) ||
      flags.some(f => /upfront|fee|payment|pay /i.test(f)),
  },
  {
    id: 'task_scam',
    label: 'Task / micro-job scam',
    test: (text, flags) =>
      /data entry|captcha|like and subscribe|product rating|app install|daily task|earn \$?\d+ per (day|task|hour)/i.test(text) ||
      flags.some(f => /data entry|typing|survey|task/i.test(f)),
  },
  {
    id: 'fake_recruiter',
    label: 'Fake recruiter',
    test: (text, flags) =>
      /whatsapp only|telegram only|contact (me|us) on whatsapp|hr@gmail|recruiter@yahoo|@gmail\.com|@yahoo\.com/i.test(text) ||
      flags.some(f => /whatsapp|telegram|free email|gmail|yahoo/i.test(f)),
  },
  {
    id: 'identity_harvest',
    label: 'Identity / document harvest',
    test: (text, flags) =>
      /send (your )?(passport|id card|national id|bvn|nin|ssn|bank statement|utility bill)|scan of (your )?id/i.test(text) ||
      flags.some(f => /passport|identity|document|bvn|nin|ssn|bank/i.test(f)),
  },
  {
    id: 'crypto_job',
    label: 'Crypto / investment job scam',
    test: (text, flags) =>
      /crypto|bitcoin|forex|trading signal|investment (manager|advisor)|guaranteed (return|profit)/i.test(text) ||
      flags.some(f => /crypto|bitcoin|forex|invest/i.test(f)),
  },
  {
    id: 'urgency_pressure',
    label: 'High-pressure urgency scam',
    test: (text, flags) =>
      /act now|limited slots|only \d+ spots|today only|urgent hiring|immediate start.*pay/i.test(text) ||
      flags.some(f => /urgenc|pressure|act now/i.test(f)),
  },
];

function normalizeFlags(list) {
  if (!Array.isArray(list)) return [];
  return list
    .map(f => (typeof f === 'string' ? f : f.signal || f.label || f.reason || f.message || ''))
    .filter(Boolean);
}

/**
 * Build a customer-facing decision object from an analysis result.
 * @param {object} result - Output from analyzeJob / API
 * @param {string} [rawText] - Optional original text for pattern detection
 */
function buildDecision(result, rawText = '') {
  const risk = Number(result.riskScore ?? result.risk_score ?? 50);
  const flags = normalizeFlags(result.redFlags || result.red_flags || []);
  const positives = normalizeFlags(
    result.positiveIndicators || result.positiveSignals || result.positives || []
  );
  const text = String(rawText || result.explanation || '').slice(0, 20000);

  // ── Verdict ──────────────────────────────────────
  let verdict;
  let verdictLabel;
  let verdictTone; // danger | warn | safe

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
    verdictLabel = 'Looks OK';
    verdictTone = 'safe';
  }

  // Override if status already says definite scam with high confidence
  const status = String(result.status || '').toLowerCase();
  if (status.includes('definite') || status.includes('scam') && risk >= 55) {
    if (risk >= 55) {
      verdict = 'dont_apply';
      verdictLabel = "Don't apply";
      verdictTone = 'danger';
    }
  }

  // ── Top 3 reasons (plain language) ───────────────
  const reasons = [];

  if (flags.length) {
    // Prefer real red flags, shortened
    for (const f of flags) {
      if (reasons.length >= 3) break;
      reasons.push(plainReason(f, 'flag'));
    }
  }

  if (reasons.length < 3 && risk >= 45) {
    reasons.push('Several warning signs appear together — treat this as high risk until proven otherwise.');
  }

  if (reasons.length < 3 && positives.length && risk < 45) {
    for (const p of positives) {
      if (reasons.length >= 3) break;
      reasons.push(plainReason(p, 'positive'));
    }
  }

  if (reasons.length === 0) {
    if (risk < 25) {
      reasons.push('No major scam indicators were detected in the text provided.');
    } else {
      reasons.push('Some mixed signals — independent verification is still recommended.');
    }
  }

  // ── Known scam pattern ───────────────────────────
  let scamPattern = null;
  if (risk >= 40) {
    for (const p of SCAM_PATTERNS) {
      if (p.test(text, flags)) {
        scamPattern = { id: p.id, label: p.label };
        break;
      }
    }
  }

  // ── What to do next ──────────────────────────────
  const nextSteps = [];

  if (verdict === 'dont_apply') {
    nextSteps.push('Do not send money, gift cards, crypto, or bank details.');
    nextSteps.push('Do not share passport, national ID, BVN, NIN, or SSN.');
    nextSteps.push('Stop contact and keep screenshots as evidence.');
    nextSteps.push('Report the listing on the platform where you found it.');
    nextSteps.push('Report to local authorities if you already lost money (FTC, Action Fraud, EFCC, etc.).');
  } else if (verdict === 'verify_first') {
    nextSteps.push('Find the company via Google — do not trust links inside the message.');
    nextSteps.push('Check the company on LinkedIn and whether real employees list it.');
    nextSteps.push('Confirm the email domain matches the official website.');
    nextSteps.push('Never pay for training, equipment, or “background checks” before day one.');
    nextSteps.push('Search the job title in quotes plus “scam” to see if it was copied elsewhere.');
  } else {
    nextSteps.push('Still confirm the company on its official careers page.');
    nextSteps.push('Review Glassdoor / Indeed ratings before accepting an offer.');
    nextSteps.push('Never pay fees to start work — legitimate employers do not charge you to get hired.');
  }

  // Cap next steps at 5 for UI
  const limitedSteps = nextSteps.slice(0, 5);

  return {
    verdict,
    verdictLabel,
    verdictTone,
    topReasons: reasons.slice(0, 3),
    nextSteps: limitedSteps,
    scamPattern, // { id, label } or null
    // Short one-liner for cards / notifications
    summary:
      verdict === 'dont_apply'
        ? scamPattern
          ? `Don't apply — looks like a ${scamPattern.label.toLowerCase()}.`
          : "Don't apply — strong scam indicators."
        : verdict === 'verify_first'
        ? scamPattern
          ? `Verify first — possible ${scamPattern.label.toLowerCase()}.`
          : 'Verify first — warning signs present.'
        : 'Looks OK — still do basic company checks.',
  };
}

function plainReason(text, kind) {
  let t = String(text).trim();
  // Strip emoji prefixes and rule-id style noise
  t = t.replace(/^[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\s]+/u, '');
  t = t.replace(/^[🚨⚠️✓✅🛑📱🚔🔍💼🔎📧⭐🤝❌📅]+\s*/u, '');
  if (t.length > 120) t = t.slice(0, 117) + '…';
  if (kind === 'positive' && !/^(has |includes |mentions |lists |uses |official)/i.test(t)) {
    // keep as-is; positives are already mostly plain
  }
  return t;
}

module.exports = { buildDecision, SCAM_PATTERNS };
