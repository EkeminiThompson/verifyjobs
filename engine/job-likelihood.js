// job-likelihood.js — Is this text actually a job posting?
// Run BEFORE fraud scoring. Non-jobs should not get scam/legit scores.

'use strict';

/**
 * Lightweight rule-based job-likelihood assessment.
 * Returns { isJob, confidence, score 0–100, reasons[], signals }.
 *
 * score >= 55 → treat as job
 * score 35–54 → maybe job (still run fraud scoring, flag uncertainty)
 * score < 35  → not a job (early return)
 */

const JOB_POSITIVE = [
  { re: /\b(job\s*(title|description|posting|opening|vacancy|opportunity)|position\s*(title|available|open)|we('re| are)\s+hiring|now\s+hiring|apply\s+(now|today|here|online)|how\s+to\s+apply)\b/i, w: 18, label: 'Hiring / apply language' },
  { re: /\b(responsibilit(y|ies)|requirements?|qualifications?|duties|what\s+you('ll| will)\s+do|role\s+overview|about\s+the\s+(role|position|job))\b/i, w: 16, label: 'Job structure sections' },
  { re: /\b(full[- ]?time|part[- ]?time|contract|internship|permanent|temporary|remote|hybrid|on[- ]?site|work\s+from\s+home)\b/i, w: 12, label: 'Employment type / location' },
  { re: /\b(salary|compensation|pay\s+range|benefits|per\s+(annum|year|month|hour)|\$\d|£\d|€\d|₦\d)\b/i, w: 10, label: 'Compensation language' },
  { re: /\b(years?\s+of\s+experience|bachelor'?s?|master'?s?|degree|preferred\s+qualifications?|must\s+have|nice\s+to\s+have)\b/i, w: 10, label: 'Experience / education requirements' },
  { re: /\b(recruiter|hiring\s+manager|talent\s+acquisition|careers?\s+page|join\s+(our|the)\s+team)\b/i, w: 8, label: 'Recruitment context' },
  { re: /\b(cv|resume|cover\s+letter|application|candidates?\s+(will|should|must))\b/i, w: 8, label: 'Application materials' },
  { re: /\b(report(s|ing)?\s+to|team\s+of|collaborat(e|ion)|stakeholders?)\b/i, w: 6, label: 'Team / reporting structure' },
];

const NON_JOB_STRONG = [
  { re: /\b(privacy\s+policy|terms\s+of\s+(service|use)|cookie\s+policy|refund\s+policy)\b/i, w: 40, label: 'Legal / policy page' },
  { re: /\b(invoice|receipt|order\s+#|tracking\s+number|shipping\s+address)\b/i, w: 35, label: 'Invoice / commerce' },
  { re: /\b(dear\s+(sir|madam|friend)|i\s+hope\s+this\s+(email|message)\s+finds\s+you|as\s+per\s+our\s+conversation)\b/i, w: 25, label: 'Generic email / letter' },
  { re: /\b(my\s+name\s+is|i\s+am\s+a\s+(student|graduate)|objective\s*:|education\s*:|work\s+experience\s*:)\b/i, w: 30, label: 'Resume / CV content' },
  { re: /\b(how\s+to\s+spot\s+a\s+(job\s+)?scam|warning\s+signs\s+of\s+(employment\s+)?fraud|scam\s+checker|this\s+(tool|page)\s+(checks|detects))\b/i, w: 45, label: 'Educational / tool content about scams' },
  { re: /\b(subscribe\s+to\s+(our\s+)?newsletter|follow\s+us\s+on|share\s+this\s+(article|post)|leave\s+a\s+comment)\b/i, w: 25, label: 'Blog / social content' },
  { re: /\b(add\s+to\s+cart|buy\s+now|free\s+shipping|product\s+description|sku\s*:)\b/i, w: 35, label: 'E-commerce product page' },
];

const NON_JOB_MILD = [
  { re: /\b(about\s+us|our\s+mission|our\s+story|company\s+history|founded\s+in)\b/i, w: 8, label: 'Company about page tone' },
  { re: /\b(breaking\s+news|published\s+on|author\s*:|read\s+more)\b/i, w: 12, label: 'News / article tone' },
];

function assessJobLikelihood(text, jobTitle = '') {
  const t = String(text || '');
  const title = String(jobTitle || '').trim();
  const reasons = [];
  const signals = { positive: [], negative: [] };

  let score = 20; // neutral baseline — short ambiguous text stays low

  // Title hints
  if (title && title.length > 2 && !/^(untitled|unknown|file|document|image)/i.test(title)) {
    if (/\b(engineer|developer|manager|analyst|assistant|coordinator|specialist|officer|intern|director|designer|accountant|nurse|teacher|driver|sales|marketing|hr|recruiter)\b/i.test(title)) {
      score += 15;
      signals.positive.push('Job-like title');
      reasons.push('Title looks like a role name');
    } else if (/verifyjobs|scam\s*check|how\s+it\s+works|privacy|about/i.test(title)) {
      score -= 20;
      signals.negative.push('Non-job page title');
    }
  }

  for (const p of JOB_POSITIVE) {
    if (p.re.test(t)) {
      score += p.w;
      signals.positive.push(p.label);
      if (reasons.length < 4) reasons.push(p.label);
    }
  }

  for (const n of NON_JOB_STRONG) {
    if (n.re.test(t)) {
      score -= n.w;
      signals.negative.push(n.label);
      reasons.push(n.label);
    }
  }

  for (const n of NON_JOB_MILD) {
    if (n.re.test(t)) {
      score -= n.w;
      signals.negative.push(n.label);
    }
  }

  // Length heuristics
  const words = t.split(/\s+/).filter(Boolean).length;
  if (words < 25) {
    score -= 15;
    signals.negative.push('Very short text');
  } else if (words >= 80 && signals.positive.length >= 2) {
    score += 8;
  }

  // Strong job structure: requirements + responsibilities together
  if (/requirements?:/i.test(t) && /responsibilit/i.test(t)) {
    score += 12;
    signals.positive.push('Requirements + responsibilities structure');
  }

  score = Math.max(0, Math.min(100, score));

  let isJob;
  let confidence;
  if (score >= 55) {
    isJob = true;
    confidence = score >= 70 ? 'high' : 'medium';
  } else if (score >= 35) {
    isJob = true; // still run fraud scoring, but flag uncertainty
    confidence = 'low';
  } else {
    isJob = false;
    confidence = score <= 20 ? 'high' : 'medium';
  }

  // Hard override: educational scam-checker content
  if (/how\s+to\s+spot\s+a\s+(job\s+)?scam|job\s+scam\s+checker|verifyjobs/i.test(t) &&
      !/\b(we\s+are\s+hiring|apply\s+now|job\s+title\s*:)/i.test(t)) {
    isJob = false;
    confidence = 'high';
    score = Math.min(score, 15);
    if (!signals.negative.includes('Educational / tool content about scams')) {
      signals.negative.push('Educational / tool content about scams');
      reasons.unshift('Looks like educational or tool content, not a job ad');
    }
  }

  return {
    isJob,
    confidence,
    score,
    reasons: reasons.slice(0, 5),
    signals,
  };
}

/**
 * Build a full analysis-shaped result for non-job input.
 */
function buildNotAJobResult(jobCheck, jobTitle, source, text) {
  const explanation =
    jobCheck.reasons.length > 0
      ? `This does not appear to be a job posting. Signals: ${jobCheck.reasons.slice(0, 3).join('; ')}. Scam checks are designed for job advertisements, not general web pages, resumes, or chat messages.`
      : 'This does not appear to be a job posting. Paste a job description, offer letter, or recruiting message to check for scam indicators.';

  const result = {
    status: 'not_a_job',
    statusLabel: 'Not a job posting',
    riskScore: 0,
    legitimacyScore: 0,

    jobStatus: 'Unknown',
    jobStatusMeta: { color: '#6b7280', icon: '📄', badge: 'Not a job posting' },
    isAcceptingApplications: false,
    jobStatusConfidence: 'n/a',
    jobStatusInferred: false,

    freshness: {
      score: null,
      staleness: null,
      label: 'N/A',
      signals: [],
    },

    redFlags: [],
    positiveIndicators: [],

    explanation,
    recommendation:
      'This input does not look like a job ad. If you meant to check a job offer, paste the full job description, recruiting email, or WhatsApp message instead.',
    actionItems: [
      'Paste the full job description or offer text',
      'Or upload a PDF / Word job posting',
      'Or submit the URL of the job listing on a careers site',
      'For general scam advice, see the Report a Scam page',
    ],

    jobLikelihood: {
      isJob: false,
      confidence: jobCheck.confidence,
      score: jobCheck.score,
      reasons: jobCheck.reasons,
      signals: jobCheck.signals,
    },

    metadata: {
      redFlagCount: 0,
      positiveCount: 0,
      contextPenalty: 0,
      contextBonus: 0,
      netContextAdjustment: 0,
      contextFlags: [],
      originalLength: (text || '').length,
      cleanedLength: (text || '').length,
      wordCount: String(text || '').split(/\s+/).filter(Boolean).length,
      hasEmail: false,
      hasFreeEmail: false,
      hasPhone: false,
      hasURL: false,
      hasSalary: false,
      hasLocation: false,
      hasCompanyName: false,
      analysisTimestamp: new Date().toISOString(),
      notAJob: true,
    },
  };

  return result;
}

module.exports = {
  assessJobLikelihood,
  buildNotAJobResult,
};
