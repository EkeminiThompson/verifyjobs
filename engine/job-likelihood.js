// job-likelihood.js — Is this text actually a job posting?
// Run BEFORE fraud scoring. Non-jobs should not get scam/legit scores.

'use strict';

/**
 * score >= 55 → job
 * score 35–54 → maybe job (still score for fraud)
 * score < 35  → not a job (early return)
 *
 * Opportunities in scope: jobs, vacancies, internships, fellowships,
 * scholarships, open calls, traineeships, apprenticeships.
 *
 * Critical: real career-site / ATS pages often include footers
 * ("Terms of use", "Scam warning", privacy). Those must NOT veto
 * clear job structure (duties, apply, job id, vacancy, etc.).
 */

const JOB_POSITIVE = [
  { re: /\b(job\s*(title|description|posting|opening|vacancy|opportunity|identification|info)|position\s*(title|available|open)|we('re| are)\s+hiring|now\s+hiring|apply\s+(now|today|here|online)|how\s+to\s+apply|application\s+procedure)\b/i, w: 18, label: 'Hiring / apply language' },
  // Fellowships, scholarships, grants, residencies, open calls — treat as job-like opportunities
  { re: /\b(fellowship|fellowships|scholarship|scholarships|grant\s+opportunity|open\s+call|call\s+for\s+(applications?|proposals?)|residency\s+programme|internship\s+programme|traineeship|apprenticeship)\b/i, w: 20, label: 'Fellowship / scholarship / open call' },
  { re: /\b(eligibility\s+criteria|selection\s+criteria|who\s+can\s+apply|award\s+(amount|value)|stipend|duration\s+of\s+(the\s+)?(fellowship|programme|program|internship))\b/i, w: 14, label: 'Opportunity eligibility / award structure' },
  { re: /\b(submit\s+(your\s+)?application|applications?\s+(are\s+)?(open|close|due)|deadline\s+to\s+apply|apply\s+by)\b/i, w: 12, label: 'Application deadline language' },
  { re: /\b(responsibilit(y|ies)|requirements?|qualifications?|duties(\s+and\s+responsibilities)?|what\s+you('ll| will)\s+do|role\s+overview|about\s+the\s+(role|position|job)|competencies|required\s+skills\s+and\s+experience)\b/i, w: 16, label: 'Job structure sections' },
  { re: /\b(full[- ]?time|part[- ]?time|contract|internship(\s+programme)?|permanent|temporary|remote|hybrid|on[- ]?site|work\s+from\s+home|home[- ]?based)\b/i, w: 12, label: 'Employment type / location' },
  { re: /\b(salary|compensation|pay\s+range|benefits|stipend|per\s+(annum|year|month|hour)|\$\d|£\d|€\d|₦\d)\b/i, w: 10, label: 'Compensation language' },
  { re: /\b(years?\s+of\s+experience|bachelor'?s?|master'?s?|degree|preferred\s+qualifications?|must\s+have|nice\s+to\s+have|postgraduate|university\s+degree)\b/i, w: 10, label: 'Experience / education requirements' },
  { re: /\b(recruiter|hiring\s+manager|talent\s+acquisition|careers?\s+page|join\s+(our|the)\s+team|vacancy\s+type|posting\s+date|apply\s+before)\b/i, w: 10, label: 'Recruitment / ATS context' },
  { re: /\b(cv|resume|cover\s+letter|application|candidates?\s+(will|should|must)|submit\s+(your\s+)?(cv|application))\b/i, w: 8, label: 'Application materials' },
  { re: /\b(report(s|ing)?\s+to|team\s+of|collaborat(e|ion)|stakeholders?)\b/i, w: 6, label: 'Team / reporting structure' },
];

/** Strong ATS / career-system structure — almost always a real posting */
const ATS_STRUCTURE = [
  { re: /\bjob\s+identification\b/i, w: 22, label: 'ATS job ID field' },
  { re: /\b(posting\s+date|apply\s+before|closing\s+date)\b/i, w: 18, label: 'ATS dates' },
  { re: /\b(job\s+schedule|vacancy\s+type|contract\s+duration|practice\s+area|grade\b)/i, w: 14, label: 'ATS metadata fields' },
  { re: /\bduties\s+and\s+responsibilities\b/i, w: 16, label: 'Duties and responsibilities section' },
  { re: /\brequired\s+skills\s+and\s+experience\b/i, w: 16, label: 'Required skills section' },
  { re: /\b(oraclecloud\.com|greenhouse\.io|lever\.co|workday\.com|successfactors|icims\.com|bamboohr|smartrecruiters)\b/i, w: 20, label: 'Known ATS / career domain in text' },
  { re: /\b(undp|unicef|who\s+careers|un\s+careers|united\s+nations)\b/i, w: 8, label: 'UN / IGO employer context' },
];

const NON_JOB_STRONG = [
  { re: /\b(privacy\s+policy|terms\s+of\s+(service|use)|cookie\s+policy|refund\s+policy)\b/i, w: 40, label: 'Legal / policy page', footerSafe: true },
  { re: /\b(invoice|receipt|order\s+#|tracking\s+number|shipping\s+address)\b/i, w: 35, label: 'Invoice / commerce', footerSafe: false },
  { re: /\b(dear\s+(sir|madam|friend)|i\s+hope\s+this\s+(email|message)\s+finds\s+you|as\s+per\s+our\s+conversation)\b/i, w: 25, label: 'Generic email / letter', footerSafe: false },
  { re: /\b(my\s+name\s+is|i\s+am\s+a\s+(student|graduate)|objective\s*:|education\s*:|work\s+experience\s*:)\b/i, w: 30, label: 'Resume / CV content', footerSafe: false },
  // Employer anti-scam footers look like "tool content" — only strong when job structure is absent
  { re: /\b(how\s+to\s+spot\s+a\s+(job\s+)?scam|warning\s+signs\s+of\s+(employment\s+)?fraud|scam\s+checker|verifyjobs)\b/i, w: 35, label: 'Educational / tool content about scams', footerSafe: true },
  { re: /\bscam\s+warning\b/i, w: 25, label: 'Scam warning footer', footerSafe: true },
];

const NON_JOB_MILD = [
  { re: /\b(blog\s+post|subscribe\s+to\s+(our\s+)?newsletter|leave\s+a\s+comment)\b/i, w: 12, label: 'Blog / newsletter' },
  { re: /\b(add\s+to\s+cart|checkout|product\s+description|sku\s*:)\b/i, w: 15, label: 'Product page' },
  { re: /\b(i\s+am\s+an\s+employee|employee\s+login|sign\s+in\s+to\s+your\s+account)\b/i, w: 10, label: 'Employee portal chrome' },
];

function assessJobLikelihood(text, jobTitle = '') {
  const t = String(text || '');
  const title = String(jobTitle || '').trim();
  const reasons = [];
  const signals = { positive: [], negative: [] };

  let score = 20;
  let atsHits = 0;

  if (title && title.length > 2 && !/^(untitled|unknown|file|document|image)/i.test(title)) {
    if (/\b(engineer|developer|manager|analyst|assistant|coordinator|specialist|officer|intern|internship|director|designer|accountant|nurse|teacher|driver|sales|marketing|hr|recruiter|fellow|fellowship|scholar|scholarship|trainee|apprentice|volunteer|vacancy)\b/i.test(title)) {
      score += 15;
      signals.positive.push('Job-like title');
      reasons.push('Title looks like a role name');
    } else if (/verifyjobs|scam\s*check|how\s+it\s+works|privacy|about\s+us/i.test(title)) {
      score -= 20;
      signals.negative.push('Non-job page title');
    }
  }

  for (const p of JOB_POSITIVE) {
    if (p.re.test(t)) {
      score += p.w;
      signals.positive.push(p.label);
      if (reasons.length < 5) reasons.push(p.label);
    }
  }

  for (const p of ATS_STRUCTURE) {
    if (p.re.test(t)) {
      score += p.w;
      atsHits += 1;
      signals.positive.push(p.label);
      if (reasons.length < 6) reasons.push(p.label);
    }
  }

  const wordCountEarly = t.split(/\s+/).filter(Boolean).length;
  const opportunityStructure =
    /\b(fellowship|scholarship|open\s+call|call\s+for\s+applications?|traineeship|apprenticeship)\b/i.test(t) &&
    (/\b(apply|eligibility|deadline|stipend|duration|selection|criteria)\b/i.test(t) || wordCountEarly >= 60);

  const strongJobStructure =
    atsHits >= 2 ||
    (atsHits >= 1 && signals.positive.length >= 3) ||
    (/duties\s+and\s+responsibilities/i.test(t) && /required\s+skills|qualifications|requirements/i.test(t)) ||
    (/job\s+identification/i.test(t) && /apply/i.test(t)) ||
    opportunityStructure;

  for (const n of NON_JOB_STRONG) {
    if (!n.re.test(t)) continue;
    // Real job pages (UNDP, Oracle HCM, etc.) include anti-scam + legal footers
    if (n.footerSafe && strongJobStructure) {
      score -= Math.min(8, Math.floor(n.w / 5)); // soft penalty only
      signals.negative.push(n.label + ' (discounted — job structure present)');
      continue;
    }
    score -= n.w;
    signals.negative.push(n.label);
    reasons.push(n.label);
  }

  for (const n of NON_JOB_MILD) {
    if (n.re.test(t)) {
      const pen = strongJobStructure ? Math.min(4, n.w) : n.w;
      score -= pen;
      signals.negative.push(n.label);
    }
  }

  const words = t.split(/\s+/).filter(Boolean).length;
  if (words < 25) {
    score -= 15;
    signals.negative.push('Very short text');
  } else if (words >= 80 && signals.positive.length >= 2) {
    score += 8;
  }

  if (/requirements?:/i.test(t) && /responsibilit/i.test(t)) {
    score += 12;
    signals.positive.push('Requirements + responsibilities structure');
  }

  // Hard boost: classic ATS field cluster
  if (strongJobStructure) {
    score += 15;
    signals.positive.push('Strong career/ATS structure');
  }

  score = Math.max(0, Math.min(100, score));

  let isJob;
  let confidence;
  if (score >= 55) {
    isJob = true;
    confidence = score >= 70 ? 'high' : 'medium';
  } else if (score >= 35) {
    isJob = true;
    confidence = 'low';
  } else {
    isJob = false;
    confidence = score <= 20 ? 'high' : 'medium';
  }

  // Override: educational scam-tool page only when NOT a real posting structure
  if (/how\s+to\s+spot\s+a\s+(job\s+)?scam|job\s+scam\s+checker|\bverifyjobs\b/i.test(t) &&
      !strongJobStructure &&
      !/\b(we\s+are\s+hiring|apply\s+now|job\s+title\s*:|job\s+identification|duties\s+and\s+responsibilities)\b/i.test(t)) {
    isJob = false;
    confidence = 'high';
    score = Math.min(score, 15);
    if (!signals.negative.includes('Educational / tool content about scams')) {
      signals.negative.push('Educational / tool content about scams');
    }
  }

  // Override: never call not-a-job when ATS structure is clear
  if (strongJobStructure && !isJob) {
    isJob = true;
    confidence = 'medium';
    score = Math.max(score, 55);
    reasons.unshift('Career/ATS structure overrides non-job footers');
  }

  return {
    isJob,
    confidence,
    score,
    reasons: reasons.slice(0, 6),
    signals,
    strongJobStructure,
  };
}

function buildNotAJobResult(jobCheck, jobTitle, source, text) {
  const explanation =
    'This does not look like a job advertisement, so we did not run full scam scoring. ' +
    (jobCheck.reasons && jobCheck.reasons.length
      ? 'Signals: ' + jobCheck.reasons.slice(0, 3).join('; ') + '.'
      : '');

  return {
    status: 'not_a_job',
    statusLabel: 'Not a Job Posting',
    riskScore: 0,
    legitimacyScore: null,
    redFlags: [],
    positiveIndicators: [],
    explanation,
    recommendation:
      'Paste a job description, careers-page text, or a direct job URL — not a homepage, policy page, or resume.',
    actionItems: [
      'Open the specific vacancy (not the site menu or about page)',
      'Copy the full job description including duties and requirements',
      'Or submit the direct link to the job posting',
    ],
    note: 'Scam checks are designed for job ads only.',
    metadata: {
      notAJob: true,
      jobLikelihood: jobCheck,
      wordCount: String(text || '').split(/\s+/).filter(Boolean).length,
      source: source || 'Unknown',
      analysisTimestamp: new Date().toISOString(),
    },
    decision: {
      verdict: 'not_a_job',
      verdictLabel: 'Not a job posting',
      verdictTone: 'neutral',
      summary: 'Not a job posting — scam checks are for job ads only.',
      topReasons: (jobCheck.reasons || []).slice(0, 4),
      nextSteps: [
        'Use a direct job URL or paste the full vacancy text',
        'Avoid homepage/menu chrome only',
      ],
      scamPattern: null,
      riskScore: 0,
    },
  };
}

module.exports = {
  assessJobLikelihood,
  buildNotAJobResult,
  JOB_POSITIVE,
  NON_JOB_STRONG,
};
