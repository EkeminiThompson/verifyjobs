// job-likelihood.js — Is this text actually a job posting (or job-like offer)?
// Run BEFORE fraud scoring. Non-jobs should not get scam/legit scores.
//
// Design philosophy:
//   The gate's ONLY job is to answer: "Is someone trying to offer employment
//   or a paid opportunity?" — NOT to pre-judge legitimacy. Scam job blasts,
//   WhatsApp "work from home" offers, task-based fraud schemes, and fake
//   crypto trading roles ARE job offers. They must pass through so the fraud
//   scorer can do its work. Only genuine non-job content (resumes, blogs,
//   policy pages, invoices) should be rejected here.
//
// Score thresholds:
//   >= 55  → job (run full fraud scoring)
//   35–54  → probable job (still run fraud scoring)
//   < 35   → not a job (early return, skip fraud scoring)

'use strict';

// ---------------------------------------------------------------------------
// SECTION 1: FORMAL JOB / ATS SIGNALS
// Standard job description language from career sites, ATS systems, NGOs.
// ---------------------------------------------------------------------------

const FORMAL_JOB_SIGNALS = [
  {
    re: /\b(job\s*(title|description|posting|opening|vacancy|opportunity|identification|info)|position\s*(title|available|open)|we('re| are)\s+hiring|now\s+hiring|apply\s+(now|today|here|online|via|with|to|at)|how\s+to\s+apply|application\s+procedure|send\s+(your\s+)?(cv|resume|credentials|application))\b/i,
    w: 18,
    label: 'Formal hiring / apply language',
  },
  {
    re: /\b(fellowship|fellowships|scholarship|scholarships|grant\s+opportunity|open\s+call|call\s+for\s+(applications?|proposals?)|residency\s+programme|internship\s+programme|traineeship|apprenticeship)\b/i,
    w: 20,
    label: 'Fellowship / scholarship / open call',
  },
  {
    re: /\b(eligibility\s+criteria|selection\s+criteria|who\s+can\s+apply|award\s+(amount|value)|stipend|duration\s+of\s+(the\s+)?(fellowship|programme|program|internship))\b/i,
    w: 14,
    label: 'Opportunity eligibility / award structure',
  },
  {
    re: /\b(submit\s+(your\s+)?application|applications?\s+(are\s+)?(open|close|due)|deadline\s+to\s+apply|apply\s+by)\b/i,
    w: 12,
    label: 'Application deadline language',
  },
  {
    re: /\b(responsibilit(y|ies)|duties(\s+and\s+responsibilities)?|what\s+you('ll| will)\s+do|role\s+overview|about\s+the\s+(role|position|job)|competencies|required\s+skills\s+and\s+experience)\b/i,
    w: 16,
    label: 'Job structure sections',
  },
  {
    re: /\b(full[- ]?time|part[- ]?time|contract|permanent|temporary|remote|hybrid|on[- ]?site|work\s+from\s+home|home[- ]?based|project[- ]based|consultancy)\b/i,
    w: 12,
    label: 'Employment type / location',
  },
  {
    re: /\b(salary|compensation|pay\s+range|benefits|per\s+(annum|year|month|hour)|competitive\s+(?:package|remuneration|salary))\b/i,
    w: 10,
    label: 'Formal compensation language',
  },
  {
    re: /\b(years?\s+of\s+experience|\d+\+?\s*years?\s+(?:[\w\/\-\s]{0,40})?experience|minimum\s+\d+\s+years?|bachelor'?s?|master'?s?|b\.?\s*sc|b\.?\s*eng|m\.?\s*sc|hnd\b|llb\b|mbbs\b|degree|preferred\s+qualifications?|must\s+have|nice\s+to\s+have|postgraduate|university\s+degree|coren|nmcn|mdcn|professional\s+(?:registration|licence|license))\b/i,
    w: 12,
    label: 'Experience / education requirements',
  },
  {
    re: /\b(recruiter|hiring\s+manager|talent\s+acquisition|careers?\s+page|join\s+(our|the)\s+team|vacancy\s+type|posting\s+date|apply\s+before)\b/i,
    w: 10,
    label: 'Recruitment / ATS context',
  },
  {
    re: /\b(cv|resume|cover\s+letter|credentials|candidates?\s+(will|should|must)|submit\s+(your\s+)?(cv|application|credentials)|shortlisted\s+candidates?)\b/i,
    w: 8,
    label: 'Application materials',
  },
  {
    re: /\b(report(s|ing)?\s+to|team\s+of|collaborat(e|ion)|stakeholders?)\b/i,
    w: 6,
    label: 'Team / reporting structure',
  },
  {
    re: /\b(apply\s+(at|via|through|on)|careers?\s+(page|site|portal)|https?:\/\/[^\s]+\/(jobs?|careers?|openings?)|[a-z0-9\-]+\.(com|ng|gh|co\.uk|org)\/careers)\b/i,
    w: 14,
    label: 'Apply / careers URL or CTA',
  },
  {
    re: /(?:recruitment|careers|jobs|hr|hiring|talent)@[a-zA-Z0-9.\-]+\.(?:com|org|net|ng|co\.uk|io)\b/i,
    w: 14,
    label: 'Branded recruitment email',
  },
];

// ---------------------------------------------------------------------------
// SECTION 2: ATS STRUCTURE — high-weight structural markers from career systems
// ---------------------------------------------------------------------------

const ATS_STRUCTURE = [
  { re: /\bjob\s+identification\b/i,                                                                w: 22, label: 'ATS job ID field' },
  { re: /\b(posting\s+date|apply\s+before|closing\s+date)\b/i,                                     w: 18, label: 'ATS dates' },
  { re: /\b(job\s+schedule|vacancy\s+type|contract\s+duration|practice\s+area|grade\b)/i,          w: 14, label: 'ATS metadata fields' },
  { re: /\bduties\s+and\s+responsibilities\b/i,                                                     w: 16, label: 'Duties and responsibilities section' },
  { re: /\brequired\s+skills\s+and\s+experience\b/i,                                               w: 16, label: 'Required skills section' },
  { re: /\b(oraclecloud\.com|greenhouse\.io|lever\.co|workday\.com|successfactors|icims\.com|bamboohr|smartrecruiters)\b/i, w: 20, label: 'Known ATS / career domain' },
  { re: /\b(undp|unicef|who\s+careers|un\s+careers|united\s+nations)\b/i,                          w: 8,  label: 'UN / IGO employer context' },
];

// ---------------------------------------------------------------------------
// SECTION 3: INFORMAL / WHATSAPP / SOCIAL-MEDIA JOB OFFER SIGNALS
//
// These are the patterns used by scam blasts and genuine informal offers alike.
// They look NOTHING like ATS postings but are still employment offers.
// The gate must let them through so the fraud scorer can evaluate them.
// ---------------------------------------------------------------------------

const INFORMAL_JOB_SIGNALS = [
  // Urgent hiring language common in WhatsApp blasts
  {
    re: /\b(urgent(ly)?\s+(hiring|needed|required|recruiting|vacancy)|urgently\s+seek|positions?\s+(urgently\s+)?(available|open)|immediate\s+(opening|vacancy|hiring|start))\b/i,
    w: 16,
    label: 'Urgent informal hiring language',
  },

  // Earn X amount promises — the core hook of scam job offers
  // Handles: "Earn $500", "earn ₦200,000", "$500 - $1500 weekly", etc.
  {
    re: /\bearn\s+(up\s+to\s+)?[$£€₦][\d,]+|\b[$£€₦][\d,]+\s*([-–]\s*[$£€₦][\d,]+)?\s*(weekly|daily|monthly|per\s+week|per\s+day|per\s+month)\b/i,
    w: 14,
    label: 'Earnings promise (informal)',
  },

  // Currency amounts anywhere in text — fixed regex (was ₦\d which missed ₦200,000)
  {
    re: /[$£€₦][\d,]+/,
    w: 8,
    label: 'Currency amount in text',
  },

  // "No experience needed / required" — classic informal / scam signal
  {
    re: /\bno\s+(prior\s+)?experience\s+(needed|required|necessary)\b/i,
    w: 12,
    label: 'No experience required',
  },

  // Short-hours work claims: "Work 2hrs a day", "2 hours daily"
  {
    re: /\bwork\s+\d+\s*(hrs?|hours?)(\s+(a|per)\s+day)?\b/i,
    w: 12,
    label: 'Short-hours work claim',
  },

  // Task-based "jobs": copy-paste, data entry, product review, liking, clicking
  {
    re: /\b(copy[\s-]paste\s+(job|work|task)|data\s+entry\s+(job|work|task|role)|product\s+review\s+(job|work|task)|like\s+products?\s+(on|for)|click\s+(tasks?|jobs?)|online\s+(task|job)\s+work)\b/i,
    w: 14,
    label: 'Task-based informal work offer',
  },

  // Agent / representative recruiting (package handler, regional agent scams)
  {
    re: /\b(regional\s+agent|local\s+agent|delivery\s+agent|package\s+(handler|receiver|agent)|receive\s+packages?|forward\s+packages?|our\s+(hq|headquarters)|deduct\s+(your\s+)?commission)\b/i,
    w: 16,
    label: 'Package agent / reshipping role',
  },

  // Weekly / daily / monthly income framing
  {
    re: /\b(weekly|daily|monthly)\s+(income|earnings?|salary|pay(ment)?|profit)\b/i,
    w: 10,
    label: 'Periodic income promise',
  },

  // "WhatsApp HR at..." — recruitment via WhatsApp
  {
    re: /\b(whatsapp\s+(hr|us|the\s+(hr|recruiter|manager)|your\s+details?|to\s+apply|now)|contact\s+(hr|recruiter)\s+(on|via|through|at)\s+whatsapp|dm\s+(hr|us|recruiter)|send\s+(your\s+)?cv\s+(to|via|on)\s+whatsapp)\b/i,
    w: 14,
    label: 'WhatsApp-based recruitment',
  },

  // Telegram / social media group recruitment
  {
    re: /\b(join\s+(our\s+)?(telegram|whatsapp)\s+(group|channel|community)|telegram\s+group\s+link|click\s+the\s+link\s+to\s+join)\b/i,
    w: 12,
    label: 'Social media group recruitment',
  },

  // Commission-based structure
  {
    re: /\b(earn\s+(your\s+)?commission|commission\s+(rate|structure|of\s+\d)|keep\s+\d+%|you\s+keep\s+\d+%|\d+%\s+(commission|profit|cut))\b/i,
    w: 10,
    label: 'Commission / profit-split structure',
  },

  // Crypto / funded account trading scams — still presented as a "job"
  {
    re: /\b(crypto\s+trading\s+(assistant|job|role|opportunity)|we\s+fund\s+your\s+account|funded\s+(trading\s+)?account|trade\s+and\s+keep|trading\s+(profit|commission)|forex\s+(trader|trading)\s+(job|role|opportunity)|binary\s+option\s+(trader|job))\b/i,
    w: 16,
    label: 'Crypto / funded trading job offer',
  },

  // Payment-to-unlock scam pattern — "pay to activate / unlock / start"
  {
    re: /\b(pay\s+(to\s+)?(unlock|activate|start|access|register)|registration\s+(fee|payment)|activation\s+(fee|payment)|unlock\s+(your\s+)?(account|access|task|slot)|deposit\s+(as\s+)?(insurance|security|guarantee|collateral))\b/i,
    w: 12,
    label: 'Pay-to-unlock / upfront fee scam marker',
  },

  // "Work from home" informal framing
  {
    re: /\bwork\s+(from\s+)?home\s+and\s+(earn|make|get paid)\b/i,
    w: 12,
    label: 'Work-from-home earnings claim',
  },

  // Withdrawal / balance threshold tactics (common in task-scam jobs)
  {
    re: /\b(withdraw(al)?\s+(your\s+)?(earnings?|balance|funds?|money)|minimum\s+(withdrawal|balance)|must\s+reach\s+[$£€₦][\d,]+\s+(balance|before|to\s+withdraw)|complete\s+\d+\s+tasks?\s+to\s+withdraw)\b/i,
    w: 14,
    label: 'Withdrawal / task-completion threshold',
  },

  // Agent commission deduction instruction — very specific to reshipping / money-mule
  {
    re: /\bdeduct\s+\d+%\s+(commission|as\s+your\s+(fee|pay|commission))\b/i,
    w: 16,
    label: 'Deduct-your-commission instruction',
  },

  // "Send balance to HQ / headquarters via crypto / bank"
  {
    re: /\b(send\s+(the\s+)?(balance|remainder|remaining\s+amount)\s+(to|via)\s+(hq|headquarters|us|the\s+company)|(forward|transfer)\s+(balance|funds|payment)\s+(via\s+)?(crypto|bitcoin|bank|wire))\b/i,
    w: 16,
    label: 'Balance forwarding instruction',
  },

  // Salary + monthly promise (informal phrasing)
  {
    re: /\b(monthly\s+(salary|income|stipend|allowance)\s+of\s+[$£€₦][\d,]+|[$£€₦][\d,]+\s+(monthly|per\s+month)\s+(salary|income|stipend|pay)|earn\s+[$£€₦][\d,]+\s+(monthly|per\s+month))\b/i,
    w: 14,
    label: 'Monthly salary promise',
  },

  // Mystery shopper / secret evaluator (still a "job" offer)
  {
    re: /\b(mystery\s+shopper|secret\s+(?:shopper|evaluator|inspector)|hotel\s+inspector|rate\s+(?:the\s+)?(?:western\s+union|customer\s+service))\b/i,
    w: 14,
    label: 'Mystery shopper / secret evaluator offer',
  },
  // Money mule / payment processor / wire coordinator
  {
    re: /\b(payment\s+processor|wire\s+transfer\s+coordinator|receive\s+(?:and\s+)?(?:forward|transfer)\s+(?:money|payments?|funds)|receive\s+money\s+into\s+your\s+(?:bank\s+)?account|international\s+transfer\s+agent|p2p\s+trading\s+agent)\b/i,
    w: 16,
    label: 'Payment processor / money-handling role',
  },
  // Car wrap / vehicle branding
  {
    re: /\b(car\s+wrap|vehicle\s+wrap|car\s+branding|display\s+our\s+(?:sticker|decal|logo)\s+on\s+your\s+car|wrap(?:ping)?\s+(?:private\s+)?cars?\s+with)\b/i,
    w: 14,
    label: 'Car wrap / vehicle branding offer',
  },
  // Govt / agency recruitment & grant "jobs"
  {
    re: /\b(you\s+(?:have\s+been\s+)?selected|you\s+qualify\s+for|recruiting\s+\d+|youth\s+empowerment|processing\s+(?:and\s+)?documentation\s+fee|clearance\s+fee|commitment\s+fee|deployment\s+letter|appointment\s+letter)\b/i,
    w: 12,
    label: 'Selection / recruitment / grant processing language',
  },
  // Visa / overseas placement jobs
  {
    re: /\b(visa\s+(?:sponsorship|processing|and\s+flight)|work\s+permit|overseas\s+(?:job|placement|recruitment)|caregiver\s+(?:position|jobs?)\s+in|housemaid|placement\s+fee|agency\s+fee\s+to\s+begin)\b/i,
    w: 14,
    label: 'Overseas / visa job placement offer',
  },
  // MLM / distributor / starter kit
  {
    re: /\b(distributor\s+needed|independent\s+distributor|starter\s+(?:kit|pack|inventory)|downline|recruit\s+\d+\s+people|residual\s+income|network\s+marketing|entry[- ]level\s+product\s+pack)\b/i,
    w: 12,
    label: 'Distributor / MLM opportunity language',
  },
  // Investment / ponzi framed as role or opportunity
  {
    re: /\b(investment\s+opportunity|turn\s+[$£€₦]?\s*[\d,]+\s+into|cloud\s+mining|copy\s+trading|binary\s+options?|arbitrage\s+trader|account\s+manager\s+needed|manage\s+trading\s+accounts)\b/i,
    w: 14,
    label: 'Investment / trading opportunity framed as work',
  },
  // Identity harvest framed as onboarding for a role
  {
    re: /\b(submit\s+(?:your\s+)?(?:bvn|nin|bank\s+(?:account\s+)?details|atm\s+card)|provide\s+(?:your\s+)?(?:bvn|nin|passport)|send\s+(?:your\s+)?(?:bvn|nin).{0,40}(?:confirm|onboard|disbursement|shortlist))\b/i,
    w: 12,
    label: 'Credential collection framed as job onboarding',
  },
  {
    re: /\b(offer\s+letter|internship\s+letter|allowance\s+setup|disbursement\s+officer|confirm\s+your\s+shortlisting|complete\s+your\s+onboarding)\b/i,
    w: 12,
    label: 'Offer-letter credential demand',
  },
  // Trade / artisan hiring (electrician, plumber, tailor, driver, security)
  {
    re: /\b(needs?\s+qualified\s+\w+|recruiting\s+experienced\s+\w+|qualified\s+(?:electricians?|plumbers?|tailors?|drivers?|guards?)|trade\s+test|city\s+and\s+guilds|daily\s+(?:rate|pay)\s*:?\s*₦)\b/i,
    w: 14,
    label: 'Trade / artisan hiring language',
  },
  // Generic "we are hiring / needed / wanted" short blast
  {
    re: /\b(we\s+are\s+(?:hiring|recruiting|looking\s+for)|(?:wanted|needed)\s*:?\s*(?:urgently)?|\bhiring\b.{0,30}\b(?:earn|salary|pay|₦|\$))\b/i,
    w: 10,
    label: 'Generic hiring / wanted language',
  },
  // Package receiving / reshipping
  {
    re: /\b(receive\s+packages?\s+at\s+your|repack\s+and\s+ship|package\s+(?:receiving|forwarding)|last[- ]mile\s+delivery\s+specialist|forward\s+via\s+(?:dhl|fedex))\b/i,
    w: 14,
    label: 'Package receiving / reshipping role',
  },
  // Rating / review / booster agent
  {
    re: /\b(booster\s+agent|rate\s+\d+\s+stars?|product\s+reviewer|rating\s+agent|google\s+(?:map\s+)?reviewer|follow\s+accounts\s+and\s+like)\b/i,
    w: 12,
    label: 'Rating / review / booster agent offer',
  },
];

// ---------------------------------------------------------------------------
// SECTION 4: NON-JOB SIGNALS — content that is clearly not a job offer
// ---------------------------------------------------------------------------

const NON_JOB_STRONG = [
  { re: /\b(privacy\s+policy|terms\s+of\s+(service|use)|cookie\s+policy|refund\s+policy)\b/i,              w: 40, label: 'Legal / policy page',                      footerSafe: true  },
  { re: /\b(invoice|receipt|order\s+#|tracking\s+number|shipping\s+address)\b/i,                            w: 35, label: 'Invoice / commerce',                        footerSafe: false },
  { re: /\b(dear\s+(sir|madam|friend)|i\s+hope\s+this\s+(email|message)\s+finds\s+you|as\s+per\s+our\s+conversation)\b/i, w: 25, label: 'Generic email / letter', footerSafe: false },
  { re: /\b(my\s+name\s+is|i\s+am\s+a\s+(student|graduate)|objective\s*:|education\s*:|work\s+experience\s*:)\b/i, w: 30, label: 'Resume / CV content',            footerSafe: false },
  { re: /\b(how\s+to\s+spot\s+a\s+(job\s+)?scam|warning\s+signs\s+of\s+(employment\s+)?fraud|scam\s+checker|verifyjobs)\b/i, w: 35, label: 'Educational / tool content about scams', footerSafe: true },
  { re: /\bscam\s+warning\b/i,                                                                               w: 25, label: 'Scam warning footer',                      footerSafe: true  },
];

const NON_JOB_MILD = [
  { re: /\b(blog\s+post|subscribe\s+to\s+(our\s+)?newsletter|leave\s+a\s+comment)\b/i, w: 12, label: 'Blog / newsletter' },
  { re: /\b(add\s+to\s+cart|checkout|product\s+description|sku\s*:)\b/i,               w: 15, label: 'Product page' },
  { re: /\b(i\s+am\s+an\s+employee|employee\s+login|sign\s+in\s+to\s+your\s+account)\b/i, w: 10, label: 'Employee portal chrome' },
];

// ---------------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------------

/**
 * Count how many distinct patterns from a signal list match the text.
 * Returns { hits, totalWeight, matchedLabels }.
 */
function scoreSignalList(text, list) {
  let totalWeight = 0;
  const matchedLabels = [];
  for (const sig of list) {
    if (sig.re.test(text)) {
      totalWeight += sig.w;
      matchedLabels.push(sig.label);
    }
  }
  return { hits: matchedLabels.length, totalWeight, matchedLabels };
}

// ---------------------------------------------------------------------------
// MAIN EXPORT
// ---------------------------------------------------------------------------

/**
 * assessJobLikelihood(text, jobTitle?)
 *
 * Returns:
 *   isJob            — boolean
 *   confidence       — 'high' | 'medium' | 'low'
 *   score            — 0–100
 *   jobFlavour       — 'formal' | 'informal' | 'mixed' | 'none'
 *   reasons          — string[] (top signals, for display)
 *   signals          — { positive: string[], negative: string[] }
 *   strongJobStructure — boolean
 */
function assessJobLikelihood(text, jobTitle = '') {
  const t = String(text || '');
  const title = String(jobTitle || '').trim();
  const reasons = [];
  const signals = { positive: [], negative: [] };

  let score = 20; // neutral baseline
  let atsHits = 0;

  // --- Title heuristic ---
  if (title && title.length > 2 && !/^(untitled|unknown|file|document|image)/i.test(title)) {
    if (/\b(engineer|developer|manager|analyst|assistant|coordinator|specialist|officer|intern|internship|director|designer|accountant|nurse|teacher|driver|sales|marketing|hr|recruiter|fellow|fellowship|scholar|scholarship|trainee|apprentice|volunteer|vacancy|agent|trader|representative|electrician|plumber|tailor|guard|cook|nanny|geologist|cashier|tutor)\b/i.test(title)) {
      score += 15;
      signals.positive.push('Job-like title');
      reasons.push('Title looks like a role name');
    } else if (/verifyjobs|scam\s*check|how\s+it\s+works|privacy|about\s+us/i.test(title)) {
      score -= 20;
      signals.negative.push('Non-job page title');
    }
  }

  // Lead-line role: "Electrical Engineer, Julius Berger..." or "ROLE — company"
  const lead = t.slice(0, 120);
  if (/^\s*[A-Z][A-Za-z\/\-\s]{2,40}(?:,|\s+[—\-–]|\s+\(|\s+needed|\s+wanted|\s+position)/m.test(lead) ||
      /\b(engineer|developer|manager|analyst|officer|nurse|electrician|plumber|driver|accountant|geologist|designer|assistant|coordinator|specialist|cashier|tutor|guard|cook|nanny|agent|representative|associate)\b\s*[,\-—]/i.test(lead)) {
    score += 12;
    signals.positive.push('Role-like opening line');
    if (reasons.length < 6) reasons.push('Role-like opening line');
  }

  // --- Score formal job signals ---
  const formal = scoreSignalList(t, FORMAL_JOB_SIGNALS);
  score += formal.totalWeight;
  signals.positive.push(...formal.matchedLabels);
  for (const l of formal.matchedLabels) {
    if (reasons.length < 5) reasons.push(l);
  }

  // --- Score ATS structure ---
  for (const p of ATS_STRUCTURE) {
    if (p.re.test(t)) {
      score += p.w;
      atsHits += 1;
      signals.positive.push(p.label);
      if (reasons.length < 6) reasons.push(p.label);
    }
  }

  // --- Score informal / WhatsApp / social-media job signals ---
  const informal = scoreSignalList(t, INFORMAL_JOB_SIGNALS);
  score += informal.totalWeight;
  signals.positive.push(...informal.matchedLabels);
  for (const l of informal.matchedLabels) {
    if (reasons.length < 8) reasons.push(l);
  }

  // --- Job flavour classification ---
  const hasFormal = formal.hits > 0 || atsHits > 0;
  const hasInformal = informal.hits > 0;
  let jobFlavour = 'none';
  if (hasFormal && hasInformal) jobFlavour = 'mixed';
  else if (hasFormal) jobFlavour = 'formal';
  else if (hasInformal) jobFlavour = 'informal';

  // --- Structural strength checks ---
  const wordCount = t.split(/\s+/).filter(Boolean).length;

  // Short offer boost: currency + earn/hire language ⇒ job-like even when sparse
  if (wordCount <= 100 && /[$£€₦]|\b(?:ngn|usd|gbp|cad|usdt)\b/i.test(t) &&
      /\b(earn|salary|pay|hiring|wanted|needed|apply|recruit|vacancy|position|job|commission|stipend|fee)\b/i.test(t)) {
    score += 12;
    signals.positive.push('Short paid-offer blast');
    if (reasons.length < 8) reasons.push('Short paid-offer blast');
  }

  const opportunityStructure =
    /\b(fellowship|scholarship|open\s+call|call\s+for\s+applications?|traineeship|apprenticeship)\b/i.test(t) &&
    (/\b(apply|eligibility|deadline|stipend|duration|selection|criteria)\b/i.test(t) || wordCount >= 60);

  const strongFormalStructure =
    atsHits >= 2 ||
    (atsHits >= 1 && signals.positive.length >= 3) ||
    (/duties\s+and\s+responsibilities/i.test(t) && /required\s+skills|qualifications|requirements/i.test(t)) ||
    (/job\s+identification/i.test(t) && /apply/i.test(t)) ||
    opportunityStructure;

  // Informal "strong structure": multiple independent scam-job signals
  // e.g. earnings promise + upfront fee + withdrawal mechanics = clearly a (fake) job offer
  const strongInformalStructure =
    informal.hits >= 3 ||
    (informal.hits >= 2 && hasInformal && wordCount >= 30) ||
    (informal.matchedLabels.includes('Pay-to-unlock / upfront fee scam marker') &&
      (informal.matchedLabels.includes('Earnings promise (informal)') ||
       informal.matchedLabels.includes('Urgent informal hiring language') ||
       informal.matchedLabels.includes('Task-based informal work offer'))) ||
    (informal.matchedLabels.includes('Withdrawal / task-completion threshold') &&
      informal.matchedLabels.includes('Earnings promise (informal)')) ||
    (informal.matchedLabels.includes('Balance forwarding instruction') &&
      informal.matchedLabels.includes('Package agent / reshipping role')) ||
    (informal.matchedLabels.includes('Crypto / funded trading job offer') &&
      informal.matchedLabels.includes('Pay-to-unlock / upfront fee scam marker'));

  const strongJobStructure = strongFormalStructure || strongInformalStructure;

  // Hard boost for strong structure
  if (strongJobStructure) {
    score += 15;
    signals.positive.push('Strong job structure detected');
    if (strongInformalStructure && !strongFormalStructure) {
      signals.positive.push('Informal/WhatsApp job structure');
    }
  }

  // --- Non-job penalty (formal signals can discount footer penalties) ---
  for (const n of NON_JOB_STRONG) {
    if (!n.re.test(t)) continue;
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

  // --- Length adjustments ---
  if (wordCount < 25) {
    score -= 15;
    signals.negative.push('Very short text');
  } else if (wordCount >= 80 && signals.positive.length >= 2) {
    score += 8;
  }

  // --- Requirements + responsibilities co-occurrence bonus ---
  if (/requirements?:/i.test(t) && /responsibilit/i.test(t)) {
    score += 12;
    signals.positive.push('Requirements + responsibilities structure');
  }

  score = Math.max(0, Math.min(100, score));

  // --- Decision ---
  let isJob;
  let confidence;
  if (score >= 55) {
    isJob = true;
    confidence = score >= 70 ? 'high' : 'medium';
  } else if (score >= 28) {
    isJob = true;
    confidence = 'low';
  } else {
    isJob = false;
    confidence = score <= 20 ? 'high' : 'medium';
  }

  // --- Override: tool / educational scam page (VerifyJobs own pages, etc.) ---
  if (
    /how\s+to\s+spot\s+a\s+(job\s+)?scam|job\s+scam\s+checker|\bverifyjobs\b/i.test(t) &&
    !strongJobStructure &&
    !/\b(we\s+are\s+hiring|apply\s+now|job\s+title\s*:|job\s+identification|duties\s+and\s+responsibilities|urgent(ly)?\s+hiring|earn\s+[$£€₦])\b/i.test(t)
  ) {
    isJob = false;
    confidence = 'high';
    score = Math.min(score, 15);
    if (!signals.negative.includes('Educational / tool content about scams')) {
      signals.negative.push('Educational / tool content about scams');
    }
  }

  // --- Override: never suppress a real job when structure is clear ---
  if (strongJobStructure && !isJob) {
    isJob = true;
    confidence = 'medium';
    score = Math.max(score, 55);
    reasons.unshift('Job structure overrides non-job content markers');
  }

  return {
    isJob,
    confidence,
    score,
    jobFlavour,
    reasons: [...new Set(reasons)].slice(0, 8),
    signals,
    strongJobStructure,
    strongFormalStructure,
    strongInformalStructure,
  };
}

// ---------------------------------------------------------------------------
// NOT-A-JOB RESULT BUILDER
// ---------------------------------------------------------------------------

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
      'Paste a job description, careers-page text, WhatsApp job offer, or a direct job URL — ' +
      'not a homepage, policy page, or resume.',
    actionItems: [
      'Open the specific vacancy or offer message',
      'Copy the full text including any payment or earnings claims',
      'Or submit the direct link to the job posting',
    ],
    note: 'Scam checks are designed for job offers of any kind — formal ads and informal WhatsApp blasts alike.',
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
      summary: 'Not a job posting — scam checks are for job offers only.',
      topReasons: (jobCheck.reasons || []).slice(0, 4),
      nextSteps: [
        'Use a direct job URL or paste the full vacancy / offer text',
        'Works with formal job ads AND WhatsApp / Telegram job blasts',
      ],
      scamPattern: null,
      riskScore: 0,
    },
  };
}

// ---------------------------------------------------------------------------
// EXPORTS
// ---------------------------------------------------------------------------

module.exports = {
  assessJobLikelihood,
  buildNotAJobResult,
  FORMAL_JOB_SIGNALS,
  INFORMAL_JOB_SIGNALS,
  ATS_STRUCTURE,
  NON_JOB_STRONG,
};