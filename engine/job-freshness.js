// job-freshness.js — VerifyJobs v1.4
// Detects whether a job posting is likely still open, stale, or closed
// WITHOUT relying on hardcoded years or months.
// Uses only structural, linguistic, and relative-time signals.

// ─────────────────────────────────────────────
// SIGNAL WEIGHTS
// Each signal contributes a "staleness score" from -100 (very fresh) to +100 (very stale).
// Final score is clamped to 0–100 and mapped to a status.
// ─────────────────────────────────────────────

/**
 * RELATIVE TIME EXPRESSIONS
 * Captures things like "posted 3 days ago", "2 weeks ago", "just posted", "today"
 * without knowing what the current date is.
 */
function detectRelativeTime(text) {
    const signals = [];
    let stalenessScore = 0;
  
    // ── VERY FRESH (strongly open) ──
    const veryFreshPatterns = [
      /\bjust posted\b/i,
      /\bposted today\b/i,
      /\bnew (listing|posting|job|role|opportunity)\b/i,
      /\bopening (today|now)\b/i,
      /\bimmediately available\b/i,
      /\bstarting (now|immediately|asap)\b/i,
      /\burgently (hiring|needed|required)\b/i,
      /\bwe('re| are) actively hiring\b/i,
      /\bcurrently (accepting|seeking|looking for)\b/i,
    ];
    for (const p of veryFreshPatterns) {
      if (p.test(text)) {
        stalenessScore -= 40;
        signals.push({ signal: 'Very fresh language detected', weight: -40 });
        break;
      }
    }
  
    // ── FRESH (likely open) ──
    // "posted X days ago" where X is small
    const daysAgoMatch = text.match(/posted\s+(\d+)\s+day[s]?\s+ago/i);
    if (daysAgoMatch) {
      const days = parseInt(daysAgoMatch[1], 10);
      if (days <= 7) {
        stalenessScore -= 35;
        signals.push({ signal: `Posted ${days} day(s) ago — very recent`, weight: -35 });
      } else if (days <= 30) {
        stalenessScore -= 15;
        signals.push({ signal: `Posted ${days} day(s) ago — recent`, weight: -15 });
      } else if (days <= 90) {
        stalenessScore += 20;
        signals.push({ signal: `Posted ${days} day(s) ago — getting old`, weight: +20 });
      } else {
        stalenessScore += 50;
        signals.push({ signal: `Posted ${days} day(s) ago — likely stale`, weight: +50 });
      }
    }
  
    // "posted X weeks ago"
    const weeksAgoMatch = text.match(/posted\s+(\d+)\s+week[s]?\s+ago/i);
    if (weeksAgoMatch) {
      const weeks = parseInt(weeksAgoMatch[1], 10);
      if (weeks <= 2) {
        stalenessScore -= 20;
        signals.push({ signal: `Posted ${weeks} week(s) ago — recent`, weight: -20 });
      } else if (weeks <= 8) {
        stalenessScore += 25;
        signals.push({ signal: `Posted ${weeks} week(s) ago — aging`, weight: +25 });
      } else {
        stalenessScore += 55;
        signals.push({ signal: `Posted ${weeks} week(s) ago — likely stale`, weight: +55 });
      }
    }
  
    // "posted X months ago"
    const monthsAgoMatch = text.match(/posted\s+(\d+)\s+month[s]?\s+ago/i);
    if (monthsAgoMatch) {
      const months = parseInt(monthsAgoMatch[1], 10);
      if (months <= 1) {
        stalenessScore += 10;
        signals.push({ signal: `Posted ${months} month(s) ago — borderline`, weight: +10 });
      } else {
        stalenessScore += 60 + (months * 5); // more months = more stale
        signals.push({ signal: `Posted ${months} month(s) ago — stale`, weight: +(60 + months * 5) });
      }
    }
  
    // "X+ applicants" — large applicant pools suggest the role may be filled
    const applicantsMatch = text.match(/(\d+)\+?\s*applicants?/i);
    if (applicantsMatch) {
      const count = parseInt(applicantsMatch[1], 10);
      if (count >= 200) {
        stalenessScore += 40;
        signals.push({ signal: `${count}+ applicants — high competition, may be filled`, weight: +40 });
      } else if (count >= 100) {
        stalenessScore += 20;
        signals.push({ signal: `${count}+ applicants — moderate staleness signal`, weight: +20 });
      }
    }
  
    // "Be an early applicant" — explicitly fresh
    if (/\b(be an? early applicant|early applicant|among the first)\b/i.test(text)) {
      stalenessScore -= 30;
      signals.push({ signal: 'Early applicant prompt — very fresh listing', weight: -30 });
    }
  
    return { stalenessScore, signals };
  }
  
  /**
   * DEADLINE & CLOSING SIGNALS
   * Application deadlines, closing dates, and urgency windows.
   */
  function detectDeadlineSignals(text) {
    const signals = [];
    let stalenessScore = 0;
  
    // Explicit "apply by" / "deadline" — suggests still open if not passed
    if (/\b(apply by|application deadline|closing date|applications close|deadline to apply)\b/i.test(text)) {
      // We can't know if the deadline passed, but its presence is a neutral-to-fresh signal
      // (scam posts rarely include real deadlines)
      stalenessScore -= 10;
      signals.push({ signal: 'Application deadline mentioned — structured posting', weight: -10 });
    }
  
    // "Interviews will be held [soon / this week / next week]"
    if (/interviews?\s+(will be|are being|scheduled|held)\s+(soon|this week|next week|shortly)/i.test(text)) {
      stalenessScore -= 20;
      signals.push({ signal: 'Interview scheduling language — actively hiring', weight: -20 });
    }
  
    // "Position to be filled by [relative expression]"
    if (/\b(position|role|vacancy)\s+(to be|will be)\s+filled\s+(soon|shortly|quickly|immediately)\b/i.test(text)) {
      stalenessScore -= 15;
      signals.push({ signal: 'Position to be filled soon — actively hiring', weight: -15 });
    }
  
    // "We are no longer accepting" / "This role has been filled"
    if (/\b(no longer accepting|this (role|position|vacancy) (has been|is) (filled|closed)|filled internally)\b/i.test(text)) {
      stalenessScore += 100;
      signals.push({ signal: 'Explicit closed/filled language', weight: +100 });
    }
  
    // "Due to high volume" — often appears in autoresponses for stale posts
    if (/\bdue to (high|overwhelming|large) (volume|number|response)\b/i.test(text)) {
      stalenessScore += 30;
      signals.push({ signal: 'High volume disclaimer — possibly stale', weight: +30 });
    }
  
    return { stalenessScore, signals };
  }
  
  /**
   * STRUCTURAL COMPLETENESS SIGNALS
   * Thin, incomplete postings are often stale reposts or placeholders.
   * Well-structured postings tend to be actively maintained.
   */
  function detectStructuralSignals(text) {
    const signals = [];
    let stalenessScore = 0;
  
    const wordCount = text.split(/\s+/).filter(Boolean).length;
  
    // Very short postings are often placeholder reposts
    if (wordCount < 80) {
      stalenessScore += 25;
      signals.push({ signal: `Very short posting (${wordCount} words) — possible placeholder`, weight: +25 });
    } else if (wordCount < 150) {
      stalenessScore += 12;
      signals.push({ signal: `Short posting (${wordCount} words) — low detail`, weight: +12 });
    } else if (wordCount > 400) {
      // Detailed postings are usually actively maintained
      stalenessScore -= 15;
      signals.push({ signal: `Detailed posting (${wordCount} words) — well maintained`, weight: -15 });
    }
  
    // Active hiring language in the body
    if (/\b(we are (looking for|seeking|hiring)|join (our|the) team|come (work|join) with us|this role (will|involves))\b/i.test(text)) {
      stalenessScore -= 20;
      signals.push({ signal: 'Active recruitment language in body', weight: -20 });
    }
  
    // Future tense responsibilities — role is clearly being planned for
    if (/\b(you will|you('ll| will) be|the (candidate|hire) will|successful candidate will)\b/i.test(text)) {
      stalenessScore -= 15;
      signals.push({ signal: 'Future-tense role description — actively planning hire', weight: -15 });
    }
  
    // Stale repost indicators — generic boilerplate with no specifics
    const genericBoilerplate = [
      /\bvarious duties as assigned\b/i,
      /\bother duties as required\b/i,
      /\bmust be a team player\b/i,        // alone, this is common; as a cluster it's stale
      /\bself[- ]?starter\b/i,
      /\bfast[- ]?paced environment\b/i,
    ];
    const boilerplateCount = genericBoilerplate.filter(p => p.test(text)).length;
    if (boilerplateCount >= 4) {
      stalenessScore += 20;
      signals.push({ signal: 'Heavy generic boilerplate — possible stale repost', weight: +20 });
    }
  
    return { stalenessScore, signals };
  }
  
  /**
   * APPLICATION PROCESS SIGNALS
   * Active application processes suggest the role is open.
   * Passive or missing processes suggest it may not be.
   */
  function detectApplicationProcessSignals(text) {
    const signals = [];
    let stalenessScore = 0;
  
    // Active apply prompts
    if (/\b(apply (now|today|here|below|via|through|at)|submit (your )?(resume|cv|application)|send (your )?(resume|cv) to)\b/i.test(text)) {
      stalenessScore -= 25;
      signals.push({ signal: 'Active application call-to-action', weight: -25 });
    }
  
    // Interview process described (multi-step = planned, active)
    if (/\b(interview process|hiring process|selection process|recruitment process)\b/i.test(text)) {
      stalenessScore -= 20;
      signals.push({ signal: 'Hiring process described — actively recruiting', weight: -20 });
    }
  
    // Salary range visible (companies remove or archive listings once filled)
    if (/\$[\d,]+\s*[-–]\s*\$[\d,]+|\bsalary range\b/i.test(text)) {
      stalenessScore -= 10;
      signals.push({ signal: 'Salary range listed — posting actively maintained', weight: -10 });
    }
  
    // "We will contact shortlisted candidates" — passive, possibly stale autoresponse
    if (/\b(only shortlisted|shortlisted candidates (will|shall)|we will contact you if)\b/i.test(text)) {
      stalenessScore += 20;
      signals.push({ signal: 'Passive response language — possible stale autoresponse', weight: +20 });
    }
  
    return { stalenessScore, signals };
  }
  
  /**
   * PLATFORM METADATA SIGNALS
   * Text scraped from job boards often contains platform-level freshness metadata.
   */
  function detectPlatformMetadata(text) {
    const signals = [];
    let stalenessScore = 0;
  
    // "Reposted" — explicitly recycled listing
    if (/\b(reposted|re-?listed|refreshed listing)\b/i.test(text)) {
      stalenessScore += 35;
      signals.push({ signal: 'Listing marked as reposted or re-listed', weight: +35 });
    }
  
    // "Original post date" being mentioned suggests someone is archiving it
    if (/\b(original(ly)? posted|first posted|originally listed)\b/i.test(text)) {
      stalenessScore += 25;
      signals.push({ signal: 'Original post date reference — may be an archive', weight: +25 });
    }
  
    // "Views" count — high views on an old post = stale
    const viewsMatch = text.match(/(\d{1,3}(?:,\d{3})*)\s*(views?|impressions?)/i);
    if (viewsMatch) {
      const views = parseInt(viewsMatch[1].replace(/,/g, ''), 10);
      if (views > 5000) {
        stalenessScore += 30;
        signals.push({ signal: `${views.toLocaleString()} views — high traffic may indicate old listing`, weight: +30 });
      }
    }
  
    // Active "save job" / "follow" prompts from job board UI residue
    if (/\b(save (this )?job|set up (a )?job alert|notify me of similar)\b/i.test(text)) {
      stalenessScore -= 15;
      signals.push({ signal: 'Job board save/alert prompt — active listing UI', weight: -15 });
    }
  
    return { stalenessScore, signals };
  }
  
  // ─────────────────────────────────────────────
  // MASTER FRESHNESS ANALYZER
  // ─────────────────────────────────────────────
  
  /**
   * Runs all signal detectors and produces a unified freshness verdict.
   *
   * @param {string} text — cleaned job posting text
   * @returns {object} freshness result
   */
  function analyzeJobFreshness(text) {
    if (!text || text.trim().length < 20) {
      return buildFreshnessResult(0, [], 'unknown');
    }
  
    const allSignals = [];
    let totalStaleness = 0;
  
    const detectors = [
      detectRelativeTime,
      detectDeadlineSignals,
      detectStructuralSignals,
      detectApplicationProcessSignals,
      detectPlatformMetadata,
    ];
  
    for (const detect of detectors) {
      const { stalenessScore, signals } = detect(text);
      totalStaleness += stalenessScore;
      allSignals.push(...signals);
    }
  
    // Clamp to -100 … +100 then normalise to 0–100
    const clamped   = Math.max(-100, Math.min(100, totalStaleness));
    const normalised = Math.round((clamped + 100) / 2); // -100→0, 0→50, +100→100
  
    return buildFreshnessResult(normalised, allSignals, null);
  }
  
  /**
   * Maps a normalised staleness score (0–100) to a human-readable status.
   */
  function buildFreshnessResult(stalenessNorm, signals, forceStatus) {
    let status, label, color, icon, isAccepting, confidence;
  
    if (forceStatus === 'unknown') {
      status      = 'Unknown';
      label       = 'Status Unknown';
      color       = '#9ca3af';
      icon        = '❓';
      isAccepting = true;
      confidence  = 'very_low';
    } else if (stalenessNorm >= 80) {
      status      = 'Likely Closed';
      label       = 'Likely Closed or Filled';
      color       = '#dc2626';
      icon        = '🔴';
      isAccepting = false;
      confidence  = 'medium';
    } else if (stalenessNorm >= 60) {
      status      = 'Possibly Stale';
      label       = 'Possibly Stale — Verify Before Applying';
      color       = '#ea580c';
      icon        = '🟠';
      isAccepting = true; // still might be open
      confidence  = 'low';
    } else if (stalenessNorm >= 40) {
      status      = 'Uncertain';
      label       = 'Status Uncertain — Check Directly';
      color       = '#d97706';
      icon        = '🟡';
      isAccepting = true;
      confidence  = 'low';
    } else if (stalenessNorm >= 20) {
      status      = 'Likely Open';
      label       = 'Likely Still Open';
      color       = '#2563eb';
      icon        = '🔵';
      isAccepting = true;
      confidence  = 'medium';
    } else {
      status      = 'Open';
      label       = 'Actively Hiring';
      color       = '#1a7a45';
      icon        = '🟢';
      isAccepting = true;
      confidence  = 'high';
    }
  
    // Top signals for display (exclude neutral noise)
    const topSignals = signals
      .filter(s => Math.abs(s.weight) >= 10)
      .sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight))
      .slice(0, 4);
  
    return {
      status,
      label,
      color,
      icon,
      isAccepting,
      confidence,
      stalenessScore: stalenessNorm, // 0 = very fresh, 100 = very stale
      freshnessScore: 100 - stalenessNorm, // inverse — easier to display
      signals: topSignals,
      allSignals: signals,
      badge: label, // matches JOB_STATUS_META.badge shape for UI compatibility
    };
  }
  
  module.exports = {
    analyzeJobFreshness,
    detectRelativeTime,
    detectDeadlineSignals,
    detectStructuralSignals,
    detectApplicationProcessSignals,
    detectPlatformMetadata,
  };