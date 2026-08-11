// engine/analytics.js — VerifyJobs Data Science Layer (trustworthy)
// Ops metrics from analyses.json. Model quality from trained hold-out metrics
// (proxied via ML server), NOT circular labels on live risk scores.

const fs   = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

// Always read the same file storage.js writes
const storage = require('./storage');
const ML_SERVER_URL = (process.env.ML_SERVER_URL || 'http://127.0.0.1:8001').replace(/\/$/, '');

// Minimum samples before claiming statistical or model metrics from live logs
const MIN_OPS_N = 5;
const MIN_AB_N = 100;
const MIN_DID_N = 100;
const MIN_SEGMENT_N = 30;

// ─────────────────────────────────────────────
// DATA ACCESS
// ─────────────────────────────────────────────

function loadAnalyses() {
  try {
    return storage.loadAnalyses();
  } catch {
    return [];
  }
}

// ─────────────────────────────────────────────
// FEATURE ENGINEERING (ops only — not ground truth)
// ─────────────────────────────────────────────

function extractFeatures(record) {
  const r = record.result || record;
  const risk = r.riskScore || 0;
  return {
    riskScore:        risk,
    legitimacyScore:  r.legitimacyScore  || 0,
    redFlagCount:     (r.redFlags        || []).length,
    positiveCount:    (r.positiveIndicators || []).length,
    wordCount:        r.metadata?.wordCount || 0,
    hasEmail:         r.metadata?.hasEmail  ? 1 : 0,
    hasFreeEmail:     r.metadata?.hasFreeEmail ? 1 : 0,
    hasURL:           r.metadata?.hasURL    ? 1 : 0,
    hasSalary:        r.metadata?.hasSalary ? 1 : 0,
    hasLocation:      r.metadata?.hasLocation ? 1 : 0,
    contextPenalty:   r.metadata?.contextPenalty || 0,
    contextBonus:     r.metadata?.contextBonus   || 0,
    source:           record.source || r.source || 'Unknown',
    timestamp:        record.timestamp || r.metadata?.analysisTimestamp || new Date().toISOString(),
    // High-risk proxy for ops rates only — NOT a training label
    highRisk:         risk >= 65 ? 1 : 0,
    status:           r.status || 'unknown',
    notAJob:          r.status === 'not_a_job' || r.metadata?.notAJob === true,
  };
}

// ─────────────────────────────────────────────
// STATISTICAL HELPERS
// ─────────────────────────────────────────────

function mean(arr)     { return arr.length ? arr.reduce((a,b)=>a+b,0)/arr.length : 0; }
function variance(arr) { const m=mean(arr); return mean(arr.map(x=>(x-m)**2)); }
function stddev(arr)   { return Math.sqrt(variance(arr)); }
function median(arr)   {
  if (!arr.length) return 0;
  const s = [...arr].sort((a,b)=>a-b);
  const m = Math.floor(s.length/2);
  return s.length % 2 ? s[m] : (s[m-1]+s[m])/2;
}

function twoProportionZTest(n1, c1, n2, c2) {
  if (!n1 || !n2) return { z: 0, pValue: 1, significant: false };
  const p1 = c1 / n1, p2 = c2 / n2;
  const pp = (c1 + c2) / (n1 + n2);
  const se = Math.sqrt(pp * (1 - pp) * (1/n1 + 1/n2));
  if (!se) return { z: 0, pValue: 1, significant: false };
  const z = (p2 - p1) / se;
  const pValue = parseFloat((2 * (1 - normalCDF(Math.abs(z)))).toFixed(4));
  return {
    z: parseFloat(z.toFixed(4)),
    pValue,
    significant: pValue < 0.05,
    lift: p1 > 0 ? parseFloat(((p2 - p1) / p1 * 100).toFixed(2)) : 0,
    ci95: {
      lower: parseFloat(((p2-p1) - 1.96*se).toFixed(4)),
      upper: parseFloat(((p2-p1) + 1.96*se).toFixed(4)),
    }
  };
}

function normalCDF(x) {
  const t = 1 / (1 + 0.2316419 * Math.abs(x));
  const d = 0.3989423 * Math.exp(-x * x / 2);
  const p = d * t * (0.3193815 + t * (-0.3565638 + t * (1.7814779 + t * (-1.8212560 + t * 1.3302744))));
  return x > 0 ? 1 - p : p;
}

function sampleSizeCalc(baseRate, mde, alpha=0.05, power=0.80) {
  const p2 = baseRate * (1 + mde);
  const za = 1.96;
  const zb = power >= 0.90 ? 1.282 : power >= 0.85 ? 1.036 : 0.842;
  const nRaw = 2 * (za + zb)**2 * baseRate * (1 - baseRate) / ((p2 - baseRate)**2 || 1e-9);
  return Math.ceil(nRaw);
}

// ─────────────────────────────────────────────
// OVERVIEW STATS
// ─────────────────────────────────────────────

function getOverviewStats(records) {
  if (!records.length) return {};
  const features = records.map(extractFeatures).filter(f => !f.notAJob);
  const allFeat = records.map(extractFeatures);
  const scores = features.map(f => f.riskScore);
  const highRisk = features.filter(f => f.highRisk);

  const sourceCounts = {};
  allFeat.forEach(f => { sourceCounts[f.source] = (sourceCounts[f.source]||0)+1; });

  const daily = {};
  allFeat.forEach(f => {
    const d = f.timestamp ? f.timestamp.slice(0,10) : 'unknown';
    if (!daily[d]) daily[d] = { total:0, highRisk:0 };
    daily[d].total++;
    if (f.highRisk) daily[d].highRisk++;
  });

  return {
    total: records.length,
    scoredJobs: features.length,
    notAJobCount: allFeat.filter(f => f.notAJob).length,
    // "scamRate" here = high-risk share among scored jobs (proxy, not human labels)
    highRiskRate: features.length
      ? parseFloat((highRisk.length / features.length * 100).toFixed(1))
      : 0,
    scamRate: features.length
      ? parseFloat((highRisk.length / features.length * 100).toFixed(1))
      : 0,
    avgRiskScore: scores.length ? parseFloat(mean(scores).toFixed(1)) : 0,
    medianRisk: scores.length ? parseFloat(median(scores).toFixed(1)) : 0,
    stddevRisk: scores.length ? parseFloat(stddev(scores).toFixed(1)) : 0,
    highRiskCount: highRisk.length,
    legitCount: features.length - highRisk.length,
    sourceCounts,
    daily,
    scoreDistribution: buildHistogram(scores, 10),
  };
}

function buildHistogram(values, bins) {
  const min=0, max=100, step=max/bins;
  const counts = Array(bins).fill(0);
  values.forEach(v => {
    const i = Math.min(bins-1, Math.floor(v/step));
    counts[i]++;
  });
  return counts.map((count,i) => ({
    bin:   `${i*step}–${(i+1)*step}`,
    count,
    label: `${Math.round(i*step)}–${Math.round((i+1)*step)}`
  }));
}

// ─────────────────────────────────────────────
// REAL ML MODEL METRICS (from serve.py /model-info)
// ─────────────────────────────────────────────

function fetchJson(url, timeoutMs = 2500) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, { timeout: timeoutMs }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

/**
 * Trustworthy model card: hold-out metrics from training, not live logs.
 */
async function getTrainedModelMetrics() {
  try {
    const info = await fetchJson(`${ML_SERVER_URL}/model-info`);
    const ensemble = info.ensemble_test_metrics || {};
    const xgb = info.xgb_test_metrics || {};
    const top = (info.top_features || []).slice(0, 8).map(f => ({
      feature: typeof f === 'string' ? f : (f.feature || f.name || String(f)),
      importance: typeof f === 'object' ? f.importance : undefined,
      direction: 'trained',
    }));

    return {
      source: 'trained_holdout',
      available: true,
      auc: ensemble.auc ?? xgb.auc ?? null,
      bestF1: ensemble.f1 ?? xgb.f1 ?? null,
      bestPrecision: ensemble.precision ?? null,
      bestRecall: ensemble.recall ?? null,
      auprc: ensemble.auprc ?? xgb.auprc ?? null,
      threshold: info.threshold ?? null,
      xgbWeight: info.xgb_weight ?? null,
      bertWeight: info.bert_weight ?? null,
      featureImportance: top,
      note: 'Metrics from held-out test set at training time. Not computed from live traffic labels.',
      raw: {
        ensemble_test_metrics: info.ensemble_test_metrics,
        xgb_test_metrics: info.xgb_test_metrics,
      },
    };
  } catch (err) {
    return {
      source: 'trained_holdout',
      available: false,
      error: `ML server unreachable (${err.message}). Start serve.py or set ML_SERVER_URL. Live traffic is not used as ground truth.`,
    };
  }
}

/**
 * @deprecated Circular live-log evaluation removed. Kept as explicit refusal.
 */
function getModelMetrics(records) {
  return {
    error: 'Live-log model metrics disabled. Labels from riskScore≥65 are circular and not trustworthy. Use trained hold-out metrics from the ML server.',
    sampleSize: records.length,
  };
}

// ─────────────────────────────────────────────
// A/B TESTING (gated)
// ─────────────────────────────────────────────

function runABTest(records) {
  if (records.length < MIN_AB_N) {
    return {
      error: `Need at least ${MIN_AB_N} analyses for A/B reporting (have ${records.length}). Input method is observational, not a randomized experiment.`,
      groups: [],
      planning: null,
    };
  }

  const features = records.map(extractFeatures).filter(f => !f.notAJob);
  const manual = features.filter(f => f.source === 'Manual' || f.source === 'Unknown');
  const urlSource = features.filter(f => f.source === 'URL' || f.source === 'URL analysis');
  const fileSource = features.filter(f => f.source === 'File Upload');

  function groupStats(group, name) {
    if (!group.length) return null;
    const high = group.filter(f => f.highRisk).length;
    const scores = group.map(f => f.riskScore);
    return {
      name,
      n: group.length,
      scamCount: high,
      scamRate: parseFloat((high / group.length * 100).toFixed(2)),
      avgScore: parseFloat(mean(scores).toFixed(1)),
      medianScore: parseFloat(median(scores).toFixed(1)),
    };
  }

  const control = groupStats(manual, 'Manual (control)');
  const variantA = groupStats(urlSource, 'URL analysis');
  const variantB = groupStats(fileSource, 'File upload');

  let test = null;
  if (control && variantA && control.n >= 30 && variantA.n >= 30) {
    const result = twoProportionZTest(control.n, control.scamCount, variantA.n, variantA.scamCount);
    test = {
      comparison: 'Manual vs URL analysis (observational)',
      hypothesis: 'URL submissions have different high-risk rate than manual paste',
      ...result,
      interpretation: result.significant
        ? `Difference detected (p=${result.pValue}). Observational only — users self-select input method.`
        : `No significant difference (p=${result.pValue}). Not a randomized A/B test.`,
    };
  } else {
    test = {
      comparison: 'Manual vs URL analysis',
      significant: false,
      pValue: null,
      lift: 0,
      interpretation: 'Insufficient per-arm sample (need ≥30 each) for a stable comparison.',
    };
  }

  const baseRate = control ? control.scamRate / 100 : 0.15;
  const planning = {
    baseRate: parseFloat((baseRate * 100).toFixed(1)),
    mde10pct: sampleSizeCalc(baseRate || 0.15, 0.10),
    mde20pct: sampleSizeCalc(baseRate || 0.15, 0.20),
    note: 'Sample sizes for a future randomized experiment, not current observational data.',
  };

  return {
    groups: [control, variantA, variantB].filter(Boolean),
    test,
    planning,
    disclaimer: 'Observational comparison by input source — not a randomized controlled experiment.',
  };
}

// ─────────────────────────────────────────────
// DiD (gated — rarely meaningful without real intervention)
// ─────────────────────────────────────────────

function runDifferenceInDifferences(records) {
  if (records.length < MIN_DID_N) {
    return {
      error: `Need at least ${MIN_DID_N} records for DiD-style reporting (have ${records.length}). Median-time splits are not a real product intervention.`,
    };
  }

  const features = records.map(extractFeatures).filter(f => f.timestamp && !f.notAJob);
  features.sort((a,b) => a.timestamp.localeCompare(b.timestamp));

  const mid = Math.floor(features.length / 2);
  const pre = features.slice(0, mid);
  const post = features.slice(mid);

  function split(group) {
    return {
      treatment: group.filter(f => f.source === 'URL' || f.source === 'File Upload' || f.source === 'URL analysis'),
      control: group.filter(f => f.source === 'Manual' || f.source === 'Unknown'),
    };
  }

  const preSplit = split(pre);
  const postSplit = split(post);

  function avg(arr) {
    return arr.length ? mean(arr.map(f => f.riskScore)) : null;
  }

  const preCtrl = avg(preSplit.control);
  const postCtrl = avg(postSplit.control);
  const preTrt = avg(preSplit.treatment);
  const postTrt = avg(postSplit.treatment);

  const did = (preCtrl !== null && postCtrl !== null && preTrt !== null && postTrt !== null)
    ? parseFloat(((postTrt - preTrt) - (postCtrl - preCtrl)).toFixed(2))
    : null;

  return {
    intervention: 'Median timestamp split (exploratory only)',
    disclaimer: 'Not causal evidence of a product change. Parallel trends not validated.',
    groups: {
      control: { pre: preCtrl != null ? parseFloat(preCtrl.toFixed(1)) : null, post: postCtrl != null ? parseFloat(postCtrl.toFixed(1)) : null },
      treatment: { pre: preTrt != null ? parseFloat(preTrt.toFixed(1)) : null, post: postTrt != null ? parseFloat(postTrt.toFixed(1)) : null },
    },
    didEstimate: did,
    interpretation: did !== null
      ? `Exploratory DiD-style estimate: ${did > 0 ? '+' : ''}${did} risk points (URL/File vs Manual, pre/post median time). Do not treat as causal.`
      : 'Insufficient data in one or more cells.',
    sampleBreakdown: {
      preControl: preSplit.control.length,
      pretreatment: preSplit.treatment.length,
      postControl: postSplit.control.length,
      postTreatment: postSplit.treatment.length,
    },
  };
}

// ─────────────────────────────────────────────
// COHORT / SEGMENTS / QUERIES
// ─────────────────────────────────────────────

function getCohortAnalysis(records) {
  if (records.length < MIN_OPS_N) return { error: 'Not enough data' };

  const features = records.map(extractFeatures).filter(f => f.timestamp);
  features.sort((a,b) => a.timestamp.localeCompare(b.timestamp));

  function weekKey(ts) {
    const d = new Date(ts);
    const jan1 = new Date(d.getFullYear(), 0, 1);
    const week = Math.ceil((((d - jan1) / 86400000) + jan1.getDay() + 1) / 7);
    return `${d.getFullYear()}-W${String(week).padStart(2,'0')}`;
  }

  const cohorts = {};
  features.forEach(f => {
    const wk = weekKey(f.timestamp);
    if (!cohorts[wk]) cohorts[wk] = [];
    cohorts[wk].push(f);
  });

  const cohortKeys = Object.keys(cohorts).sort().slice(-8);

  return {
    cohorts: cohortKeys.map(wk => {
      const scored = cohorts[wk].filter(f => !f.notAJob);
      const high = scored.filter(f => f.highRisk).length;
      return {
        week: wk,
        count: cohorts[wk].length,
        scamRate: scored.length ? parseFloat((high / scored.length * 100).toFixed(1)) : 0,
        avgScore: scored.length ? parseFloat(mean(scored.map(f => f.riskScore)).toFixed(1)) : 0,
        sources: [...new Set(cohorts[wk].map(f => f.source))],
      };
    }),
    totalCohorts: cohortKeys.length,
  };
}

function getSegmentInsights(records) {
  const features = records.map(extractFeatures).filter(f => !f.notAJob);
  if (features.length < MIN_OPS_N) {
    return { insights: [], actionable: 'Not enough scored job analyses for segments.' };
  }

  const segments = {
    'With URL': features.filter(f => f.hasURL),
    'Free email': features.filter(f => f.hasFreeEmail),
    'Has salary': features.filter(f => f.hasSalary),
    'Long desc (200+)': features.filter(f => f.wordCount >= 200),
    'Short desc (<50)': features.filter(f => f.wordCount < 50),
  };

  const baseRate = features.filter(f => f.highRisk).length / features.length * 100;

  const insights = Object.entries(segments).map(([name, grp]) => {
    if (grp.length < 5) return null;
    const scores = grp.map(f => f.riskScore);
    const highRate = grp.filter(f => f.highRisk).length / grp.length * 100;
    return {
      segment: name,
      n: grp.length,
      avgScore: parseFloat(mean(scores).toFixed(1)),
      scamRate: parseFloat(highRate.toFixed(1)),
      vsBase: parseFloat((highRate - baseRate).toFixed(1)),
      reliable: grp.length >= MIN_SEGMENT_N,
    };
  }).filter(Boolean);

  insights.sort((a,b) => b.scamRate - a.scamRate);

  const top = insights.find(s => s.reliable) || insights[0];
  const actionable = top
    ? `Segment "${top.segment}" high-risk rate ${top.scamRate}% (${top.vsBase > 0 ? '+' : ''}${top.vsBase}pp vs baseline, n=${top.n}). ${top.reliable ? '' : 'Small sample — treat cautiously.'}`
    : 'Not enough data for segment insights.';

  return { insights, actionable };
}

function runQuery(queryName, params = {}) {
  const records = loadAnalyses();
  const features = records.map(extractFeatures);

  const queries = {
    scam_rate_by_source: () => {
      const groups = {};
      features.forEach(f => {
        if (f.notAJob) return;
        const s = f.source || 'Unknown';
        if (!groups[s]) groups[s] = { source:s, count:0, high:0, totalScore:0 };
        groups[s].count++;
        groups[s].totalScore += f.riskScore;
        if (f.highRisk) groups[s].high++;
      });
      return Object.values(groups).map(g => ({
        source: g.source,
        count: g.count,
        scamRate: parseFloat((g.high / g.count * 100).toFixed(1)),
        avgScore: parseFloat((g.totalScore / g.count).toFixed(1)),
      })).sort((a,b) => b.scamRate - a.scamRate);
    },

    daily_volume: () => {
      const daily = {};
      features.forEach(f => {
        const d = f.timestamp ? f.timestamp.slice(0,10) : 'unknown';
        if (!daily[d]) daily[d] = { date:d, count:0, scams:0 };
        daily[d].count++;
        if (f.highRisk) daily[d].scams++;
      });
      return Object.values(daily).sort((a,b) => a.date.localeCompare(b.date));
    },

    score_distribution: () => buildHistogram(
      features.filter(f => !f.notAJob).map(f => f.riskScore),
      10
    ),

    high_risk_cases: () => {
      const threshold = params.threshold || 65;
      const limit = params.limit || 20;
      return features
        .filter(f => !f.notAJob && f.riskScore >= threshold)
        .sort((a,b) => b.riskScore - a.riskScore)
        .slice(0, limit);
    },

    top_red_flags: () => {
      const flagCounts = {};
      records.forEach(r => {
        const flags = (r.result?.redFlags || r.redFlags || []);
        flags.forEach(f => {
          const key = typeof f === 'string' ? f : (f.reason || f.label || String(f));
          flagCounts[key] = (flagCounts[key] || 0) + 1;
        });
      });
      return Object.entries(flagCounts)
        .map(([flag, count]) => ({
          flag,
          count,
          pct: parseFloat((count / Math.max(records.length, 1) * 100).toFixed(1)),
        }))
        .sort((a,b) => b.count - a.count)
        .slice(0, params.limit || 10);
    },

    rolling_7day: () => {
      const daily = queries.daily_volume();
      return daily.map((d, i) => {
        const window = daily.slice(Math.max(0, i - 6), i + 1);
        return {
          date: d.date,
          rolling_count: Math.round(mean(window.map(w => w.count))),
          rolling_scams: Math.round(mean(window.map(w => w.scams))),
        };
      });
    },
  };

  const q = queries[queryName];
  if (!q) {
    return { error: `Unknown query: ${queryName}. Available: ${Object.keys(queries).join(', ')}` };
  }
  return { queryName, params, result: q(), executedAt: new Date().toISOString() };
}

// ─────────────────────────────────────────────
// INTELLIGENCE LAYER (honest, data-driven narratives)
// ─────────────────────────────────────────────

function buildIntelligence(records, overview, segments, queries, trainedModel) {
  const features = records.map(extractFeatures);
  const scored = features.filter(f => !f.notAJob);
  const n = records.length;
  const bullets = [];
  const alerts = [];

  // Volume / mix
  const notJob = features.filter(f => f.notAJob).length;
  if (notJob > 0 && n > 0) {
    bullets.push(`${notJob} of ${n} inputs (${((notJob/n)*100).toFixed(0)}%) were classified as not a job posting — gate is working.`);
  }

  // Risk shape
  if (scored.length >= 5) {
    const high = scored.filter(f => f.highRisk).length;
    const mid = scored.filter(f => f.riskScore >= 45 && f.riskScore < 65).length;
    const low = scored.filter(f => f.riskScore < 45).length;
    bullets.push(`Risk mix among jobs: ${low} lower-risk, ${mid} verify-first band, ${high} high-risk (≥65).`);
    if (high / scored.length > 0.4) {
      alerts.push('High share of high-risk submissions — traffic may be skewed toward suspicious pastes (common for a scam checker).');
    }
  }

  // Flags
  const topFlags = (queries && queries.topRedFlags) || [];
  if (topFlags.length) {
    bullets.push(`Most common signal: “${String(topFlags[0].flag).slice(0, 72)}” (${topFlags[0].count} hits).`);
  }

  // Sources
  const bySource = (queries && queries.bySource) || [];
  if (bySource.length) {
    const top = bySource[0];
    bullets.push(`Highest high-risk share by source: ${top.source} at ${top.scamRate}% (n=${top.count}).`);
  }

  // Segments
  const insights = (segments && segments.insights) || [];
  const reliable = insights.filter(s => s.reliable);
  if (reliable.length) {
    const s = reliable[0];
    bullets.push(`Segment “${s.segment}” stands out at ${s.scamRate}% high-risk (${s.vsBase > 0 ? '+' : ''}${s.vsBase}pp vs baseline, n=${s.n}).`);
  } else if (insights.length) {
    bullets.push('Segment differences exist but samples are still small — treat rankings as directional.');
  }

  // ML hybrid usage from stored results (if enrichWithML persisted ml block)
  let mlUsed = 0;
  let mlOffline = 0;
  records.forEach(r => {
    const ml = r.ml || r.result?.ml;
    if (ml && ml.available === true) mlUsed++;
    else if (ml && ml.available === false) mlOffline++;
  });
  if (mlUsed + mlOffline > 0) {
    bullets.push(`Hybrid ML was available on ${mlUsed} of ${mlUsed + mlOffline} stored runs with an ml block.`);
  }

  // Trained model status
  let modelHeadline = 'Model metrics unavailable — start serve.py for hold-out AUC/AUPRC.';
  if (trainedModel && trainedModel.available) {
    const auc = trainedModel.auc;
    const auprc = trainedModel.auprc;
    const f1 = trainedModel.bestF1;
    modelHeadline = `Trained ensemble hold-out: AUC ${auc != null ? (auc <= 1 ? (auc*100).toFixed(1) : auc) : '—'}%` +
      (auprc != null ? `, AUPRC ${(auprc <= 1 ? auprc*100 : auprc).toFixed(1)}%` : '') +
      (f1 != null ? `, F1 ${(f1 <= 1 ? f1*100 : f1).toFixed(1)}%` : '') +
      '. These are test-set metrics, not live labels.';
    bullets.push(modelHeadline);
  } else if (trainedModel && trainedModel.error) {
    alerts.push(trainedModel.error);
  }

  // Data maturity
  let maturity = 'early';
  if (n >= 500) maturity = 'established';
  else if (n >= 100) maturity = 'growing';
  else if (n >= 30) maturity = 'forming';

  if (n < 100) {
    alerts.push(`Sample is still ${n} analyses — intelligence is directional until n is larger and optional human labels exist.`);
  }

  const headline = n === 0
    ? 'No analyses yet.'
    : maturity === 'early'
      ? `Early signal from ${n} analyses — patterns are forming.`
      : maturity === 'forming'
        ? `Forming intelligence from ${n} analyses.`
        : `Live intelligence from ${n} analyses.`;

  return {
    headline,
    maturity,
    modelHeadline,
    bullets: bullets.slice(0, 8),
    alerts: alerts.slice(0, 5),
    mlHybrid: { withMl: mlUsed, mlOffline },
  };
}


// ─────────────────────────────────────────────
// MASTER
// ─────────────────────────────────────────────

async function getFullAnalytics() {
  const records = loadAnalyses();

  if (!records.length) {
    const info = storage.getStorageInfo ? storage.getStorageInfo() : {};
    return {
      empty: true,
      recordCount: 0,
      message: 'No analyses yet. Run a job check on the homepage, then refresh this page.',
      trustNote: 'If you already ran checks and still see zero, the server cannot write data/analyses.json (check permissions or VERIFYJOBS_DATA_DIR).',
      storage: info,
      model: await getTrainedModelMetrics(),
    };
  }

  const trainedModel = await getTrainedModelMetrics();
  const overview = getOverviewStats(records);
  const segments = getSegmentInsights(records);
  const queries = {
    bySource: runQuery('scam_rate_by_source').result,
    dailyVolume: runQuery('daily_volume').result,
    topRedFlags: runQuery('top_red_flags').result,
    scoreHistogram: runQuery('score_distribution').result,
    rolling7d: runQuery('rolling_7day').result,
  };
  const intelligence = buildIntelligence(records, overview, segments, queries, trainedModel);

  return {
    empty: false,
    recordCount: records.length,
    trustNote:
      'High-risk rates use risk ≥ 65 as an operational proxy (not human labels). ' +
      'Model quality is the trained hold-out set from serve.py. Insights below are derived from live traffic patterns.',
    intelligence,
    overview,
    model: trainedModel,
    abTest: runABTest(records),
    causal: runDifferenceInDifferences(records),
    cohorts: getCohortAnalysis(records),
    segments,
    queries,
    storage: storage.getStorageInfo ? storage.getStorageInfo() : undefined,
    generatedAt: new Date().toISOString(),
  };
}

module.exports = {
  getFullAnalytics,
  getOverviewStats,
  getModelMetrics,
  getTrainedModelMetrics,
  runABTest,
  runDifferenceInDifferences,
  getCohortAnalysis,
  getSegmentInsights,
  runQuery,
  loadAnalyses,
  extractFeatures,
};
