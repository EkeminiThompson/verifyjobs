// server.js — ML integration patch
// ===================================
// These are the ONLY changes needed to integrate the ML model
// into your existing server.js. Apply them as a diff.
//
// CHANGE 1: Add import at the top (after existing requires)
// CHANGE 2: Replace analyzeJob() calls with enrichWithML() wrapper
// CHANGE 3: Add ML server startup check
//
// ─────────────────────────────────────────────────────────────────────────────

// ── CHANGE 1: Add this import alongside your existing requires ────────────────
//
// Find this line in server.js:
//   const analyzeJob = require('./engine/analyzer');
//
// Replace with:
const analyzeJob    = require('./engine/analyzer');
const { enrichWithML, checkServerHealth } = require('./engine/ml_scorer');

// ── CHANGE 2: Text analysis endpoint ─────────────────────────────────────────
//
// Find your POST /analyze handler. Change this:
//
//   const result = analyzeJob(text, jobTitle, source);
//   res.json(result);
//
// To this:

async function analyzeTextWithML(text, jobTitle, source) {
  const ruleResult = analyzeJob(text, jobTitle, source);
  return await enrichWithML(text, ruleResult);
}

// Your route becomes:
// app.post('/analyze', validateTextInput, async (req, res) => {   // <-- add async
//   const { text, jobTitle, source } = req.validatedInput;
//   const result = await analyzeTextWithML(text, jobTitle, source); // <-- await
//   res.json(result);
// });

// ── CHANGE 3: URL analysis endpoint ──────────────────────────────────────────
//
// Find where you call analyzeJob in /analyze-url:
//   const analysis = analyzeJob(ctx.combinedText, ctx.pageTitle, 'URL');
//
// Change to:
//   const analysis = await enrichWithML(ctx.combinedText,
//                      analyzeJob(ctx.combinedText, ctx.pageTitle, 'URL'));

// ── CHANGE 4: File analysis endpoint ─────────────────────────────────────────
//
// Find where you call analyzeJob in /analyze-file:
//   const result = analyzeJob(text, jobTitle, 'File Upload');
//
// Change to:
//   const ruleResult = analyzeJob(text, jobTitle, 'File Upload');
//   const result     = await enrichWithML(text, ruleResult);

// ── CHANGE 5: Add ML health info to /health endpoint ─────────────────────────
//
// In your GET /health handler, add:
//   const mlReady = await checkServerHealth().catch(() => false);
//   res.json({
//     ...existingHealthData,
//     ml: { available: mlReady, host: process.env.ML_HOST || 'localhost', port: 8001 }
//   });

// ── CHANGE 6: Add ML endpoint for transparency ────────────────────────────────
//
// Optionally add a passthrough to the ML server's model-info:
app.get('/ml-info', async (req, res) => {
  try {
    const response = await fetch(`http://${process.env.ML_HOST || 'localhost'}:8001/model-info`);
    const data     = await response.json();
    res.json(data);
  } catch (err) {
    res.status(503).json({ error: 'ML server unavailable', message: err.message });
  }
});

// ── STARTUP: Start ML server as child process ─────────────────────────────────
//
// Add this near the bottom of server.js, just before server.listen():

const { spawn } = require('child_process');

function startMLServer() {
  const mlPort    = process.env.ML_PORT    || '8001';
  const mlWorkers = process.env.ML_WORKERS || '1';

  console.log(`🤖 Starting ML inference server on port ${mlPort}...`);

  const mlProc = spawn('uvicorn', [
    'ml.serve:app',
    '--host', '0.0.0.0',
    '--port', mlPort,
    '--workers', mlWorkers,
  ], {
    cwd:   __dirname,
    stdio: 'pipe',
    env:   { ...process.env, PYTHONUNBUFFERED: '1' },
  });

  mlProc.stdout.on('data', (d) => {
    const line = d.toString().trim();
    if (line) console.log(`[ML] ${line}`);
  });
  mlProc.stderr.on('data', (d) => {
    const line = d.toString().trim();
    if (line && !line.includes('INFO')) console.error(`[ML] ${line}`);
  });
  mlProc.on('exit', (code) => {
    if (code !== 0) {
      console.warn(`[ML] Server exited with code ${code} — rule engine only`);
    }
  });
  mlProc.on('error', (err) => {
    console.warn(`[ML] Failed to start: ${err.message} — rule engine only`);
  });

  // Graceful shutdown: kill ML process when Node exits
  process.on('exit',    () => mlProc.kill());
  process.on('SIGTERM', () => mlProc.kill());
  process.on('SIGINT',  () => mlProc.kill());

  return mlProc;
}

// Call this just before server.listen():
// if (process.env.ENABLE_ML !== 'false') {
//   startMLServer();
// }

// ── ENV VARS to add to your .env ─────────────────────────────────────────────
//
// ENABLE_ML=true          # set to false to disable ML entirely
// ML_HOST=localhost       # ML server host
// ML_PORT=8001            # ML server port
// ML_TIMEOUT=5000         # ms to wait for ML response before falling back
// ML_WORKERS=1            # uvicorn workers (1 is fine for single-GPU)
