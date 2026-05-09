const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');

// Core modules
const analyzeJob = require('./engine/analyzer');
const { ensureStorage, getAllAnalyses } = require('./engine/storage');

const app = express();
const PORT = process.env.PORT || 3000;

// ====================== MULTER ======================
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.pdf', '.doc', '.docx'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Only PDF and Word files (.pdf, .doc, .docx) allowed'));
  }
});

// ====================== MIDDLEWARE ======================
app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname)));

ensureStorage();

// Safe PDF Parse Import - FIXED VERSION
let pdfParse;
try {
  // pdf-parse exports a function directly
  pdfParse = require('pdf-parse');
  console.log('✅ pdf-parse loaded successfully');
} catch (e) {
  console.error('❌ Failed to load pdf-parse:', e.message);
}

// ====================== ROUTES ======================

// Text Analysis
app.post('/analyze', (req, res) => {
  try {
    const { text, jobTitle = "Untitled Job", source = "Manual" } = req.body;
    if (!text || text.trim().length === 0) {
      return res.status(400).json({ error: 'Job description text is required' });
    }
    const result = analyzeJob(text, jobTitle, source);
    res.json(result);
  } catch (err) {
    console.error('Analysis error:', err);
    res.status(500).json({ error: err.message });
  }
});

// File Analysis - FIXED PDF PARSING
app.post('/analyze-file', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const file = req.file;
    const jobTitle = req.body.jobTitle || file.originalname;
    let extractedText = '';

    const ext = path.extname(file.originalname).toLowerCase();

    if (ext === '.pdf') {
      if (!pdfParse) throw new Error('PDF parser not available');
      
      // FIXED: Direct function call with buffer
      const data = await pdfParse(file.buffer);
      extractedText = data.text || '';
    } 
    else if (ext === '.docx' || ext === '.doc') {
      const mammoth = require('mammoth');
      const result = await mammoth.extractRawText({ buffer: file.buffer });
      extractedText = result.value || '';
    }

    if (!extractedText || extractedText.trim().length < 30) {
      return res.status(400).json({ 
        error: 'Could not extract enough text. Please paste the job content manually.' 
      });
    }

    const result = analyzeJob(extractedText, jobTitle, "File Upload");

    res.json({
      ...result,
      filename: file.originalname,
      extractedLength: extractedText.length
    });

  } catch (err) {
    console.error('File analysis error:', err);
    res.status(500).json({ 
      error: 'File processing failed', 
      message: err.message 
    });
  }
});

// URL Analysis
app.post('/analyze-url', (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    const simulatedText = `Job from URL: ${url}\nRemote position with high pay. Easy requirements. Contact via WhatsApp.`;

    const result = analyzeJob(simulatedText, "URL Job Posting", "Website");

    res.json({
      ...result,
      url: url,
      note: "Basic URL analysis"
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// History
app.get('/analyses', (req, res) => {
  try {
    res.json(getAllAnalyses(50));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Job Scam Detector running on http://localhost:${PORT}`);
});