# VerifyJobs ML Pipeline
## From zero to trained ensemble in 4 steps

---

## Prerequisites

- Python 3.11+ (`python --version`)
- Node.js 18+ (your existing server)
- Kaggle account (free)
- Thinking Machines compute credits (for BERT step only)

---

## Step 0 — Install Python dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

If you're on GitHub Codespaces and want to avoid touching system Python:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Step 1 — Get the Kaggle dataset

1. Go to: https://www.kaggle.com/datasets/shivamb/real-or-fake-fake-jobposting-prediction
2. Click **Download** → you get `fake_job_postings.csv`
3. Rename it to `kaggle_jobs.csv` and place it at: `data/kaggle_jobs.csv`

That's 17,880 rows of labelled job postings (real and fake).

---

## Step 2 — Add your manual labels (Nigerian/WhatsApp scams)

The file `data/manual_labels/labels.csv` already has 20 pre-filled examples.

Add your own rows in the same format:
```
text,label,source,notes
"Full job posting text here",1,whatsapp,advance_fee
"Another job posting",0,linkedin,legitimate
```

- `label`: 1 = scam, 0 = legitimate
- `source`: whatsapp | email | telegram | facebook | linkedin | jobberman | other
- `notes`: optional description of scam type

**Aim for 200-300 Nigerian/WhatsApp examples.** Even 50 good labelled posts
will measurably improve the model's performance on your target domain.

---

## Step 3 — Prepare data

```bash
python ml/data_prep.py
```

This will:
- Load Kaggle CSV + your manual labels
- Merge and deduplicate
- Engineer 30+ features (naira amounts, WhatsApp signals, urgency patterns, etc.)
- Split into train/val/test (70/15/15)
- Save to `data/processed/`

Expected output:
```
Combined dataset: 18,000+ rows | Scam: 900+ (5.0%) | Legit: 17,100+
Splits:
  Train: 12,600 | Scam rate: 5.0%
  Val:   2,700  | Scam rate: 5.0%
  Test:  2,700  | Scam rate: 5.0%
```

---

## Step 4a — Train XGBoost (Codespaces, no GPU needed)

```bash
python ml/train_xgboost.py
```

With optional hyperparameter tuning (takes ~30 min, improves AUC by ~2-3%):
```bash
python ml/train_xgboost.py --tune
```

Expected results:
```
Test AUC:   0.97+
Test AUPRC: 0.85+
Test F1:    0.82+
```

Output: `models/xgboost_pipeline.pkl`, `models/xgboost_meta.json`

---

## Step 4b — Fine-tune DistilBERT (uses compute credits)

### Option A: Modal (Thinking Machines)

```bash
pip install modal
modal token new
modal run ml/train_bert.py::main_modal
```

This sends training to Modal's A10G GPU. Takes ~45 minutes.
Estimated cost: $0.50–$1.50 from your credits.

### Option B: SSH into a GPU instance

If Thinking Machines gives you SSH access to a GPU box:
```bash
scp -r data/ user@your-gpu-box:~/verifyjobs/
scp -r ml/  user@your-gpu-box:~/verifyjobs/
ssh user@your-gpu-box
cd ~/verifyjobs
pip install -r requirements.txt
python ml/train_bert.py --epochs 3 --batch_size 32
scp -r user@your-gpu-box:~/verifyjobs/models/ ./models/
```

### Option C: Google Colab (free T4)

Upload `data/processed/` to Google Drive, then run `train_bert.py` in Colab.

Expected results:
```
Test AUC:   0.98+
Test AUPRC: 0.90+
Test F1:    0.86+
```

Output: `models/bert/` directory (HuggingFace format), `models/bert_meta.json`

---

## Step 5 — Build ensemble

```bash
python ml/ensemble.py
```

This stacks XGBoost + BERT using a meta-learner trained on validation predictions.
If BERT is not trained yet, it runs XGBoost-only and you can re-run later.

Expected results (ensemble):
```
Test AUC:   0.98+
Test AUPRC: 0.92+
Test F1:    0.87+
```

Output: `models/ensemble_meta.pkl`, `models/calibration.pkl`, `models/ensemble_config.json`

---

## Step 6 — Integrate with Node.js server

Apply the patch from `server_ml_patch.js`:

1. In `server.js`, add the import:
   ```js
   const { enrichWithML, checkServerHealth } = require('./engine/ml_scorer');
   ```

2. Make your `/analyze` route async and wrap `analyzeJob()`:
   ```js
   app.post('/analyze', validateTextInput, async (req, res) => {
     const { text, jobTitle, source } = req.validatedInput;
     const ruleResult = analyzeJob(text, jobTitle, source);
     const result     = await enrichWithML(text, ruleResult);
     res.json(result);
   });
   ```

3. Add to your `.env`:
   ```
   ENABLE_ML=true
   ML_PORT=8001
   ML_TIMEOUT=5000
   ```

4. Start both servers:
   ```bash
   # Terminal 1 — ML inference server
   uvicorn ml.serve:app --host 0.0.0.0 --port 8001

   # Terminal 2 — Node.js server
   node server.js
   ```

   Or let Node start the ML server automatically (see `server_ml_patch.js`).

---

## Directory structure after training

```
verifyjobs/
├── data/
│   ├── kaggle_jobs.csv           ← download from Kaggle
│   ├── manual_labels/
│   │   └── labels.csv            ← your labelled Nigerian scam posts
│   └── processed/
│       ├── train.parquet
│       ├── val.parquet
│       ├── test.parquet
│       └── feature_meta.json
├── models/
│   ├── xgboost_pipeline.pkl      ← TF-IDF + XGBoost
│   ├── xgboost_meta.json
│   ├── bert/                     ← DistilBERT fine-tuned
│   ├── bert_meta.json
│   ├── ensemble_meta.pkl         ← logistic regression meta-learner
│   ├── calibration.pkl           ← isotonic calibrator
│   └── ensemble_config.json
├── ml/
│   ├── data_prep.py
│   ├── train_xgboost.py
│   ├── train_bert.py
│   ├── ensemble.py
│   └── serve.py
├── engine/
│   ├── analyzer.js               ← existing rule engine (unchanged)
│   ├── ml_scorer.js              ← NEW: hybrid blending layer
│   └── storage.js                ← existing (unchanged)
├── requirements.txt
└── server.js                     ← add 6 lines (see server_ml_patch.js)
```

---

## How the hybrid scoring works

```
Job posting text
      │
      ├──▶ Rule engine (analyzer.js)    → rule_score (0–100)
      │
      └──▶ ML server (/predict)
              ├── XGBoost (TF-IDF)      → xgb_prob
              ├── DistilBERT            → bert_prob
              ├── Meta-learner          → ensemble_prob
              └── Isotonic calibrator   → calibrated_prob

Blend:
  • Both agree + ML high confidence  → 70% ML + 30% rules
  • Both agree + ML medium           → 55% ML + 45% rules
  • They disagree (>35 pts)          → conservative_max (safety first)
  • ML unreachable                   → 100% rules + hard floors

Hard floors (always applied, regardless of model):
  • Upfront fee detected             → minimum score 68
  • Crypto payment requested         → minimum score 72
  • Wallet funding required          → minimum score 80
  • ₦500k+/day salary claim          → minimum score 65
```

---

## Retraining

As you accumulate more labelled data from production (user reports, flagged
analyses), retrain monthly:

```bash
# Export production analyses with confirmed labels
# Add them to data/manual_labels/labels.csv

python ml/data_prep.py       # re-merge
python ml/train_xgboost.py   # retrain XGBoost (Codespaces)
python ml/train_bert.py      # retrain BERT (compute credits)
python ml/ensemble.py        # re-stack
# restart serve.py
```

The model will continuously improve as you label more Nigerian-context scams.
