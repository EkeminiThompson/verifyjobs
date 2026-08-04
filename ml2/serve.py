# ml/serve.py
"""
VerifyJobs ML — Inference Server
==================================
FastAPI server that loads the trained ensemble and serves predictions.
Node.js server.js calls this over HTTP at startup and on each analysis.

Endpoints:
  POST /predict          — single job posting → { ml_prob, ml_score, confidence }
  POST /predict/batch    — list of texts → array of predictions
  GET  /health           — liveness check + model info
  GET  /model-info       — metrics, thresholds, feature importances

Run locally:
  uvicorn ml.serve:app --host 0.0.0.0 --port 8001 --workers 1

Run with auto-reload (dev):
  uvicorn ml.serve:app --reload --port 8001

In production (keep alive alongside Node):
  Add to your Procfile:  ml: uvicorn ml.serve:app --host 0.0.0.0 --port 8001
  Or use PM2:            pm2 start "uvicorn ml.serve:app --port 8001" --name verifyjobs-ml
"""

import json
import os
import pickle
import re
import time
import unicodedata
import warnings
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

import numpy as np
import pandas as pd
import torch
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

warnings.filterwarnings('ignore')

ROOT       = Path(__file__).parent.parent
MODELS_DIR = ROOT / 'models'

# ── GLOBAL STATE ──────────────────────────────────────────────────────────────
# Loaded once at startup, shared across requests

_state = {
    'xgb_model':    None,
    'builder':      None,
    'bert_model':   None,
    'bert_tok':     None,
    'meta_learner': None,
    'calibrator':   None,
    'config':       None,
    'xgb_meta':     None,
    'bert_meta':    None,
    'device':       None,
    'ready':        False,
    'startup_time': None,
}

# ── FEATURE ENGINEERING (must match data_prep.py exactly) ────────────────────

_NAIRA_RE       = re.compile(r'₦\s*[\d,]+|ngn\s*[\d,]+|\bnaira\b', re.I)
_WHATSAPP_RE    = re.compile(r'whatsapp', re.I)
_TELEGRAM_RE    = re.compile(r'telegram', re.I)
_UPFRONT_RE     = re.compile(
    r'pay\s+(registration|fee|upfront|deposit|training|equipment|setup|starter)|'
    r'registration\s+fee|activation\s+fee|starter\s+kit', re.I)
_CRYPTO_RE      = re.compile(
    r'bitcoin|usdt|tether|ethereum|binance|coinbase|crypto(currency)?|'
    r'blockchain\s+wallet|digital\s+(currency|wallet)', re.I)
_TASK_RE        = re.compile(
    r'\btask\b.*\bearn\b|\bcomplete\s+tasks?\b|daily\s+(task|mission)|'
    r'amazon\s+(review|task)|product\s+(review|rating)\s+(task|job)', re.I)
_URGENT_RE      = re.compile(
    r'urgent(ly)?|limited\s+slots?|apply\s+(now|immediately|fast|today)|'
    r'only\s+\d+\s+(positions?|slots?)|closing\s+(soon|today)', re.I)
_FREE_EMAIL_RE  = re.compile(
    r'@(gmail|yahoo|hotmail|outlook|protonmail|yandex|mail\.com)\.', re.I)
_NO_EXP_RE      = re.compile(
    r'no\s+(experience|qualification|degree|skills?)\s+(needed|required)|'
    r'anyone\s+can\s+(do|apply)', re.I)
_HIGH_SALARY_RE = re.compile(
    r'\$\s*\d{3,}\s*(per|/)\s*(day|hour)|\bkd?\s*\d{4,}\s*(daily|weekly)|'
    r'₦\s*\d{6,}\s*(daily|weekly|per\s+(day|week))', re.I)
_INTERVIEW_RE   = re.compile(
    r'phone\s+screen|technical\s+interview|panel\s+interview|'
    r'zoom\s+interview|video\s+interview|in[-\s]?person\s+interview', re.I)
_ATS_RE         = re.compile(
    r'greenhouse\.io|lever\.co|workday\.com|bamboohr\.com|'
    r'ashbyhq\.com|smartrecruiters\.com|icims\.com|jobvite\.com', re.I)
_COMPANY_EMAIL_RE = re.compile(
    r'@(?!gmail|yahoo|hotmail|outlook|protonmail)[a-z0-9.\-]+\.(com|org|net|co|io)\b',
    re.I)


def _flag(pattern, text): return int(bool(pattern.search(text)))


def _naira_max(text):
    amounts = _NAIRA_RE.findall(text)
    if not amounts: return 0
    nums = [int(re.sub(r'[^\d]', '', a)) for a in amounts if re.sub(r'[^\d]', '', a)]
    return max(nums) if nums else 0


def _emoji_count(text):
    return sum(1 for c in text
               if unicodedata.category(c) in ('So', 'Sm') or
               '\U0001F300' <= c <= '\U0001FAFF')


def clean_text(text: str) -> str:
    text = unicodedata.normalize('NFKC', text)
    text = re.sub(r'https?://\S+', ' URL ', text)
    text = re.sub(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b',
                  ' EMAIL ', text)
    text = re.sub(r'\+?\d[\d\s\-().]{7,}\d', ' PHONE ', text)
    text = re.sub(r'[\r\n\t]+', ' ', text)
    text = re.sub(r'[ ]{2,}', ' ', text)
    return text.strip()


def build_row(text: str) -> pd.DataFrame:
    """Build a single-row DataFrame with all features from raw text."""
    t = clean_text(text)
    words = t.split()
    row = {
        'text_clean':          t,
        # Structural defaults (no Kaggle metadata available at inference time)
        'has_salary':          0,
        'has_company_profile': 0,
        'has_logo':            0,
        'has_questions':       0,
        'telecommuting':       0,
        'employment_type':     '',
        'required_experience': '',
        'required_education':  '',
        # Lexical
        'word_count':          len(words),
        'char_count':          len(t),
        'avg_word_len':        len(t) / max(len(words), 1),
        'upper_ratio':         sum(1 for c in t if c.isupper()) / max(len(t), 1),
        'exclaim_count':       t.count('!'),
        'emoji_count':         _emoji_count(t),
        'digit_ratio':         sum(1 for c in t if c.isdigit()) / max(len(t), 1),
        # Signals
        'has_naira':           _flag(_NAIRA_RE, t),
        'naira_max_amount':    _naira_max(t),
        'has_whatsapp':        _flag(_WHATSAPP_RE, t),
        'has_telegram':        _flag(_TELEGRAM_RE, t),
        'has_upfront_fee':     _flag(_UPFRONT_RE, t),
        'has_crypto':          _flag(_CRYPTO_RE, t),
        'has_task_pattern':    _flag(_TASK_RE, t),
        'has_urgency':         _flag(_URGENT_RE, t),
        'has_free_email':      _flag(_FREE_EMAIL_RE, t),
        'has_no_exp_req':      _flag(_NO_EXP_RE, t),
        'has_high_salary':     _flag(_HIGH_SALARY_RE, t),
        'has_interview_proc':  _flag(_INTERVIEW_RE, t),
        'has_ats_platform':    _flag(_ATS_RE, t),
        'has_company_email':   _flag(_COMPANY_EMAIL_RE, t),
    }
    row['whatsapp_and_upfront']   = int(row['has_whatsapp'] and row['has_upfront_fee'])
    row['task_and_high_salary']   = int(row['has_task_pattern'] and row['has_high_salary'])
    row['free_email_and_urgency'] = int(row['has_free_email'] and row['has_urgency'])
    row['no_exp_and_high_salary'] = int(row['has_no_exp_req'] and row['has_high_salary'])
    return pd.DataFrame([row])


# ── PREDICTION CORE ───────────────────────────────────────────────────────────

@torch.no_grad()
def _bert_prob(texts: List[str]) -> np.ndarray:
    tok   = _state['bert_tok']
    model = _state['bert_model']
    dev   = _state['device']
    enc   = tok(texts, truncation=True, padding=True,
                max_length=512, return_tensors='pt')
    enc   = {k: v.to(dev) for k, v in enc.items()}
    out   = model(**enc)
    return torch.softmax(out.logits, dim=-1)[:, 1].cpu().numpy()


def predict_texts(texts: List[str]) -> List[dict]:
    rows = [build_row(t) for t in texts]
    df   = pd.concat(rows, ignore_index=True)

    # XGBoost
    X         = _state['builder'].transform(df)
    xgb_probs = _state['xgb_model'].predict_proba(X)[:, 1]

    # BERT (if available)
    use_bert = _state['config']['use_bert'] and _state['bert_model'] is not None
    if use_bert:
        bert_probs = _bert_prob(df['text_clean'].tolist())
    else:
        bert_probs = xgb_probs.copy()

    # Meta-learner
    meta = _state['meta_learner']
    if meta is not None and use_bert:
        meta_X     = np.column_stack([xgb_probs, bert_probs])
        raw_probs  = meta.predict_proba(meta_X)[:, 1]
    else:
        raw_probs = xgb_probs

    # Calibration
    cal_probs = _state['calibrator'].transform(raw_probs)
    threshold = _state['config']['threshold']

    results = []
    for i, (cal_p, xgb_p) in enumerate(zip(cal_probs, xgb_probs)):
        row     = df.iloc[i]
        ml_score = int(round(cal_p * 100))

        # Confidence based on distance from threshold
        dist       = abs(cal_p - threshold)
        confidence = (
            'very_high' if dist > 0.35 else
            'high'      if dist > 0.20 else
            'medium'    if dist > 0.10 else
            'low'
        )

        # Key signals that fired
        fired = [
            k for k in [
                'has_upfront_fee', 'has_crypto', 'has_task_pattern',
                'has_whatsapp', 'has_telegram', 'has_free_email',
                'has_urgency', 'has_no_exp_req', 'has_high_salary',
                'has_interview_proc', 'has_ats_platform',
            ]
            if row.get(k, 0) == 1
        ]

        results.append({
            'ml_prob':      float(cal_p),
            'ml_score':     ml_score,
            'xgb_prob':     float(xgb_p),
            'bert_prob':    float(bert_probs[i]) if use_bert else None,
            'prediction':   'scam' if cal_p >= threshold else 'legitimate',
            'confidence':   confidence,
            'threshold':    float(threshold),
            'use_bert':     use_bert,
            'signals_fired': fired,
        })

    return results


# ── STARTUP / SHUTDOWN ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load all models at startup. Fail fast if critical models missing."""
    print("[ML Server] Loading models...")
    t0 = time.time()

    # XGBoost (required)
    xgb_path = MODELS_DIR / 'xgboost_pipeline.pkl'
    if not xgb_path.exists():
        raise RuntimeError(
            "XGBoost model not found. Run: python ml/train_xgboost.py")
    with open(xgb_path, 'rb') as f:
        bundle = pickle.load(f)
    _state['xgb_model'] = bundle['model']
    _state['builder']   = bundle['builder']
    with open(MODELS_DIR / 'xgboost_meta.json') as f:
        _state['xgb_meta'] = json.load(f)
    print(f"[ML Server] ✅ XGBoost loaded")

    # BERT (optional)
    bert_dir = MODELS_DIR / 'bert'
    if bert_dir.exists():
        try:
            from transformers import (
                DistilBertTokenizerFast,
                DistilBertForSequenceClassification,
            )
            _state['device']     = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            _state['bert_tok']   = DistilBertTokenizerFast.from_pretrained(str(bert_dir))
            _state['bert_model'] = DistilBertForSequenceClassification.from_pretrained(
                str(bert_dir))
            _state['bert_model'].to(_state['device'])
            _state['bert_model'].eval()
            with open(MODELS_DIR / 'bert_meta.json') as f:
                _state['bert_meta'] = json.load(f)
            print(f"[ML Server] ✅ DistilBERT loaded on {_state['device']}")
        except Exception as e:
            print(f"[ML Server] ⚠ DistilBERT load failed: {e}")

    # Ensemble meta-learner + calibrator (required)
    meta_path = MODELS_DIR / 'ensemble_meta.pkl'
    cal_path  = MODELS_DIR / 'calibration.pkl'
    if not meta_path.exists() or not cal_path.exists():
        raise RuntimeError(
            "Ensemble models not found. Run: python ml/ensemble.py")
    with open(meta_path, 'rb') as f:
        _state['meta_learner'] = pickle.load(f)
    with open(cal_path, 'rb') as f:
        _state['calibrator'] = pickle.load(f)
    with open(MODELS_DIR / 'ensemble_config.json') as f:
        _state['config'] = json.load(f)

    _state['ready']        = True
    _state['startup_time'] = time.time() - t0
    print(f"[ML Server] ✅ All models ready in {_state['startup_time']:.1f}s")

    yield  # Server runs here

    print("[ML Server] Shutting down")


# ── APP ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title='VerifyJobs ML Inference',
    version='1.0',
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:3000', 'https://verifyjobs.org'],
    allow_methods=['GET', 'POST'],
    allow_headers=['Content-Type'],
)


# ── SCHEMAS ───────────────────────────────────────────────────────────────────

class PredictRequest(BaseModel):
    text:      str        = Field(..., min_length=10, max_length=50_000)
    job_title: str        = Field('', max_length=200)
    source:    str        = Field('', max_length=100)

class BatchRequest(BaseModel):
    texts: List[str] = Field(..., min_items=1, max_items=50)

class PredictResponse(BaseModel):
    ml_prob:       float
    ml_score:      int
    xgb_prob:      float
    bert_prob:     Optional[float]
    prediction:    str
    confidence:    str
    threshold:     float
    use_bert:      bool
    signals_fired: List[str]
    latency_ms:    float


# ── ENDPOINTS ─────────────────────────────────────────────────────────────────

@app.get('/health')
def health():
    if not _state['ready']:
        raise HTTPException(status_code=503, detail='Models not yet loaded')
    return {
        'status':       'ok',
        'ready':        True,
        'startup_time': _state['startup_time'],
        'use_bert':     _state['config']['use_bert'],
        'device':       str(_state['device']) if _state['device'] else 'cpu',
        'threshold':    _state['config']['threshold'],
    }


@app.get('/model-info')
def model_info():
    if not _state['ready']:
        raise HTTPException(status_code=503, detail='Not ready')
    return {
        'xgb_test_metrics':  _state['xgb_meta']['test_metrics'],
        'ensemble_test_metrics': _state['config']['test_metrics'],
        'bert_test_metrics': _state['bert_meta'] if _state['bert_meta'] else None,
        'threshold':         _state['config']['threshold'],
        'top_features':      _state['xgb_meta']['top_features'][:20],
        'xgb_weight':        _state['config']['xgb_weight'],
        'bert_weight':       _state['config']['bert_weight'],
    }


@app.post('/predict', response_model=PredictResponse)
def predict(req: PredictRequest):
    if not _state['ready']:
        raise HTTPException(status_code=503, detail='Models not yet loaded')
    t0      = time.time()
    results = predict_texts([req.text])
    r       = results[0]
    r['latency_ms'] = round((time.time() - t0) * 1000, 1)
    return r


@app.post('/predict/batch')
def predict_batch(req: BatchRequest):
    if not _state['ready']:
        raise HTTPException(status_code=503, detail='Models not yet loaded')
    t0      = time.time()
    results = predict_texts(req.texts)
    ms      = round((time.time() - t0) * 1000, 1)
    return {'predictions': results, 'latency_ms': ms, 'count': len(results)}


# ── DEV ENTRY POINT ───────────────────────────────────────────────────────────

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('ml.serve:app', host='0.0.0.0', port=8001, reload=False)
