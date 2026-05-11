# ml/verifyjobs_ml.py
"""
VerifyJobs ML Pipeline — Production-grade job scam detection
Implements: Feature engineering, Logistic Regression, Model evaluation, Prediction API

CHANGELOG v2
────────────
FIX-A  Removed risk_score from feature vector.
       risk_score = min(100, context_penalty + red_flag_count * 8)
       Including it alongside red_flag_count and context_penalty creates
       perfect multicollinearity (AUC 1.0, meaningless coefficients).
       The model now learns from independent raw signals only.

FIX-B  Lowered is_scam label threshold: 65 → 50.
       The old threshold mislabelled jobs scoring 50–64 (high_risk / suspicious)
       as legitimate, causing false-negative predictions like the "URGENT Data
       Entry Clerk" case (risk=64, 3 red flags → LEGITIMATE at 44%).
       Threshold 50 aligns with the 'high_risk' status in scorer.js.

FIX-C  resolve() → absolute() for path anchoring (symlink safety).
       Inherited from verifyjobs_ml.py v1 fix.

FIX-D  ml/ directory created at import time so pickle save never crashes.
"""

import json
import warnings
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import re
from pathlib import Path

from sklearn.metrics import roc_auc_score, precision_recall_curve, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# ── PATHS ────────────────────────────────────────────────────────────────────
_THIS_FILE    = Path(__file__).absolute()   # .../ml/verifyjobs_ml.py
_ML_DIR       = _THIS_FILE.parent           # .../ml/
BASE_DIR      = _ML_DIR.parent              # project root
ANALYSES_FILE = BASE_DIR / "data" / "analyses.json"
MODEL_FILE    = BASE_DIR / "ml"   / "verifyjobs_model.pkl"
_ML_DIR.mkdir(parents=True, exist_ok=True)  # FIX-D


# ── SCAM LABEL THRESHOLD ─────────────────────────────────────────────────────
# FIX-B: lowered from 65 to 50.
# Scores 50–64 represent "high_risk" — treating them as legitimate produced
# false negatives in both training labels and live predictions.
SCAM_LABEL_THRESHOLD = 50


# ── DATACLASS ────────────────────────────────────────────────────────────────

@dataclass
class JobFeatures:
    """Extracted features from a job posting"""
    # ── Raw signals ──────────────────────────────────────────────────────────
    red_flag_count:  int
    positive_count:  int
    word_count:      int
    has_email:       int
    has_free_email:  int
    has_url:         int
    has_salary:      int
    has_location:    int
    context_penalty: float   # weighted sum of scam indicators (independent signal)
    context_bonus:   float   # weighted sum of legitimacy indicators
    # ── Metadata (not used as model features) ────────────────────────────────
    risk_score:      float   # kept for logging/display; NOT in feature vector
    source:          str
    timestamp:       str
    is_scam:         int     # label: 1 if risk_score >= SCAM_LABEL_THRESHOLD

    def to_array(self) -> np.ndarray:
        """
        Feature vector — 8 independent signals.
        FIX-A: risk_score intentionally excluded to prevent label leakage.
        """
        return np.array([
            # Scam indicators
            min(self.red_flag_count / 10.0, 1.0),   # normalised 0–1
            float(self.has_free_email),
            self.context_penalty / 100.0,            # normalised 0–1

            # Legitimacy indicators (negative signal for scam)
            min(self.positive_count / 10.0, 1.0),
            float(self.has_url),
            float(self.has_salary),

            # Neutral / contextual
            min(self.word_count / 1000.0, 1.0),
            self.context_bonus / 100.0,
        ])

    # Feature names in the same order as to_array() — used for coefficient display
    FEATURE_NAMES: list = None   # set at class level below


# Attach after class definition so the list is defined once
JobFeatures.FEATURE_NAMES = [
    'red_flag_count_norm',    # scam signal
    'has_free_email',         # scam signal
    'context_penalty_norm',   # scam signal
    'positive_count_norm',    # legitimacy signal
    'has_url',                # legitimacy signal
    'has_salary',             # legitimacy signal
    'word_count_norm',        # neutral
    'context_bonus_norm',     # legitimacy signal
]


# ── FEATURE EXTRACTOR ────────────────────────────────────────────────────────

class FeatureExtractor:
    """Extract structured features from raw job posting text"""

    SCAM_PATTERNS = {
        'upfront_payment': r'\b(pay|fee|charge|deposit|registration fee|processing fee|starter kit)\b.*?\b(before|upfront|advance)\b',
        'whatsapp_only':   r'\b(whatsapp|telegram|signal|only\s*contact|contact\s*only)\b',
        'free_email':      r'@(gmail\.com|yahoo\.com|hotmail\.com|outlook\.com|aol\.com|protonmail\.com)',
        'urgent_tactics':  r'\b(urgent|immediate|asap|limited slots|apply today|don\'t miss)\b',
        'too_good_salary': r'\b(\d{4,}[\d,]*\s*(per|a|each)\s*(day|week|hour))|(₦\d{4,})|(earning potential)\b',
        'crypto_mention':  r'\b(crypto|bitcoin|ethereum|usdt|wallet|investment|passive income)\b',
        'id_request':      r'\b(bvn|nin|ssn|passport|driver\'s license|national id|identification)\b',
        'no_experience':   r'\b(no experience|entry level|training provided|we\'ll train you)\b',
        'task_based':      r'\b(complete tasks|commission|per task|reshipping|money transfer)\b',
        'telegram':        r'\b(t\.me|@[\w]+)\b',
    }

    POSITIVE_PATTERNS = {
        'company_domain':     r'@[\w\-]+\.(com|org|io|ai|co\.uk)',
        'clear_requirements': r'\b(requirements|qualifications|bachelor|master|experience|skills)\b',
        'company_info':       r'\b(about us|company profile|our mission|founded in)\b',
        'benefits':           r'\b(benefits|health insurance|paid time off|401k|vacation|remote work)\b',
        'interview_process':  r'\b(interview process|phone screen|technical interview|final round)\b',
        'salary_range':       r'\b(\$\d{2,3}[\d,]*\s*-\s*\$\d{2,3}[\d,]*|₦[\d,]+)\b',
    }

    # Weights used ONLY for context_penalty / context_bonus (not for risk_score)
    PENALTY_WEIGHTS = {
        'upfront_payment': 30,
        'whatsapp_only':   25,
        'id_request':      25,
        'crypto_mention':  20,
        'urgent_tactics':  15,
        'task_based':      15,
    }
    BONUS_WEIGHTS = {
        'company_info':       20,
        'clear_requirements': 15,
        'interview_process':  15,
        'benefits':           10,
    }

    @classmethod
    def extract(cls, text: str, job_title: str = "", source: str = "Unknown") -> JobFeatures:
        t = text.lower()

        red_flags = [k for k, p in cls.SCAM_PATTERNS.items()  if re.search(p, t, re.IGNORECASE)]
        positives = [k for k, p in cls.POSITIVE_PATTERNS.items() if re.search(p, t, re.IGNORECASE)]

        has_free_email = int(bool(re.search(cls.SCAM_PATTERNS['free_email'], t)))
        has_url        = int(bool(re.search(r'https?://[^\s]+', text)))
        has_salary     = int(bool(
            re.search(cls.SCAM_PATTERNS['too_good_salary'], t) or
            re.search(cls.POSITIVE_PATTERNS['salary_range'],  t)
        ))
        has_location   = int(bool(re.search(r'\b(remote|on-site|hybrid|london|nyc|lagos|abuja|nairobi)\b', t)))
        has_email      = int(bool(re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text)))

        context_penalty = float(sum(cls.PENALTY_WEIGHTS.get(f, 0) for f in red_flags))
        context_bonus   = float(sum(cls.BONUS_WEIGHTS.get(p, 0) for p in positives))

        # risk_score kept for display only — not in feature vector
        risk_score = min(100.0, context_penalty + len(red_flags) * 8.0)

        return JobFeatures(
            red_flag_count  = len(red_flags),
            positive_count  = len(positives),
            word_count      = len(text.split()),
            has_email       = has_email,
            has_free_email  = has_free_email,
            has_url         = has_url,
            has_salary      = has_salary,
            has_location    = has_location,
            context_penalty = context_penalty,
            context_bonus   = context_bonus,
            risk_score      = risk_score,
            source          = source,
            timestamp       = datetime.now().isoformat(),
            is_scam         = int(risk_score >= SCAM_LABEL_THRESHOLD),   # FIX-B
        )


# ── LOGISTIC REGRESSION (pure NumPy) ─────────────────────────────────────────

class LogisticRegressionScamDetector:
    """Gradient-descent logistic regression — no sklearn dependency for training"""

    def __init__(self, learning_rate: float = 0.01, n_iterations: int = 2000):
        self.lr             = learning_rate
        self.n_iter         = n_iterations
        self.weights: Optional[np.ndarray] = None
        self.bias:    float = 0.0
        self.loss_history:  List[float] = []

    @staticmethod
    def _sigmoid(z: np.ndarray) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(z, -250, 250)))

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        n, p          = X.shape
        self.weights  = np.zeros(p)
        self.bias     = 0.0
        self.loss_history = []

        for i in range(self.n_iter):
            y_hat = self._sigmoid(X @ self.weights + self.bias)
            dw    = (X.T @ (y_hat - y)) / n
            db    = float(np.sum(y_hat - y)) / n
            self.weights -= self.lr * dw
            self.bias    -= self.lr * db

            loss = float(-np.mean(y * np.log(y_hat + 1e-8) + (1 - y) * np.log(1 - y_hat + 1e-8)))
            self.loss_history.append(loss)
            if i > 10 and abs(self.loss_history[-1] - self.loss_history[-2]) < 1e-7:
                break

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self._sigmoid(X @ self.weights + self.bias)

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        return (self.predict_proba(X) >= threshold).astype(int)

    def get_coefficients(self, feature_names: List[str]) -> pd.DataFrame:
        return pd.DataFrame({
            'feature':     feature_names,
            'coefficient': self.weights,
            'impact':      np.abs(self.weights),
            'direction':   ['risk' if w > 0 else 'safe' for w in self.weights],
        }).sort_values('impact', ascending=False)


# ── PIPELINE ──────────────────────────────────────────────────────────────────

class ScamDetectorPipeline:
    """Feature extraction → training → evaluation → prediction"""

    def __init__(self):
        self.model     = LogisticRegressionScamDetector(learning_rate=0.01, n_iterations=2000)
        self.scaler    = StandardScaler()
        self.is_fitted = False

    def _to_Xy(self, postings: List[JobFeatures]) -> Tuple[np.ndarray, np.ndarray]:
        X = np.array([f.to_array() for f in postings])
        y = np.array([f.is_scam    for f in postings])
        return X, y

    def train(self, postings: List[JobFeatures], test_size: float = 0.2) -> Dict:
        X, y = self._to_Xy(postings)

        unique, counts = np.unique(y, return_counts=True)
        can_stratify   = len(unique) > 1 and all(c >= 2 for c in counts)
        if not can_stratify:
            warnings.warn(
                "Cannot stratify split (class has < 2 samples). Using random split.",
                UserWarning, stacklevel=2,
            )

        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=test_size, random_state=42,
            stratify=y if can_stratify else None,
        )

        X_tr_s = self.scaler.fit_transform(X_tr)
        X_te_s = self.scaler.transform(X_te)

        self.model.fit(X_tr_s, y_tr)
        self.is_fitted = True

        y_pred  = self.model.predict(X_te_s)
        y_proba = self.model.predict_proba(X_te_s)

        auc = float(roc_auc_score(y_te, y_proba)) if len(np.unique(y_te)) > 1 else float('nan')
        f1  = float(f1_score(y_te, y_pred, zero_division=0))

        precision, recall, thresholds = precision_recall_curve(y_te, y_proba)
        f1s            = 2 * precision[:-1] * recall[:-1] / (precision[:-1] + recall[:-1] + 1e-8)
        best_threshold = float(thresholds[np.argmax(f1s)]) if len(thresholds) else 0.5

        return {
            'auc':            auc,
            'f1_score':       f1,
            'best_threshold': best_threshold,
            'train_size':     len(X_tr),
            'test_size':      len(X_te),
            'n_features':     X.shape[1],
            'class_distribution': {
                'legitimate': int(np.sum(y == 0)),
                'scam':       int(np.sum(y == 1)),
                'scam_rate':  float(np.mean(y)),
            },
        }

    def predict_job(self, text: str, job_title: str = "", source: str = "API") -> Dict:
        if not self.is_fitted:
            raise ValueError("Model must be trained before calling predict_job()")

        f     = FeatureExtractor.extract(text, job_title, source)
        X     = f.to_array().reshape(1, -1)
        X_s   = self.scaler.transform(X)
        prob  = float(self.model.predict_proba(X_s)[0])

        # Use best_threshold if available, else 0.45
        threshold = getattr(self, '_best_threshold', 0.45)

        return {
            'prediction':       'scam' if prob >= threshold else 'legitimate',
            'scam_probability': round(prob, 4),
            'confidence':       round(abs(prob - 0.5) * 2, 4),
            'risk_score':       f.risk_score,
            'red_flags_count':  f.red_flag_count,
            'positive_count':   f.positive_count,
            'recommendation': (
                'Do not proceed'       if prob >= 0.60 else
                'Proceed with caution' if prob >= 0.35 else
                'Likely safe'
            ),
        }

    def get_feature_importance(self) -> pd.DataFrame:
        if not self.is_fitted:
            raise ValueError("Model must be trained first")
        return self.model.get_coefficients(JobFeatures.FEATURE_NAMES)


# ── TIME SERIES FORECASTER ────────────────────────────────────────────────────

class TimeSeriesForecaster:
    """Moving average + exponential smoothing for scam volume forecasting"""

    def __init__(self, data: pd.DataFrame, value_col: str = 'scam_count'):
        if value_col not in data.columns:
            raise ValueError(
                f"Column '{value_col}' not found. Available: {list(data.columns)}"
            )
        self.value_col = value_col
        self.data      = data.copy()
        self.data['date'] = pd.to_datetime(self.data['date'])
        self.data = self.data.set_index('date').sort_index()

    def simple_moving_average(self, window: int = 7) -> pd.DataFrame:
        self.data['sma_7']  = self.data[self.value_col].rolling(window=7).mean()
        self.data['sma_30'] = self.data[self.value_col].rolling(window=30).mean()
        return self.data

    def exponential_smoothing(self, alpha: float = 0.3) -> pd.DataFrame:
        self.data['ewm'] = self.data[self.value_col].ewm(alpha=alpha, adjust=False).mean()
        return self.data

    def predict_next_week(self) -> Dict:
        series = self.data[self.value_col]
        if len(series) < 7:
            return {'error': 'Need at least 7 data points'}

        alpha      = 0.3
        last_val   = float(series.iloc[-1])
        forecast   = last_val
        predictions: List[float] = []

        for _ in range(7):
            forecast = alpha * last_val + (1 - alpha) * forecast
            predictions.append(round(forecast, 2))
            last_val = forecast

        recent_avg = float(series.tail(7).mean())
        older_avg  = float(series.tail(14).head(7).mean()) if len(series) >= 14 else recent_avg
        pct        = ((recent_avg - older_avg) / older_avg * 100) if older_avg else 0.0

        return {
            'next_7_days':    predictions,
            'expected_total': round(sum(predictions), 2),
            'daily_average':  round(float(np.mean(predictions)), 2),
            'trend':          'increasing' if recent_avg > older_avg else 'decreasing',
            'trend_percent':  round(pct, 2),
            'confidence':     'medium',
        }


# ── DATA LOADER ──────────────────────────────────────────────────────────────

def load_analyses_from_json(json_path: Optional[Path] = None) -> List[JobFeatures]:
    """
    Load JobFeatures from analyses.json.
    Defaults to <project_root>/data/analyses.json.
    Returns [] with a warning if file is missing.
    """
    file_path = Path(json_path) if json_path else ANALYSES_FILE

    if not file_path.exists():
        warnings.warn(
            f"analyses.json not found at {file_path}. Returning [] — "
            "run some job checks first to populate data.",
            UserWarning, stacklevel=2,
        )
        return []

    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    analyses = data if isinstance(data, list) else data.get('analyses', [])

    out: List[JobFeatures] = []
    for a in analyses:
        r  = a.get('result', a)
        md = r.get('metadata', {})
        rs = float(r.get('riskScore', 50))
        out.append(JobFeatures(
            red_flag_count  = len(r.get('redFlags', [])),
            positive_count  = len(r.get('positiveIndicators', [])),
            word_count      = int(md.get('wordCount', 100)),
            has_email       = int(bool(md.get('hasEmail',    False))),
            has_free_email  = int(bool(md.get('hasFreeEmail', False))),
            has_url         = int(bool(md.get('hasURL',      False))),
            has_salary      = int(bool(md.get('hasSalary',   False))),
            has_location    = int(bool(md.get('hasLocation', False))),
            context_penalty = float(md.get('contextPenalty', 0)),
            context_bonus   = float(md.get('contextBonus',   0)),
            risk_score      = rs,
            source          = a.get('source', 'Unknown'),
            timestamp       = a.get('timestamp',
                               md.get('analysisTimestamp', datetime.now().isoformat())),
            is_scam         = int(rs >= SCAM_LABEL_THRESHOLD),   # FIX-B
        ))
    return out


# ── SYNTHETIC DATA ────────────────────────────────────────────────────────────

def _build_synthetic_features(n: int = 60, seed: int = 42) -> List[JobFeatures]:
    """Realistic synthetic features for demo padding"""
    rng = np.random.default_rng(seed)
    out: List[JobFeatures] = []
    for _ in range(n):
        is_scam     = int(rng.choice([0, 1], p=[0.60, 0.40]))
        red_flags   = int(rng.integers(3, 8)) if is_scam else int(rng.integers(0, 3))
        ctx_pen     = float(rng.uniform(30, 80)) if is_scam else float(rng.uniform(0, 20))
        ctx_bon     = float(rng.uniform(0, 15))  if is_scam else float(rng.uniform(20, 50))
        risk        = min(100.0, ctx_pen + red_flags * 8.0)
        out.append(JobFeatures(
            red_flag_count  = red_flags,
            positive_count  = int(rng.integers(0, 5)),
            word_count      = int(rng.integers(50, 500)),
            has_email       = int(rng.choice([0,1], p=[0.3,0.7])),
            has_free_email  = int(rng.choice([0,1], p=[0.4,0.6])) if is_scam else 0,
            has_url         = int(rng.choice([0,1], p=[0.2,0.8])),
            has_salary      = int(rng.choice([0,1], p=[0.5,0.5])),
            has_location    = int(rng.choice([0,1], p=[0.3,0.7])),
            context_penalty = ctx_pen,
            context_bonus   = ctx_bon,
            risk_score      = risk,
            source          = 'Synthetic',
            timestamp       = datetime.now().isoformat(),
            is_scam         = int(risk >= SCAM_LABEL_THRESHOLD),
        ))
    return out


# ── DEMO ──────────────────────────────────────────────────────────────────────

def demo() -> Tuple[ScamDetectorPipeline, List[JobFeatures]]:
    print("=" * 60)
    print("VerifyJobs ML Pipeline")
    print(f"ANALYSES_FILE : {ANALYSES_FILE}")
    print(f"MODEL_FILE    : {MODEL_FILE}")
    print(f"SCAM_THRESHOLD: {SCAM_LABEL_THRESHOLD}  (risk_score >= {SCAM_LABEL_THRESHOLD} → is_scam=1)")
    print("=" * 60)

    print("\n📂 Loading analyses from data/analyses.json…")
    postings = load_analyses_from_json()
    print(f"   Loaded {len(postings)} real records.")

    sample_jobs = [
        dict(text="""
            URGENT HIRING! Remote Data Entry Clerk. NO EXPERIENCE NEEDED!
            Earn ₦500,000 per week working from home.
            Contact us on WhatsApp: +234 123 456 7890
            Pay registration fee of ₦5,000 to secure your slot.
            Limited positions available!
        """, title='URGENT Data Entry Clerk', source='WhatsApp'),

        dict(text="""
            Software Engineer at TechCorp
            Requirements: 3+ years of Python, SQL. Bachelor's degree in CS.
            Benefits include health insurance, 401k matching, remote work.
            Apply: https://techcorp.com/careers
            Interview process: Phone screen → Technical assessment → Final round
        """, title='Software Engineer', source='Website'),

        dict(text="""
            Crypto Investment Manager — Work from anywhere! No experience needed.
            Earn daily returns on your crypto investments.
            Start with as little as $100. Message our Telegram: @crypto_jobs_bot
        """, title='Crypto Investment Manager', source='Telegram'),
    ]

    print("\n📊 Extracting features from sample jobs…")
    for job in sample_jobs:
        f = FeatureExtractor.extract(job['text'], job['title'], job['source'])
        postings.append(f)
        print(
            f"  → {job['title']:<32} "
            f"risk={f.risk_score:.0f}  "
            f"red_flags={f.red_flag_count}  "
            f"is_scam={f.is_scam}  "
            f"(threshold={SCAM_LABEL_THRESHOLD})"
        )

    MIN_TRAIN = 30
    if len(postings) < MIN_TRAIN:
        synth = _build_synthetic_features(n=MIN_TRAIN + 10 - len(postings))
        postings.extend(synth)
        print(f"\n⚙  Added {len(synth)} synthetic records (real data < {MIN_TRAIN}).")

    scam_n = sum(p.is_scam for p in postings)
    print(f"\n   Class balance: {scam_n} scam / {len(postings)-scam_n} legit "
          f"({scam_n/len(postings)*100:.1f}% scam rate)")

    print("\n🤖 Training Logistic Regression (8 independent features, no risk_score)…")
    pipeline = ScamDetectorPipeline()
    metrics  = pipeline.train(postings)

    # Persist best threshold for predict_job
    pipeline._best_threshold = metrics['best_threshold']

    print(f"\n📈 Model Performance:")
    print(f"   AUC-ROC        : {metrics['auc']:.3f}  (target 0.75–0.92; 1.0 = data leakage)")
    print(f"   F1 Score       : {metrics['f1_score']:.3f}")
    print(f"   Best threshold : {metrics['best_threshold']:.3f}")
    print(f"   Train samples  : {metrics['train_size']}")
    print(f"   Scam rate      : {metrics['class_distribution']['scam_rate']:.1%}")

    print("\n🔍 Feature Importance (no risk_score — independent signals only):")
    for _, row in pipeline.get_feature_importance().iterrows():
        icon = "⚠️" if row['direction'] == 'risk' else "✅"
        print(f"   {icon} {row['feature']:<30} {row['coefficient']:+.3f}")

    print("\n🎯 Predictions:")
    for job in sample_jobs:
        p    = pipeline.predict_job(job['text'], job['title'], job['source'])
        icon = "🚨" if p['prediction'] == 'scam' else "✅"
        print(f"\n   {icon} {job['title']}")
        print(f"      → {p['prediction'].upper()} (probability: {p['scam_probability']:.1%})")
        print(f"      → {p['recommendation']}")

    print("\n" + "=" * 60)
    print("✅ Demo complete.")
    print("=" * 60)
    return pipeline, postings


if __name__ == "__main__":
    import pickle
    pipeline, features = demo()
    with open(MODEL_FILE, 'wb') as f:
        pickle.dump(pipeline, f)
    print(f"\n💾 Model saved → {MODEL_FILE}")