# ml/ensemble.py
"""
VerifyJobs ML — Ensemble Layer
================================
Stacks XGBoost + DistilBERT predictions using a logistic regression
meta-learner trained on validation set outputs.

Why validation set (not training set) for meta-learner:
  Training XGBoost and BERT on the same data they predict on causes
  data leakage — the meta-learner would overfit to their in-sample
  confidence rather than their true generalisation ability.
  Using held-out val predictions gives the meta-learner honest signal.

Fallback:
  If BERT model is not yet trained (no models/bert/ directory),
  the ensemble uses XGBoost only with its own calibration.

Outputs:
  models/ensemble_meta.pkl      — LogisticRegression meta-learner
  models/ensemble_config.json   — weights, thresholds, metrics
  models/calibration.pkl        — Platt scaling calibrator

Run:
  python ml/ensemble.py
"""

import json
import pickle
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    roc_auc_score, average_precision_score,
    f1_score, brier_score_loss,
    precision_recall_curve, classification_report,
)
from sklearn.isotonic import IsotonicRegression
from torch.utils.data import DataLoader

warnings.filterwarnings('ignore')

ROOT       = Path(__file__).parent.parent
PROCESSED  = ROOT / 'data' / 'processed'
MODELS_DIR = ROOT / 'models'


# ── LOADERS ───────────────────────────────────────────────────────────────────

def load_xgboost():
    path = MODELS_DIR / 'xgboost_pipeline.pkl'
    if not path.exists():
        raise FileNotFoundError(
            "XGBoost model not found. Run: python ml/train_xgboost.py")
    with open(path, 'rb') as f:
        bundle = pickle.load(f)
    with open(MODELS_DIR / 'xgboost_meta.json') as f:
        meta = json.load(f)
    print(f"✅ XGBoost loaded  |  test AUPRC: {meta['test_metrics']['auprc']:.4f}")
    return bundle['model'], bundle['builder'], meta


def load_bert():
    bert_dir = MODELS_DIR / 'bert'
    if not bert_dir.exists():
        print("⚠ DistilBERT model not found at models/bert/")
        print("  Run: python ml/train_bert.py  (needs GPU)")
        print("  Falling back to XGBoost-only ensemble.\n")
        return None, None, None

    try:
        from transformers import (
            DistilBertTokenizerFast,
            DistilBertForSequenceClassification,
        )
        tokeniser = DistilBertTokenizerFast.from_pretrained(str(bert_dir))
        model     = DistilBertForSequenceClassification.from_pretrained(str(bert_dir))
        model.eval()
        with open(MODELS_DIR / 'bert_meta.json') as f:
            meta = json.load(f)
        print(f"✅ DistilBERT loaded  |  test AUPRC: {meta['test_auprc']:.4f}")
        return model, tokeniser, meta
    except Exception as e:
        print(f"⚠ Failed to load DistilBERT: {e}")
        return None, None, None


# ── BERT INFERENCE ────────────────────────────────────────────────────────────

@torch.no_grad()
def bert_predict_proba(model, tokeniser, texts, batch_size=32):
    """Run DistilBERT inference on a list of texts. Returns P(scam) array."""
    device  = next(model.parameters()).device
    all_prob = []

    for i in range(0, len(texts), batch_size):
        batch_texts = list(texts[i: i + batch_size])
        enc = tokeniser(
            batch_texts,
            truncation=True,
            padding=True,
            max_length=512,
            return_tensors='pt',
        )
        enc  = {k: v.to(device) for k, v in enc.items()}
        out  = model(**enc)
        prob = torch.softmax(out.logits, dim=-1)[:, 1].cpu().numpy()
        all_prob.extend(prob)

    return np.array(all_prob)


# ── THRESHOLD SEARCH ──────────────────────────────────────────────────────────

def find_best_threshold(y_true, y_prob, min_recall=0.82):
    """Find F1-maximising threshold subject to recall >= min_recall."""
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_prob)
    f1s            = 2 * precisions * recalls / (precisions + recalls + 1e-8)
    recall_penalty = np.where(recalls[:-1] < min_recall, -1.5, 0.0)
    adjusted       = f1s[:-1] + recall_penalty
    best_idx       = np.argmax(adjusted)
    return float(thresholds[best_idx]), float(f1s[best_idx])


# ── ISOTONIC CALIBRATION ──────────────────────────────────────────────────────

def calibrate_probabilities(y_true, raw_prob):
    """
    Isotonic regression calibration.
    Maps raw model probabilities to well-calibrated posteriors.
    Fitted on validation set; applied at inference time.
    """
    calibrator = IsotonicRegression(out_of_bounds='clip')
    calibrator.fit(raw_prob, y_true)
    return calibrator


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    print("\n=== VerifyJobs Ensemble Training ===\n")

    # Load processed data
    val_df  = pd.read_parquet(PROCESSED / 'val.parquet')
    test_df = pd.read_parquet(PROCESSED / 'test.parquet')
    y_val   = val_df['label'].values
    y_test  = test_df['label'].values

    # Load models
    xgb_model, builder, xgb_meta = load_xgboost()
    bert_model, bert_tok, bert_meta = load_bert()
    use_bert = bert_model is not None

    # ── XGBoost predictions ─────────────────────────────────────────────────
    print("\nGenerating XGBoost predictions...")
    X_val  = builder.transform(val_df)
    X_test = builder.transform(test_df)

    xgb_val_prob  = xgb_model.predict_proba(X_val)[:, 1]
    xgb_test_prob = xgb_model.predict_proba(X_test)[:, 1]

    # ── BERT predictions ────────────────────────────────────────────────────
    if use_bert:
        print("Generating DistilBERT predictions (val)...")
        bert_val_prob  = bert_predict_proba(
            bert_model, bert_tok, val_df['text_clean'].tolist())
        print("Generating DistilBERT predictions (test)...")
        bert_test_prob = bert_predict_proba(
            bert_model, bert_tok, test_df['text_clean'].tolist())
    else:
        bert_val_prob  = xgb_val_prob.copy()   # dummy — won't be used
        bert_test_prob = xgb_test_prob.copy()

    # ── Meta-learner ─────────────────────────────────────────────────────────
    if use_bert:
        print("\nFitting logistic regression meta-learner on val predictions...")
        meta_X_val  = np.column_stack([xgb_val_prob,  bert_val_prob])
        meta_X_test = np.column_stack([xgb_test_prob, bert_test_prob])

        meta_learner = LogisticRegression(C=1.0, class_weight='balanced',
                                          max_iter=1000, random_state=42)
        meta_learner.fit(meta_X_val, y_val)

        ensemble_val_prob  = meta_learner.predict_proba(meta_X_val)[:, 1]
        ensemble_test_prob = meta_learner.predict_proba(meta_X_test)[:, 1]

        coef = meta_learner.coef_[0]
        total = coef.sum()
        xgb_weight  = float(coef[0] / total)
        bert_weight = float(coef[1] / total)
        print(f"Meta-learner weights — XGBoost: {xgb_weight:.3f}  BERT: {bert_weight:.3f}")

    else:
        print("\nBERT not available — using XGBoost only")
        meta_learner       = None
        ensemble_val_prob  = xgb_val_prob
        ensemble_test_prob = xgb_test_prob
        xgb_weight, bert_weight = 1.0, 0.0

    # ── Calibration ──────────────────────────────────────────────────────────
    print("\nFitting isotonic calibrator on ensemble val probabilities...")
    calibrator         = calibrate_probabilities(y_val, ensemble_val_prob)
    cal_val_prob       = calibrator.transform(ensemble_val_prob)
    cal_test_prob      = calibrator.transform(ensemble_test_prob)

    # ── Threshold ────────────────────────────────────────────────────────────
    threshold, val_f1 = find_best_threshold(y_val, cal_val_prob, min_recall=0.82)
    print(f"Optimal threshold: {threshold:.3f}  (val F1: {val_f1:.4f})")

    # ── Final metrics ────────────────────────────────────────────────────────
    def report(y_true, y_prob, split):
        pred = (y_prob >= threshold).astype(int)
        auc  = roc_auc_score(y_true, y_prob)
        aprc = average_precision_score(y_true, y_prob)
        f1   = f1_score(y_true, pred)
        bs   = brier_score_loss(y_true, y_prob)
        print(f"\n── {split} ──")
        print(f"  AUC-ROC: {auc:.4f}  AUPRC: {aprc:.4f}  F1: {f1:.4f}  Brier: {bs:.4f}")
        print(classification_report(y_true, pred,
              target_names=['legit', 'scam'], digits=4))
        return {'auc': auc, 'auprc': aprc, 'f1': f1, 'brier': bs}

    val_metrics  = report(y_val,  cal_val_prob,  'Validation (calibrated)')
    test_metrics = report(y_test, cal_test_prob, 'Test       (calibrated)')

    # ── Save ─────────────────────────────────────────────────────────────────
    with open(MODELS_DIR / 'ensemble_meta.pkl', 'wb') as f:
        pickle.dump(meta_learner, f, protocol=4)

    with open(MODELS_DIR / 'calibration.pkl', 'wb') as f:
        pickle.dump(calibrator, f, protocol=4)

    config = {
        'use_bert':      use_bert,
        'xgb_weight':    xgb_weight,
        'bert_weight':   bert_weight,
        'threshold':     threshold,
        'val_metrics':   val_metrics,
        'test_metrics':  test_metrics,
        'xgb_threshold': xgb_meta['threshold'],
        'bert_threshold': bert_meta['threshold'] if bert_meta else None,
    }
    with open(MODELS_DIR / 'ensemble_config.json', 'w') as f:
        json.dump(config, f, indent=2)

    print(f"\n✅ Saved:")
    print(f"   models/ensemble_meta.pkl")
    print(f"   models/calibration.pkl")
    print(f"   models/ensemble_config.json")
    print(f"\nTest AUC:   {test_metrics['auc']:.4f}")
    print(f"Test AUPRC: {test_metrics['auprc']:.4f}")
    print(f"Test F1:    {test_metrics['f1']:.4f}")
    print(f"\nNext step: python ml/serve.py   (start local inference server)")


if __name__ == '__main__':
    main()
