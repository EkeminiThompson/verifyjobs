# ml/train_xgboost.py
"""
VerifyJobs ML — XGBoost Classifier
====================================
Trains a TF-IDF + structural features → XGBoost pipeline.
Runs entirely in Codespaces (no GPU needed).
Expected train time: 3–8 minutes on 2-core CPU.

Outputs:
  models/xgboost_pipeline.pkl   — sklearn Pipeline (tfidf + xgb)
  models/xgboost_meta.json      — threshold, AUC, F1, feature importances

Run:
  python ml/train_xgboost.py [--tune]   # --tune runs Optuna HPO (~30 min)
"""

import argparse
import json
import pickle
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    roc_auc_score, average_precision_score, f1_score,
    precision_recall_curve, classification_report, confusion_matrix
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import xgboost as xgb

warnings.filterwarnings('ignore')

ROOT        = Path(__file__).parent.parent
PROCESSED   = ROOT / 'data' / 'processed'
MODELS_DIR  = ROOT / 'models'
MODELS_DIR.mkdir(parents=True, exist_ok=True)


# ── LOAD DATA ─────────────────────────────────────────────────────────────────

def load_splits():
    train = pd.read_parquet(PROCESSED / 'train.parquet')
    val   = pd.read_parquet(PROCESSED / 'val.parquet')
    test  = pd.read_parquet(PROCESSED / 'test.parquet')
    with open(PROCESSED / 'feature_meta.json') as f:
        meta = json.load(f)
    return train, val, test, meta


# ── FEATURE BUILDER ───────────────────────────────────────────────────────────

class FeatureBuilder:
    """
    Combines TF-IDF text features with structural numeric features.
    Designed to be re-used at inference time on a single text.
    """

    def __init__(self, structural_cols: list, tfidf_params: dict = None):
        self.structural_cols = structural_cols
        self.tfidf_params    = tfidf_params or {}
        self.tfidf           = None
        self.scaler          = None

    def fit(self, df: pd.DataFrame):
        # TF-IDF on cleaned text
        self.tfidf = TfidfVectorizer(
            max_features=self.tfidf_params.get('max_features', 60_000),
            ngram_range=self.tfidf_params.get('ngram_range', (1, 3)),
            sublinear_tf=True,
            min_df=self.tfidf_params.get('min_df', 2),
            max_df=self.tfidf_params.get('max_df', 0.95),
            analyzer='word',
            strip_accents='unicode',
        )
        self.tfidf.fit(df['text_clean'].fillna(''))

        # Scaler for structural features
        self.scaler = StandardScaler()
        struct = df[self.structural_cols].fillna(0).astype(float).values
        self.scaler.fit(struct)
        return self

    def transform(self, df: pd.DataFrame):
        text_feats   = self.tfidf.transform(df['text_clean'].fillna(''))
        struct_raw   = df[self.structural_cols].fillna(0).astype(float).values
        struct_feats = csr_matrix(self.scaler.transform(struct_raw))
        return hstack([text_feats, struct_feats], format='csr')

    def fit_transform(self, df: pd.DataFrame):
        return self.fit(df).transform(df)


# ── FIND OPTIMAL THRESHOLD ────────────────────────────────────────────────────

def find_best_threshold(y_true, y_prob):
    """
    Find threshold maximising F1 on validation set.
    Prefer higher recall because missing a scam is worse than a false alarm.
    """
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_prob)
    f1s = 2 * precisions * recalls / (precisions + recalls + 1e-8)

    # Weight recall: penalise thresholds where recall < 0.80
    recall_penalty = np.where(recalls[:-1] < 0.80, -1.0, 0.0)
    adjusted_f1s   = f1s[:-1] + recall_penalty

    best_idx = np.argmax(adjusted_f1s)
    return float(thresholds[best_idx]), float(f1s[best_idx])


# ── HYPERPARAMETER TUNING ─────────────────────────────────────────────────────

def tune_with_optuna(X_train, y_train, X_val, y_val, class_weights, n_trials=40):
    try:
        import optuna
        optuna.logging.set_verbosity(optuna.logging.WARNING)
    except ImportError:
        print("Optuna not installed. Run: pip install optuna --break-system-packages")
        return default_xgb_params()

    sample_weight = np.where(
        y_train == 1, class_weights[1], class_weights[0])

    def objective(trial):
        params = {
            'n_estimators':      trial.suggest_int('n_estimators', 200, 1000, step=100),
            'max_depth':         trial.suggest_int('max_depth', 3, 9),
            'learning_rate':     trial.suggest_float('learning_rate', 0.01, 0.3, log=True),
            'subsample':         trial.suggest_float('subsample', 0.5, 1.0),
            'colsample_bytree':  trial.suggest_float('colsample_bytree', 0.4, 1.0),
            'min_child_weight':  trial.suggest_int('min_child_weight', 1, 10),
            'gamma':             trial.suggest_float('gamma', 0.0, 5.0),
            'reg_alpha':         trial.suggest_float('reg_alpha', 1e-4, 10.0, log=True),
            'reg_lambda':        trial.suggest_float('reg_lambda', 1e-4, 10.0, log=True),
            'scale_pos_weight':  class_weights[1] / class_weights[0],
            'eval_metric':       'aucpr',
            'use_label_encoder': False,
            'tree_method':       'hist',
            'random_state':      42,
            'n_jobs':            -1,
        }
        model = xgb.XGBClassifier(**params)
        model.fit(
            X_train, y_train,
            sample_weight=sample_weight,
            eval_set=[(X_val, y_val)],
            verbose=False,
        )
        prob_val = model.predict_proba(X_val)[:, 1]
        return average_precision_score(y_val, prob_val)

    study = optuna.create_study(direction='maximize')
    study.optimize(objective, n_trials=n_trials, show_progress_bar=True)
    print(f"\nBest trial AUPRC: {study.best_value:.4f}")
    print(f"Best params: {study.best_params}")
    return study.best_params


def default_xgb_params():
    return {
        'n_estimators':     500,
        'max_depth':        6,
        'learning_rate':    0.05,
        'subsample':        0.8,
        'colsample_bytree': 0.7,
        'min_child_weight': 3,
        'gamma':            0.1,
        'reg_alpha':        0.1,
        'reg_lambda':       1.0,
        'tree_method':      'hist',
        'random_state':     42,
        'n_jobs':           -1,
    }


# ── EVALUATION ────────────────────────────────────────────────────────────────

def evaluate(model, X, y, split_name, threshold=0.5):
    prob   = model.predict_proba(X)[:, 1]
    pred   = (prob >= threshold).astype(int)
    auc    = roc_auc_score(y, prob)
    auprc  = average_precision_score(y, prob)
    f1     = f1_score(y, pred)
    cm     = confusion_matrix(y, pred)
    tn, fp, fn, tp = cm.ravel()

    print(f"\n── {split_name} ──")
    print(f"  AUC-ROC: {auc:.4f}  |  AUPRC: {auprc:.4f}  |  F1: {f1:.4f}")
    print(f"  Threshold: {threshold:.3f}")
    print(f"  TP: {tp}  FP: {fp}  TN: {tn}  FN: {fn}")
    print(f"  Recall (scam catch rate): {tp/(tp+fn+1e-8):.3f}")
    print(f"  Precision: {tp/(tp+fp+1e-8):.3f}")
    print(classification_report(y, pred, target_names=['legit', 'scam'], digits=4))
    return {'auc': auc, 'auprc': auprc, 'f1': f1, 'threshold': threshold,
            'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn)}


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tune', action='store_true',
                        help='Run Optuna hyperparameter search (~30 min)')
    args = parser.parse_args()

    print("\n=== VerifyJobs XGBoost Training ===\n")

    # Load
    train_df, val_df, test_df, meta = load_splits()
    struct_cols = meta['structural_features']
    cw          = meta['class_weights']
    class_weights = np.array([cw['0'], cw['1']])

    print(f"Train: {len(train_df):,}  Val: {len(val_df):,}  Test: {len(test_df):,}")
    print(f"Structural features: {len(struct_cols)}")

    # Feature engineering
    print("\nBuilding TF-IDF + structural features...")
    builder = FeatureBuilder(struct_cols)
    X_train = builder.fit_transform(train_df)
    X_val   = builder.transform(val_df)
    X_test  = builder.transform(test_df)

    y_train = train_df['label'].values
    y_val   = val_df['label'].values
    y_test  = test_df['label'].values

    print(f"Feature matrix shape: {X_train.shape}")

    # Hyperparameters
    if args.tune:
        print("\nRunning Optuna tuning...")
        best_params = tune_with_optuna(X_train, y_train, X_val, y_val, class_weights)
    else:
        print("\nUsing default hyperparameters (pass --tune for HPO)")
        best_params = default_xgb_params()

    # Class weight
    best_params['scale_pos_weight'] = class_weights[1] / class_weights[0]
    best_params['eval_metric']      = 'aucpr'

    # Sample weights
    sample_weight = np.where(y_train == 1, class_weights[1], class_weights[0])

    # Train
    print(f"\nTraining XGBoost ({best_params['n_estimators']} trees)...")
    model = xgb.XGBClassifier(**best_params)
    model.fit(
        X_train, y_train,
        sample_weight=sample_weight,
        eval_set=[(X_val, y_val)],
        verbose=50,
    )

    # Find optimal threshold on validation set
    val_prob            = model.predict_proba(X_val)[:, 1]
    best_thresh, best_f1 = find_best_threshold(y_val, val_prob)
    print(f"\nOptimal threshold (val F1={best_f1:.4f}): {best_thresh:.3f}")

    # Evaluate
    val_metrics  = evaluate(model, X_val,  y_val,  'Validation', best_thresh)
    test_metrics = evaluate(model, X_test, y_test, 'Test',       best_thresh)

    # Feature importance (top 40 TF-IDF terms + all structural)
    tfidf_vocab    = builder.tfidf.get_feature_names_out()
    struct_names   = np.array(struct_cols)
    all_feat_names = np.concatenate([tfidf_vocab, struct_names])
    importances    = model.feature_importances_

    top_idx   = np.argsort(importances)[-40:][::-1]
    top_feats = [
        {'feature': str(all_feat_names[i]), 'importance': float(importances[i])}
        for i in top_idx
    ]
    print("\nTop 20 features by importance:")
    for f in top_feats[:20]:
        bar = '█' * int(f['importance'] * 500)
        print(f"  {f['feature'][:40]:<40} {bar}")

    # Save model + builder
    with open(MODELS_DIR / 'xgboost_pipeline.pkl', 'wb') as f:
        pickle.dump({'model': model, 'builder': builder}, f, protocol=4)

    # Save metadata
    xgb_meta = {
        'threshold':         best_thresh,
        'val_metrics':       val_metrics,
        'test_metrics':      test_metrics,
        'top_features':      top_feats,
        'xgb_params':        best_params,
        'n_features':        int(X_train.shape[1]),
        'structural_cols':   struct_cols,
        'tfidf_vocab_size':  len(tfidf_vocab),
    }
    with open(MODELS_DIR / 'xgboost_meta.json', 'w') as f:
        json.dump(xgb_meta, f, indent=2)

    print(f"\n✅ Saved:")
    print(f"   models/xgboost_pipeline.pkl")
    print(f"   models/xgboost_meta.json")
    print(f"\nTest AUC: {test_metrics['auc']:.4f}  AUPRC: {test_metrics['auprc']:.4f}  F1: {test_metrics['f1']:.4f}")
    print(f"\nNext step: python ml/train_bert.py   (needs compute credits / GPU)")


if __name__ == '__main__':
    main()
