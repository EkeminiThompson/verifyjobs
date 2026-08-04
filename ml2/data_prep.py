# ml/data_prep.py
"""
VerifyJobs ML — Data Preparation Pipeline
=========================================
Merges two data sources:
  1. Kaggle "Real or Fake Job Posting" dataset (17,880 rows)
     Download: https://www.kaggle.com/datasets/shivamb/real-or-fake-fake-jobposting-prediction
     Place at: data/kaggle_jobs.csv

  2. Your manually labelled Nigerian/WhatsApp scam posts
     Place at: data/manual_labels/labels.csv
     Format: text,label,source,notes
     label: 1 = scam, 0 = legitimate

Outputs (written to data/processed/):
  train.parquet, val.parquet, test.parquet
  feature_meta.json  — vocab sizes, column names, class weights

Run:
  python ml/data_prep.py
"""

import re
import json
import unicodedata
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight

warnings.filterwarnings('ignore')

# ── PATHS ─────────────────────────────────────────────────────────────────────
ROOT          = Path(__file__).parent.parent
KAGGLE_CSV    = ROOT / 'data' / 'kaggle_jobs.csv'
MANUAL_CSV    = ROOT / 'data' / 'manual_labels' / 'labels.csv'
PROCESSED_DIR = ROOT / 'data' / 'processed'
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# ── NIGERIAN / WEST-AFRICAN CONTEXT FEATURES ─────────────────────────────────
# These are raw signal extractors — NOT scoring rules.
# They feed the model as features so it learns their weight.

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
    r'@(?!gmail|yahoo|hotmail|outlook|protonmail)[a-z0-9.\-]+\.(com|org|net|co|io)\b', re.I)


def _flag(pattern, text):
    """Return 1 if pattern matches text, else 0."""
    return int(bool(pattern.search(text)))


def _naira_max(text):
    """Extract maximum Naira amount mentioned. 0 if none."""
    amounts = _NAIRA_RE.findall(text)
    if not amounts:
        return 0
    nums = []
    for a in amounts:
        cleaned = re.sub(r'[^\d]', '', a)
        if cleaned:
            nums.append(int(cleaned))
    return max(nums) if nums else 0


def _emoji_count(text):
    """Count emoji characters (rough unicode range check)."""
    return sum(
        1 for c in text
        if unicodedata.category(c) in ('So', 'Sm') or
           '\U0001F300' <= c <= '\U0001FAFF'
    )


# ── KAGGLE LOADER ─────────────────────────────────────────────────────────────

def load_kaggle(path: Path) -> pd.DataFrame:
    """
    Kaggle schema:
      job_id, title, location, department, salary_range, company_profile,
      description, requirements, benefits, telecommuting, has_company_logo,
      has_questions, employment_type, required_experience, required_education,
      industry, function, fraudulent (0/1 — 1=scam)
    """
    print(f"Loading Kaggle dataset from {path}...")
    df = pd.read_csv(path, low_memory=False)

    # Merge text fields
    text_cols = ['title', 'company_profile', 'description', 'requirements', 'benefits']
    df['text'] = df[text_cols].fillna('').apply(
        lambda r: ' '.join(r.values.astype(str)), axis=1
    )

    result = pd.DataFrame({
        'text':               df['text'],
        'label':              df['fraudulent'].astype(int),
        'source':             'kaggle',
        # Structural features from Kaggle that may not exist in manual data
        'has_salary':         df['salary_range'].notna().astype(int),
        'has_company_profile': df['company_profile'].notna().astype(int),
        'has_logo':           df.get('has_company_logo', pd.Series(0, index=df.index)).fillna(0).astype(int),
        'has_questions':      df.get('has_questions', pd.Series(0, index=df.index)).fillna(0).astype(int),
        'telecommuting':      df.get('telecommuting', pd.Series(0, index=df.index)).fillna(0).astype(int),
        'employment_type':    df.get('employment_type', pd.Series('', index=df.index)).fillna(''),
        'required_experience': df.get('required_experience', pd.Series('', index=df.index)).fillna(''),
        'required_education': df.get('required_education', pd.Series('', index=df.index)).fillna(''),
    })

    print(f"  → {len(result):,} rows | {result['label'].sum():,} scam | {(result['label']==0).sum():,} legit")
    return result


# ── MANUAL LABELS LOADER ──────────────────────────────────────────────────────

def load_manual(path: Path) -> pd.DataFrame:
    """
    Manual label CSV schema:
      text,label,source,notes
      text: full job posting text (paste from WhatsApp, email, etc.)
      label: 1=scam, 0=legitimate
      source: whatsapp | email | linkedin | jobberman | facebook | other
      notes: optional free-text notes
    """
    if not path.exists():
        print(f"  ⚠ Manual labels not found at {path} — skipping")
        print(f"    Create {path} with columns: text,label,source,notes")
        return pd.DataFrame()

    print(f"Loading manual labels from {path}...")
    df = pd.read_csv(path)

    required = {'text', 'label'}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Manual labels CSV missing columns: {missing}")

    df = df.dropna(subset=['text', 'label'])
    df['label'] = df['label'].astype(int)

    result = pd.DataFrame({
        'text':                df['text'].astype(str),
        'label':               df['label'],
        'source':              df.get('source', pd.Series('manual', index=df.index)).fillna('manual'),
        'has_salary':          0,
        'has_company_profile': 0,
        'has_logo':            0,
        'has_questions':       0,
        'telecommuting':       0,
        'employment_type':     '',
        'required_experience': '',
        'required_education':  '',
    })

    print(f"  → {len(result):,} rows | {result['label'].sum():,} scam | {(result['label']==0).sum():,} legit")
    return result


# ── FEATURE ENGINEERING ───────────────────────────────────────────────────────

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add all derived features. Operates on df['text'] column."""
    print("Engineering features...")
    text = df['text'].fillna('').astype(str)

    # Lexical / statistical
    df['word_count']         = text.str.split().str.len()
    df['char_count']         = text.str.len()
    df['avg_word_len']       = df.apply(
        lambda r: r['char_count'] / max(r['word_count'], 1), axis=1)
    df['upper_ratio']        = text.apply(
        lambda t: sum(1 for c in t if c.isupper()) / max(len(t), 1))
    df['exclaim_count']      = text.str.count(r'!')
    df['emoji_count']        = text.apply(_emoji_count)
    df['digit_ratio']        = text.apply(
        lambda t: sum(1 for c in t if c.isdigit()) / max(len(t), 1))

    # Nigerian context signals
    df['has_naira']          = text.apply(lambda t: _flag(_NAIRA_RE, t))
    df['naira_max_amount']   = text.apply(_naira_max)
    df['has_whatsapp']       = text.apply(lambda t: _flag(_WHATSAPP_RE, t))
    df['has_telegram']       = text.apply(lambda t: _flag(_TELEGRAM_RE, t))
    df['has_upfront_fee']    = text.apply(lambda t: _flag(_UPFRONT_RE, t))
    df['has_crypto']         = text.apply(lambda t: _flag(_CRYPTO_RE, t))
    df['has_task_pattern']   = text.apply(lambda t: _flag(_TASK_RE, t))
    df['has_urgency']        = text.apply(lambda t: _flag(_URGENT_RE, t))
    df['has_free_email']     = text.apply(lambda t: _flag(_FREE_EMAIL_RE, t))
    df['has_no_exp_req']     = text.apply(lambda t: _flag(_NO_EXP_RE, t))
    df['has_high_salary']    = text.apply(lambda t: _flag(_HIGH_SALARY_RE, t))

    # Legitimacy signals
    df['has_interview_proc'] = text.apply(lambda t: _flag(_INTERVIEW_RE, t))
    df['has_ats_platform']   = text.apply(lambda t: _flag(_ATS_RE, t))
    df['has_company_email']  = text.apply(lambda t: _flag(_COMPANY_EMAIL_RE, t))

    # Combo features (model can also learn these from raw, but helps)
    df['whatsapp_and_upfront']   = (df['has_whatsapp'] & df['has_upfront_fee']).astype(int)
    df['task_and_high_salary']   = (df['has_task_pattern'] & df['has_high_salary']).astype(int)
    df['free_email_and_urgency'] = (df['has_free_email'] & df['has_urgency']).astype(int)
    df['no_exp_and_high_salary'] = (df['has_no_exp_req'] & df['has_high_salary']).astype(int)

    print(f"  → {len(df.columns)} total columns")
    return df


# ── CLEAN TEXT ────────────────────────────────────────────────────────────────

def clean_text(text: str) -> str:
    """Normalise text for TF-IDF and BERT tokenisation."""
    text = unicodedata.normalize('NFKC', text)
    text = re.sub(r'https?://\S+', ' URL ', text)
    text = re.sub(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b', ' EMAIL ', text)
    text = re.sub(r'\+?\d[\d\s\-().]{7,}\d', ' PHONE ', text)
    text = re.sub(r'[\r\n\t]+', ' ', text)
    text = re.sub(r'[ ]{2,}', ' ', text)
    return text.strip()


# ── MAIN PIPELINE ─────────────────────────────────────────────────────────────

def main():
    print("\n=== VerifyJobs Data Preparation ===\n")

    # 1. Load sources
    dfs = []

    if KAGGLE_CSV.exists():
        dfs.append(load_kaggle(KAGGLE_CSV))
    else:
        print(f"⚠ Kaggle CSV not found at {KAGGLE_CSV}")
        print("  Download from: https://www.kaggle.com/datasets/shivamb/real-or-fake-fake-jobposting-prediction")
        print("  Then place at data/kaggle_jobs.csv\n")

    manual_df = load_manual(MANUAL_CSV)
    if not manual_df.empty:
        dfs.append(manual_df)

    if not dfs:
        raise RuntimeError("No data found. Provide at least one of: kaggle_jobs.csv or manual labels.")

    # 2. Merge
    df = pd.concat(dfs, ignore_index=True)
    print(f"\nCombined dataset: {len(df):,} rows | "
          f"Scam: {df['label'].sum():,} ({df['label'].mean()*100:.1f}%) | "
          f"Legit: {(df['label']==0).sum():,}")

    # 3. Drop near-duplicates (same first 200 chars)
    df['_dedup_key'] = df['text'].str[:200].str.lower().str.strip()
    before = len(df)
    df = df.drop_duplicates(subset=['_dedup_key']).drop(columns=['_dedup_key'])
    print(f"Deduplication: removed {before - len(df):,} near-duplicates")

    # 4. Drop too-short texts (< 20 words — not enough signal)
    df = df[df['text'].str.split().str.len() >= 20].copy()
    print(f"After length filter: {len(df):,} rows")

    # 5. Clean text
    df['text_clean'] = df['text'].apply(clean_text)

    # 6. Feature engineering
    df = engineer_features(df)

    # 7. Train / val / test split (70/15/15), stratified
    # Manual labels are upsampled slightly to weight Nigerian context
    train_df, temp_df = train_test_split(
        df, test_size=0.30, random_state=42, stratify=df['label'])
    val_df, test_df = train_test_split(
        temp_df, test_size=0.50, random_state=42, stratify=temp_df['label'])

    print(f"\nSplits:")
    print(f"  Train: {len(train_df):,} | Scam rate: {train_df['label'].mean()*100:.1f}%")
    print(f"  Val:   {len(val_df):,}   | Scam rate: {val_df['label'].mean()*100:.1f}%")
    print(f"  Test:  {len(test_df):,}  | Scam rate: {test_df['label'].mean()*100:.1f}%")

    # 8. Class weights (for imbalanced data — Kaggle is ~5% scam)
    class_weights = compute_class_weight(
        'balanced',
        classes=np.array([0, 1]),
        y=train_df['label'].values
    )
    cw_dict = {0: float(class_weights[0]), 1: float(class_weights[1])}
    print(f"\nClass weights (for imbalanced training): {cw_dict}")

    # 9. Save
    train_df.to_parquet(PROCESSED_DIR / 'train.parquet', index=False)
    val_df.to_parquet(PROCESSED_DIR / 'val.parquet', index=False)
    test_df.to_parquet(PROCESSED_DIR / 'test.parquet', index=False)

    # Feature metadata
    structural_features = [
        'has_salary', 'has_company_profile', 'has_logo', 'has_questions',
        'telecommuting', 'word_count', 'char_count', 'avg_word_len',
        'upper_ratio', 'exclaim_count', 'emoji_count', 'digit_ratio',
        'has_naira', 'naira_max_amount', 'has_whatsapp', 'has_telegram',
        'has_upfront_fee', 'has_crypto', 'has_task_pattern', 'has_urgency',
        'has_free_email', 'has_no_exp_req', 'has_high_salary',
        'has_interview_proc', 'has_ats_platform', 'has_company_email',
        'whatsapp_and_upfront', 'task_and_high_salary',
        'free_email_and_urgency', 'no_exp_and_high_salary',
    ]

    meta = {
        'n_train':             len(train_df),
        'n_val':               len(val_df),
        'n_test':              len(test_df),
        'scam_rate_train':     float(train_df['label'].mean()),
        'class_weights':       cw_dict,
        'structural_features': structural_features,
        'sources':             df['source'].value_counts().to_dict(),
    }

    with open(PROCESSED_DIR / 'feature_meta.json', 'w') as f:
        json.dump(meta, f, indent=2)

    print(f"\n✅ Saved to {PROCESSED_DIR}/")
    print("   train.parquet, val.parquet, test.parquet, feature_meta.json")
    print("\nNext step: python ml/train_xgboost.py")


if __name__ == '__main__':
    main()
