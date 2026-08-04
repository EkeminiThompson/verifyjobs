# ml/train_bert.py
"""
VerifyJobs ML — DistilBERT Fine-Tuning
=======================================
Fine-tunes distilbert-base-uncased on job scam classification.
Run this on your compute credits (needs GPU).

Compute credit estimate (Thinking Machines / Modal / Lambda):
  A10G GPU (24GB VRAM): ~45 minutes for 3 epochs on 12k train rows
  T4 GPU (16GB VRAM):   ~90 minutes
  Cost at ~$0.50–$1.00/GPU-hour: ~$0.50–$1.50 total

Outputs:
  models/bert/                  — HuggingFace SavedModel directory
  models/bert_meta.json         — eval metrics, threshold

Run locally (CPU — slow but works for testing):
  python ml/train_bert.py --epochs 1 --batch_size 8

Run on Modal (compute credits):
  modal run ml/train_bert.py::main_modal

Run on Lambda Labs / SSH'd GPU box:
  python ml/train_bert.py --epochs 3 --batch_size 32
"""

import argparse
import json
import os
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import (
    roc_auc_score, average_precision_score,
    f1_score, precision_recall_curve, classification_report
)
from torch.utils.data import Dataset, DataLoader
from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification,
    get_linear_schedule_with_warmup,
)

warnings.filterwarnings('ignore')

ROOT       = Path(__file__).parent.parent
PROCESSED  = ROOT / 'data' / 'processed'
MODELS_DIR = ROOT / 'models'
BERT_DIR   = MODELS_DIR / 'bert'
BERT_DIR.mkdir(parents=True, exist_ok=True)

MODEL_NAME = 'distilbert-base-uncased'
MAX_LEN    = 512   # DistilBERT max; job postings rarely exceed this


# ── DATASET ───────────────────────────────────────────────────────────────────

class JobDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_len=MAX_LEN):
        self.encodings = tokenizer(
            list(texts),
            truncation=True,
            padding=True,
            max_length=max_len,
            return_tensors='pt',
        )
        self.labels = torch.tensor(list(labels), dtype=torch.long)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        item = {k: v[idx] for k, v in self.encodings.items()}
        item['labels'] = self.labels[idx]
        return item


# ── TRAINING ──────────────────────────────────────────────────────────────────

def train_epoch(model, loader, optimizer, scheduler, device, class_weights_tensor):
    model.train()
    total_loss = 0
    loss_fn = torch.nn.CrossEntropyLoss(weight=class_weights_tensor)

    for batch in loader:
        optimizer.zero_grad()
        input_ids      = batch['input_ids'].to(device)
        attention_mask = batch['attention_mask'].to(device)
        labels         = batch['labels'].to(device)

        outputs = model(input_ids=input_ids, attention_mask=attention_mask)
        loss    = loss_fn(outputs.logits, labels)
        loss.backward()

        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        scheduler.step()
        total_loss += loss.item()

    return total_loss / len(loader)


@torch.no_grad()
def evaluate_epoch(model, loader, device):
    model.eval()
    all_probs  = []
    all_labels = []

    for batch in loader:
        input_ids      = batch['input_ids'].to(device)
        attention_mask = batch['attention_mask'].to(device)
        labels         = batch['labels'].numpy()

        outputs = model(input_ids=input_ids, attention_mask=attention_mask)
        probs   = torch.softmax(outputs.logits, dim=-1)[:, 1].cpu().numpy()

        all_probs.extend(probs)
        all_labels.extend(labels)

    return np.array(all_probs), np.array(all_labels)


def find_best_threshold(y_true, y_prob):
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_prob)
    f1s             = 2 * precisions * recalls / (precisions + recalls + 1e-8)
    recall_penalty  = np.where(recalls[:-1] < 0.80, -1.0, 0.0)
    adjusted_f1s    = f1s[:-1] + recall_penalty
    best_idx        = np.argmax(adjusted_f1s)
    return float(thresholds[best_idx]), float(f1s[best_idx])


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main(
    epochs: int     = 3,
    batch_size: int = 32,
    lr: float       = 2e-5,
    warmup_ratio: float = 0.1,
    fp16: bool      = True,
):
    print("\n=== VerifyJobs DistilBERT Fine-Tuning ===\n")

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Device: {device}")
    if device.type == 'cpu':
        print("⚠ Running on CPU — this will be slow. Use a GPU for full training.")
        fp16 = False  # FP16 not supported on CPU

    # Load data
    train_df = pd.read_parquet(PROCESSED / 'train.parquet')
    val_df   = pd.read_parquet(PROCESSED / 'val.parquet')
    test_df  = pd.read_parquet(PROCESSED / 'test.parquet')

    with open(PROCESSED / 'feature_meta.json') as f:
        meta = json.load(f)

    cw             = meta['class_weights']
    class_weights  = torch.tensor([cw['0'], cw['1']], dtype=torch.float).to(device)

    print(f"Train: {len(train_df):,}  Val: {len(val_df):,}  Test: {len(test_df):,}")

    # Tokeniser
    print(f"\nLoading tokeniser: {MODEL_NAME}")
    tokeniser = DistilBertTokenizerFast.from_pretrained(MODEL_NAME)

    # Datasets
    print("Tokenising datasets (this takes ~2 min)...")
    train_ds = JobDataset(train_df['text_clean'], train_df['label'], tokeniser)
    val_ds   = JobDataset(val_df['text_clean'],   val_df['label'],   tokeniser)
    test_ds  = JobDataset(test_df['text_clean'],  test_df['label'],  tokeniser)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True,  num_workers=2, pin_memory=True)
    val_loader   = DataLoader(val_ds,   batch_size=batch_size, shuffle=False, num_workers=2, pin_memory=True)
    test_loader  = DataLoader(test_ds,  batch_size=batch_size, shuffle=False, num_workers=2, pin_memory=True)

    # Model
    print(f"\nLoading model: {MODEL_NAME}")
    model = DistilBertForSequenceClassification.from_pretrained(
        MODEL_NAME, num_labels=2)
    model.to(device)

    # Optimiser + scheduler
    total_steps   = len(train_loader) * epochs
    warmup_steps  = int(total_steps * warmup_ratio)
    optimizer     = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    scheduler     = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=warmup_steps, num_training_steps=total_steps)

    # Mixed precision scaler
    scaler = torch.cuda.amp.GradScaler(enabled=fp16)

    # Training loop
    best_auprc    = 0.0
    best_thresh   = 0.5
    history       = []

    for epoch in range(1, epochs + 1):
        print(f"\n── Epoch {epoch}/{epochs} ──")

        # Train
        model.train()
        total_loss = 0
        loss_fn    = torch.nn.CrossEntropyLoss(weight=class_weights)

        for step, batch in enumerate(train_loader, 1):
            optimizer.zero_grad()
            input_ids      = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels         = batch['labels'].to(device)

            with torch.cuda.amp.autocast(enabled=fp16):
                outputs = model(input_ids=input_ids, attention_mask=attention_mask)
                loss    = loss_fn(outputs.logits, labels)

            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(optimizer)
            scaler.update()
            scheduler.step()
            total_loss += loss.item()

            if step % 100 == 0:
                print(f"  Step {step}/{len(train_loader)}  loss={total_loss/step:.4f}")

        avg_loss = total_loss / len(train_loader)
        print(f"  Avg train loss: {avg_loss:.4f}")

        # Validate
        val_probs, val_labels = evaluate_epoch(model, val_loader, device)
        val_auc   = roc_auc_score(val_labels, val_probs)
        val_auprc = average_precision_score(val_labels, val_probs)
        thresh, val_f1 = find_best_threshold(val_labels, val_probs)

        print(f"  Val AUC: {val_auc:.4f}  AUPRC: {val_auprc:.4f}  F1: {val_f1:.4f}  Thresh: {thresh:.3f}")

        history.append({
            'epoch': epoch, 'train_loss': avg_loss,
            'val_auc': val_auc, 'val_auprc': val_auprc,
            'val_f1': val_f1, 'threshold': thresh,
        })

        # Save best checkpoint
        if val_auprc > best_auprc:
            best_auprc  = val_auprc
            best_thresh = thresh
            model.save_pretrained(BERT_DIR)
            tokeniser.save_pretrained(BERT_DIR)
            print(f"  ✅ New best AUPRC={best_auprc:.4f} — checkpoint saved")

    # Final test evaluation with best model
    print("\n── Loading best checkpoint for test evaluation ──")
    model = DistilBertForSequenceClassification.from_pretrained(BERT_DIR)
    model.to(device)

    test_probs, test_labels = evaluate_epoch(model, test_loader, device)
    test_auc   = roc_auc_score(test_labels, test_probs)
    test_auprc = average_precision_score(test_labels, test_probs)
    test_pred  = (test_probs >= best_thresh).astype(int)
    test_f1    = f1_score(test_labels, test_pred)

    print(f"\nTest AUC: {test_auc:.4f}  AUPRC: {test_auprc:.4f}  F1: {test_f1:.4f}")
    print(classification_report(test_labels, test_pred,
                                target_names=['legit', 'scam'], digits=4))

    # Save metadata
    bert_meta = {
        'model_name':    MODEL_NAME,
        'threshold':     best_thresh,
        'test_auc':      test_auc,
        'test_auprc':    test_auprc,
        'test_f1':       test_f1,
        'best_val_auprc': best_auprc,
        'history':       history,
        'hyperparams': {
            'epochs': epochs, 'batch_size': batch_size,
            'lr': lr, 'warmup_ratio': warmup_ratio,
        },
    }
    with open(MODELS_DIR / 'bert_meta.json', 'w') as f:
        json.dump(bert_meta, f, indent=2)

    print(f"\n✅ Saved:")
    print(f"   models/bert/   (HuggingFace checkpoint)")
    print(f"   models/bert_meta.json")
    print(f"\nNext step: python ml/ensemble.py")


# ── MODAL ENTRY POINT ─────────────────────────────────────────────────────────
# Run with: modal run ml/train_bert.py::main_modal
# This deploys training to Modal's cloud GPU infrastructure.

try:
    import modal

    stub = modal.Stub("verifyjobs-bert-training")

    image = (
        modal.Image.debian_slim(python_version="3.11")
        .pip_install([
            "torch==2.2.0", "transformers==4.40.0",
            "datasets", "scikit-learn", "pandas", "numpy",
            "pyarrow",
        ])
    )

    @stub.function(
        image=image,
        gpu="A10G",
        timeout=3600,
        mounts=[
            modal.Mount.from_local_dir(
                Path(__file__).parent.parent / "data",
                remote_path="/root/data"
            )
        ],
        volumes={"/root/models": modal.Volume.new()},
    )
    def main_modal():
        import sys
        sys.path.insert(0, '/root')
        main(epochs=3, batch_size=32, lr=2e-5, fp16=True)

except ImportError:
    pass  # Modal not installed — that's fine for local runs


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--epochs',      type=int,   default=3)
    parser.add_argument('--batch_size',  type=int,   default=32)
    parser.add_argument('--lr',          type=float, default=2e-5)
    parser.add_argument('--warmup_ratio',type=float, default=0.1)
    parser.add_argument('--no_fp16',     action='store_true')
    args = parser.parse_args()

    main(
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        warmup_ratio=args.warmup_ratio,
        fp16=not args.no_fp16,
    )
