"""
VerifyJobs ML — Tinker-Backed Scam Classifier (Qwen3-8B via SFT)
=================================================================
Replaces the original DistilBERT + Modal setup with Thinking Machines'
Tinker API. Your Codespace runs the orchestration loop (CPU only);
Tinker's GPU clusters handle all forward/backward passes.

Resources
---------
  - GitHub Codespace  : orchestration, data prep, metrics (zero GPU needed)
  - Thinking Machines : GPU compute via Tinker API (pay-per-token, ~$0.44/M train tokens)
  - Model             : Qwen/Qwen3-8B  (cheapest dense model with strong classification perf)

Setup (run once in Codespace terminal)
---------------------------------------
  pip install tinker tinker-cookbook scikit-learn pandas pyarrow numpy
  export TINKER_API_KEY="<your-api-key>"        # rotate the one you shared publicly!

Run
----
  python ml2/train_bert_tinker.py
  python ml2/train_bert_tinker.py --epochs 1    # quick smoke-test

Outputs (same paths as before, so downstream code is unchanged)
----------------------------------------------------------------
  models/bert/          — placeholder dir + adapter info (weights live in Tinker cloud)
  models/bert_meta.json — eval metrics, threshold, Tinker run details
"""

import argparse
import asyncio
import json
import os
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score, classification_report,
    f1_score, precision_recall_curve, roc_auc_score,
)

warnings.filterwarnings("ignore")

# ── PATHS ─────────────────────────────────────────────────────────────────────

ROOT       = Path(__file__).parent.parent
PROCESSED  = ROOT / "data" / "processed"
MODELS_DIR = ROOT / "models"
BERT_DIR   = MODELS_DIR / "bert"
BERT_DIR.mkdir(parents=True, exist_ok=True)

# ── TINKER CONFIG ──────────────────────────────────────────────────────────────

BASE_MODEL = "Qwen/Qwen3-8B"   # $0.44/M train tokens; change to Qwen3.5-4B to go cheaper
LORA_RANK  = 16                  # 16 is plenty for binary classification

# ── PROMPT HELPERS ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "You are a job-posting fraud detector. "
    "Given a job posting, reply with exactly one word: SCAM or LEGIT."
)

def make_prompt(text: str) -> str:
    """Wrap a job posting in the instruct template Qwen3 expects."""
    return (
        f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n"
        f"<|im_start|>user\n{text[:2000]}<|im_end|>\n"   # cap at 2000 chars to save tokens
        f"<|im_start|>assistant\n"
    )

LABEL_MAP = {0: "LEGIT", 1: "SCAM"}

def make_target(label: int) -> str:
    return LABEL_MAP[label] + "<|im_end|>"


# ── METRICS ────────────────────────────────────────────────────────────────────

def find_best_threshold(y_true, y_prob):
    """Maximise F1 subject to recall >= 0.80 (same logic as original)."""
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_prob)
    f1s            = 2 * precisions * recalls / (precisions + recalls + 1e-8)
    recall_penalty = np.where(recalls[:-1] < 0.80, -1.0, 0.0)
    adjusted_f1s   = f1s[:-1] + recall_penalty
    best_idx       = np.argmax(adjusted_f1s)
    return float(thresholds[best_idx]), float(f1s[best_idx])


# ── EVALUATION ─────────────────────────────────────────────────────────────────

async def evaluate_split(sampling_client, tokenizer, df, split_name: str):
    """
    Run inference on a dataframe split. Returns (probs, labels).
    Tinker's SamplingClient accepts batches via asyncio.gather, so we
    fire all requests concurrently (up to 32 at a time to stay polite).
    """
    import tinker
    from tinker import types

    texts  = df["text_clean"].tolist()
    labels = df["label"].tolist()

    BATCH = 32
    all_probs = []

    for start in range(0, len(texts), BATCH):
        batch_texts = texts[start : start + BATCH]
        prompts = [
            types.ModelInput.from_ints(
                tokenizer.encode(make_prompt(t))
            )
            for t in batch_texts
        ]

        # Fire all sample calls in parallel
        params = types.SamplingParams(max_tokens=4, temperature=0.0)
        results = await asyncio.gather(*[
            sampling_client.sample_async(prompt=p, num_samples=1, sampling_params=params)
            for p in prompts
        ])

        for res in results:
            decoded = tokenizer.decode(res.sequences[0].tokens).strip().upper()
            # Convert to a probability: SCAM → 1.0, anything else → 0.0
            # (greedy decode at temp=0 so no calibration needed for threshold search)
            prob = 1.0 if "SCAM" in decoded else 0.0
            all_probs.append(prob)

        done = min(start + BATCH, len(texts))
        print(f"  [{split_name}] {done}/{len(texts)} evaluated", end="\r")

    print()
    return np.array(all_probs), np.array(labels)


# ── TRAINING LOOP ──────────────────────────────────────────────────────────────

async def main(
    epochs:       int   = 3,
    batch_size:   int   = 4,    # keep small; each datum can be 500+ tokens
    lr:           float = 1e-4,
    warmup_steps: int   = 50,
):
    import tinker
    from tinker import types

    print("\n=== VerifyJobs — Tinker-Backed Scam Classifier ===\n")
    print(f"Model : {BASE_MODEL}")
    print(f"LoRA  : rank={LORA_RANK}")
    print(f"Hyper : epochs={epochs}, batch={batch_size}, lr={lr}\n")

    # ── Load data ──────────────────────────────────────────────────────────────
    train_df = pd.read_parquet(PROCESSED / "train.parquet")
    val_df   = pd.read_parquet(PROCESSED / "val.parquet")
    test_df  = pd.read_parquet(PROCESSED / "test.parquet")

    with open(PROCESSED / "feature_meta.json") as f:
        meta = json.load(f)

    cw = meta["class_weights"]
    print(f"Train: {len(train_df):,}  Val: {len(val_df):,}  Test: {len(test_df):,}")
    print(f"Class weights: legit={cw['0']:.3f}  scam={cw['1']:.3f}\n")

    # ── Connect to Tinker ──────────────────────────────────────────────────────
    api_key = os.environ.get("TINKER_API_KEY")
    if not api_key:
        raise EnvironmentError("Set TINKER_API_KEY environment variable before running.")

    service_client = tinker.ServiceClient(api_key=api_key)

    training_client = await service_client.create_lora_training_client_async(
        base_model=BASE_MODEL,
        rank=LORA_RANK,
    )
    tokenizer = training_client.get_tokenizer()
    print("✅ Connected to Tinker — training session started\n")

    # ── Build training data ────────────────────────────────────────────────────
    # Each Datum = (prompt tokens, target tokens, per-token loss weights)
    # Loss weight = 0 on the prompt, 1 on the completion ("SCAM"/"LEGIT")
    def build_datum(row) -> types.Datum:
        prompt_text  = make_prompt(row["text_clean"])
        target_text  = make_target(int(row["label"]))

        prompt_ids = tokenizer.encode(prompt_text)
        target_ids = tokenizer.encode(target_text)

        # Full sequence: prompt + completion
        input_tokens  = prompt_ids + target_ids
        target_tokens = prompt_ids + target_ids          # shifted by 1 inside Tinker
        weights       = [0.0] * len(prompt_ids) + [1.0] * len(target_ids)

        # Apply class weight so the scam class gets upweighted
        class_weight = float(cw["1"]) if int(row["label"]) == 1 else float(cw["0"])
        weights = [w * class_weight for w in weights]

        return types.Datum(
            model_input=types.ModelInput.from_ints(tokens=input_tokens),
            loss_fn_inputs=dict(
                weights=weights,
                target_tokens=target_tokens,
            ),
        )

    print("Building training data (CPU)...")
    train_data = [build_datum(row) for _, row in train_df.iterrows()]
    print(f"  {len(train_data):,} training examples ready\n")

    # ── Training loop ──────────────────────────────────────────────────────────
    best_auprc  = 0.0
    best_thresh = 0.5
    history     = []
    best_run_id = None

    steps_per_epoch = max(1, len(train_data) // batch_size)
    total_steps     = steps_per_epoch * epochs

    for epoch in range(1, epochs + 1):
        print(f"── Epoch {epoch}/{epochs} ──")
        np.random.shuffle(train_data)   # shuffle in place each epoch

        epoch_loss = 0.0
        num_batches = 0

        for step in range(0, len(train_data), batch_size):
            batch = train_data[step : step + batch_size]

            # Adaptive LR with linear warmup
            global_step = (epoch - 1) * steps_per_epoch + num_batches + 1
            warmup_lr   = lr * min(1.0, global_step / max(1, warmup_steps))

            # Submit fwd/bwd and optim_step in the same clock cycle for efficiency
            fwd_future   = await training_client.forward_backward_async(
                data=batch, loss_fn="cross_entropy"
            )
            optim_future = await training_client.optim_step_async(
                types.AdamParams(learning_rate=warmup_lr)
            )

            # Wait for both
            fwd_result = await fwd_future.result_async()
            await optim_future.result_async()

            # Extract scalar loss — it lives in .metrics, not as a direct attribute
            # Common keys: "loss", "cross_entropy_loss", "mean_loss"
            step_loss = 0.0
            if fwd_result.metrics:
                for key in ("loss", "cross_entropy_loss", "mean_loss"):
                    if key in fwd_result.metrics:
                        step_loss = float(fwd_result.metrics[key])
                        break
                else:
                    # Fallback: take the first numeric metric value
                    for v in fwd_result.metrics.values():
                        try:
                            step_loss = float(v)
                            break
                        except (TypeError, ValueError):
                            pass

            epoch_loss += step_loss
            num_batches += 1

            if num_batches % 50 == 0:
                print(f"  Step {global_step}/{total_steps}  loss={epoch_loss/num_batches:.4f}")

        avg_loss = epoch_loss / max(1, num_batches)
        print(f"  Avg train loss: {avg_loss:.4f}")

        # ── Validate ───────────────────────────────────────────────────────────
        print("  Saving weights for validation sampling...")
        val_sampler = await training_client.save_weights_and_get_sampling_client_async(
            name=f"epoch-{epoch}"
        )

        val_probs, val_labels = await evaluate_split(
            val_sampler, tokenizer, val_df, "val"
        )

        val_auc   = roc_auc_score(val_labels, val_probs)
        val_auprc = average_precision_score(val_labels, val_probs)
        thresh, val_f1 = find_best_threshold(val_labels, val_probs)

        print(
            f"  Val AUC={val_auc:.4f}  AUPRC={val_auprc:.4f}  "
            f"F1={val_f1:.4f}  Thresh={thresh:.3f}"
        )

        history.append({
            "epoch":      epoch,
            "train_loss": avg_loss,
            "val_auc":    val_auc,
            "val_auprc":  val_auprc,
            "val_f1":     val_f1,
            "threshold":  thresh,
        })

        if val_auprc > best_auprc:
            best_auprc  = val_auprc
            best_thresh = thresh
            # Record the Tinker run/session so we can reload later
            best_run_id = training_client.run_id if hasattr(training_client, "run_id") else f"epoch-{epoch}"
            # Save full training state (weights + optimiser) for resuming
            training_client.save_state(name=f"best-epoch-{epoch}")
            print(f"  ✅ New best AUPRC={best_auprc:.4f} — state saved as best-epoch-{epoch}")

    # ── Final test evaluation ──────────────────────────────────────────────────
    print("\n── Final test evaluation (using best validation checkpoint) ──")
    test_probs, test_labels = await evaluate_split(
        val_sampler, tokenizer, test_df, "test"
    )

    test_auc   = roc_auc_score(test_labels, test_probs)
    test_auprc = average_precision_score(test_labels, test_probs)
    test_pred  = (test_probs >= best_thresh).astype(int)
    test_f1    = f1_score(test_labels, test_pred)

    print(f"\nTest AUC={test_auc:.4f}  AUPRC={test_auprc:.4f}  F1={test_f1:.4f}")
    print(classification_report(
        test_labels, test_pred, target_names=["legit", "scam"], digits=4
    ))

    # ── Save metadata (mirrors original bert_meta.json schema) ────────────────
    bert_meta = {
        "model_name":     BASE_MODEL,
        "threshold":      best_thresh,
        "test_auc":       test_auc,
        "test_auprc":     test_auprc,
        "test_f1":        test_f1,
        "best_val_auprc": best_auprc,
        "history":        history,
        "tinker": {
            "run_id":     best_run_id,
            "lora_rank":  LORA_RANK,
            "note": (
                "Weights live in Tinker cloud. To reload: "
                "service_client.create_training_client_from_state_async("
                f"path='tinker://{best_run_id}/weights/best-epoch-*')"
            ),
        },
        "hyperparams": {
            "epochs":       epochs,
            "batch_size":   batch_size,
            "lr":           lr,
            "warmup_steps": warmup_steps,
        },
    }

    with open(MODELS_DIR / "bert_meta.json", "w") as f:
        json.dump(bert_meta, f, indent=2)

    # Write a stub README in models/bert/ so downstream code finds the directory
    (BERT_DIR / "README.md").write_text(
        f"# VerifyJobs LoRA adapter\n\n"
        f"Weights are stored in Thinking Machines Tinker cloud.\n"
        f"Run ID : {best_run_id}\n"
        f"See    : ../bert_meta.json for reload instructions.\n"
    )

    print(f"\n✅ Saved:")
    print(f"   models/bert_meta.json")
    print(f"   models/bert/README.md")
    print(f"\nNext step: python ml/ensemble.py")
    print(
        f"\nTo download weights to HuggingFace format later:\n"
        f"  from tinker_cookbook.weights import build_hf_model\n"
        f"  build_hf_model(run_id='{best_run_id}', checkpoint='best-epoch-*', out_dir='models/bert')"
    )


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train VerifyJobs scam classifier via Thinking Machines Tinker API"
    )
    parser.add_argument("--epochs",       type=int,   default=3,    help="Training epochs")
    parser.add_argument("--batch_size",   type=int,   default=4,    help="Gradient batch size")
    parser.add_argument("--lr",           type=float, default=1e-4, help="Peak learning rate")
    parser.add_argument("--warmup_steps", type=int,   default=50,   help="LR warmup steps")
    args = parser.parse_args()

    asyncio.run(main(
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        warmup_steps=args.warmup_steps,
    ))