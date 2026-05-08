#!/usr/bin/env python3
"""
TorchSight LoRA Fine-Tuning Script

Fine-tunes a base model (Qwen 3.5 / Llama 3.x) on the TorchSight
security classification dataset using LoRA/QLoRA.

Auto-detects model family (Qwen, Llama, Mistral, etc.) from the model
name to select appropriate LoRA targets and chat template.

Requirements:
    pip install torch transformers peft datasets accelerate bitsandbytes trl

Usage:
    # Default: Qwen 3.5 27B (requires ~55GB VRAM for LoRA on each GPU; we used 8× A100 80GB SXM4 / 10.5 hr)
    python train_lora.py

    # QLoRA 4-bit (fits in ~24GB VRAM)
    python train_lora.py --quantize 4bit

    # Use Llama instead
    python train_lora.py --base-model meta-llama/Llama-3.1-8B-Instruct --batch-size 8 --max-seq-length 4096

    # Custom settings
    python train_lora.py --epochs 3 --lr 2e-4

    # Resume from checkpoint
    python train_lora.py --resume ./output/checkpoint-1000
"""

import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SFT_DIR = Path(os.environ.get("TORCHSIGHT_DATA_DIR", SCRIPT_DIR.parent / "data" / "sft"))
OUTPUT_DIR = Path(os.environ.get("TORCHSIGHT_OUTPUT_DIR", SCRIPT_DIR.parent / "output"))

# Default hyperparameters — Qwen 3.5 27B on 8× A100 80GB SXM4 (Beam v1.0 production run)
DEFAULTS = {
    "base_model": "Qwen/Qwen3.5-27B",
    "format": "alpaca",
    "epochs": 5,
    "lr": 2e-5,
    "batch_size": 4,         # per-GPU; fits A100 80GB with LoRA + gradient checkpointing
    "grad_accum": 4,         # effective batch = 16 per GPU
    "max_seq_length": 4096,
    "lora_r": 128,           # high rank for maximum adaptation capacity
    "lora_alpha": 256,       # 2x rank (standard ratio)
    "lora_dropout": 0.05,
    "warmup_ratio": 0.10,
    "weight_decay": 0.01,
    "quantize": None,        # full bf16 — best quality, A100 80GB handles 27B
    "resume": None,
}

# LoRA target modules per model family — all linear layers for maximum adaptation
LORA_TARGETS = {
    "llama": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    "qwen": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    "mistral": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    "phi": ["q_proj", "k_proj", "v_proj", "dense", "fc1", "fc2"],
    "gemma": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
}


def detect_model_family(model_name: str) -> str:
    """Auto-detect model family from the model name/path.

    Used to select LoRA target modules and chat template behavior.
    Checks for known family names in the model identifier.
    """
    name_lower = model_name.lower()
    # Check in priority order (qwen2 before qwen to catch both)
    family_patterns = {
        "qwen": ["qwen3.5", "qwen3", "qwen2.5", "qwen2", "qwen"],
        "llama": ["llama"],
        "mistral": ["mistral"],
        "phi": ["phi"],
        "gemma": ["gemma"],
    }
    for family, patterns in family_patterns.items():
        for pattern in patterns:
            if pattern in name_lower:
                return family
    return "llama"  # default fallback


def parse_args():
    config = dict(DEFAULTS)
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        key = args[i].lstrip("-").replace("-", "_")
        if i + 1 < len(args) and not args[i + 1].startswith("--"):
            val = args[i + 1]
            # Type coerce
            if key in ("epochs", "batch_size", "grad_accum", "max_seq_length", "lora_r", "lora_alpha"):
                val = int(val)
            elif key in ("lr", "lora_dropout", "warmup_ratio", "weight_decay"):
                val = float(val)
            config[key] = val
            i += 2
        else:
            config[key] = True
            i += 1
    return config


def main():
    config = parse_args()

    print("=" * 60)
    print("  TorchSight LoRA Fine-Tuning")
    print("=" * 60)
    print(f"\nBase model:    {config['base_model']}")
    print(f"Format:        {config['format']}")
    print(f"Quantization:  {config['quantize'] or 'none (full precision)'}")
    print(f"LoRA rank:     {config['lora_r']}")
    print(f"LoRA alpha:    {config['lora_alpha']}")
    print(f"Epochs:        {config['epochs']}")
    print(f"Learning rate: {config['lr']}")
    print(f"Batch size:    {config['batch_size']} x {config['grad_accum']} grad accum")
    print(f"Max seq len:   {config['max_seq_length']}")

    # Verify training data exists
    train_file = SFT_DIR / f"train_{config['format']}.jsonl"
    val_file = SFT_DIR / f"val_{config['format']}.jsonl"

    if not train_file.exists():
        print(f"\nERROR: Training data not found at {train_file}")
        print("Run sft_converter.py first to generate training data.")
        sys.exit(1)

    train_count = sum(1 for _ in open(train_file))
    val_count = sum(1 for _ in open(val_file)) if val_file.exists() else 0
    print(f"\nTraining data: {train_count:,} samples")
    print(f"Validation:    {val_count:,} samples")

    # Import heavy dependencies
    print("\nLoading libraries...")
    try:
        import torch
        from datasets import load_dataset
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            TrainingArguments,
            BitsAndBytesConfig,
        )
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from trl import SFTTrainer, SFTConfig
    except ImportError as e:
        print(f"\nMissing dependency: {e}")
        print("\nInstall requirements:")
        print("  pip install torch transformers peft datasets accelerate bitsandbytes trl")
        sys.exit(1)

    # Quantization config
    bnb_config = None
    if config["quantize"] == "4bit":
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )
        print("\nUsing 4-bit QLoRA quantization")
    elif config["quantize"] == "8bit":
        bnb_config = BitsAndBytesConfig(load_in_8bit=True)
        print("\nUsing 8-bit quantization")

    # Load tokenizer
    print(f"\nLoading tokenizer: {config['base_model']}")
    tokenizer = AutoTokenizer.from_pretrained(
        config["base_model"],
        trust_remote_code=True,
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    # Load model
    print(f"Loading model: {config['base_model']}")
    model_kwargs = {
        "trust_remote_code": True,
        "torch_dtype": torch.bfloat16,
    }
    if bnb_config:
        model_kwargs["quantization_config"] = bnb_config

    # In distributed mode (torchrun), each process loads onto its own GPU
    local_rank = int(os.environ.get("LOCAL_RANK", -1))
    if local_rank >= 0:
        model_kwargs["device_map"] = {"": local_rank}
    else:
        model_kwargs["device_map"] = "auto"

    model = AutoModelForCausalLM.from_pretrained(
        config["base_model"],
        **model_kwargs,
    )

    if config["quantize"]:
        model = prepare_model_for_kbit_training(model)

    # LoRA config
    family = detect_model_family(config["base_model"])
    target_modules = LORA_TARGETS.get(family, LORA_TARGETS["llama"])
    print(f"\nModel family:  {family}")
    print(f"LoRA targets:  {target_modules}")
    print(f"Chat template: {'native (tokenizer.apply_chat_template)' if family in ('qwen', 'llama', 'mistral', 'gemma') else 'generic'}")

    lora_config = LoraConfig(
        r=config["lora_r"],
        lora_alpha=config["lora_alpha"],
        lora_dropout=config["lora_dropout"],
        target_modules=target_modules,
        bias="none",
        task_type="CAUSAL_LM",
    )

    model = get_peft_model(model, lora_config)
    trainable, total = model.get_nb_trainable_parameters()
    print(f"Trainable parameters: {trainable:,} / {total:,} ({100 * trainable / total:.2f}%)")

    # Load datasets
    print("\nLoading datasets...")
    dataset = load_dataset("json", data_files={
        "train": str(train_file),
        "validation": str(val_file) if val_file.exists() else None,
    })

    # Format function based on format type
    # trl 0.15 probes with a single example (dict), then calls with batches
    if config["format"] == "chatml":
        def formatting_func(example):
            messages = example["messages"]
            # Single example: messages is a list of dicts
            if isinstance(messages, list) and len(messages) > 0 and isinstance(messages[0], dict):
                return tokenizer.apply_chat_template(
                    messages, tokenize=False, add_generation_prompt=False
                )
            # Batched: messages is a list of lists
            texts = []
            for msgs in messages:
                texts.append(tokenizer.apply_chat_template(
                    msgs, tokenize=False, add_generation_prompt=False
                ))
            return texts
    elif config["format"] == "alpaca":
        def formatting_func(example):
            inst = example["instruction"]
            inp = example["input"]
            out = example["output"]
            if isinstance(inst, str):
                return f"### Instruction:\n{inst}\n\n### Input:\n{inp}\n\n### Response:\n{out}"
            return [f"### Instruction:\n{i}\n\n### Input:\n{p}\n\n### Response:\n{o}"
                    for i, p, o in zip(inst, inp, out)]
    else:
        def formatting_func(example):
            prompt = example["prompt"]
            completion = example["completion"]
            if isinstance(prompt, str):
                return f"{prompt}{completion}"
            return [f"{p}{c}" for p, c in zip(prompt, completion)]

    # Training arguments
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / f"torchsight-{family}-lora"

    has_eval = val_file.exists()
    sft_kwargs = {
        "output_dir": str(output_path),
        "num_train_epochs": config["epochs"],
        "per_device_train_batch_size": config["batch_size"],
        "gradient_accumulation_steps": config["grad_accum"],
        "learning_rate": config["lr"],
        "warmup_ratio": config["warmup_ratio"],
        "weight_decay": config["weight_decay"],
        "logging_steps": 10,
        "save_strategy": "steps",
        "save_steps": 200,
        "save_total_limit": 3,
        "eval_strategy": "steps" if has_eval else "no",
        "eval_steps": 200 if has_eval else None,
        "load_best_model_at_end": has_eval,
        "metric_for_best_model": "eval_loss" if has_eval else None,
        "greater_is_better": False if has_eval else None,
        "bf16": torch.cuda.is_bf16_supported() if torch.cuda.is_available() else False,
        "fp16": not torch.cuda.is_bf16_supported() if torch.cuda.is_available() else False,
        "max_grad_norm": 0.5,
        "gradient_checkpointing": True,
        "optim": "paged_adamw_8bit" if config["quantize"] else "adamw_torch_fused",
        "lr_scheduler_type": "cosine",
        "logging_nan_inf_filter": False,
        "report_to": "none",
        "dataloader_num_workers": 4,
        "dataloader_pin_memory": True,
        "seed": 3407,
    }
    # max_seq_length moved in newer trl versions
    import inspect
    if "max_seq_length" in inspect.signature(SFTConfig.__init__).parameters:
        sft_kwargs["max_seq_length"] = config["max_seq_length"]
    training_args = SFTConfig(**sft_kwargs)

    # Trainer — trl 0.29+ renamed tokenizer to processing_class
    trainer_kwargs = {
        "model": model,
        "args": training_args,
        "train_dataset": dataset["train"],
        "eval_dataset": dataset.get("validation"),
        "formatting_func": formatting_func,
    }
    if "processing_class" in inspect.signature(SFTTrainer.__init__).parameters:
        trainer_kwargs["processing_class"] = tokenizer
    else:
        trainer_kwargs["tokenizer"] = tokenizer
    trainer = SFTTrainer(**trainer_kwargs)

    # Train
    print(f"\n{'=' * 60}")
    print("  Starting training...")
    print(f"{'=' * 60}")

    if config.get("resume"):
        trainer.train(resume_from_checkpoint=config["resume"])
    else:
        trainer.train()

    # Save
    print(f"\nSaving LoRA adapter to {output_path}")
    model.save_pretrained(str(output_path))
    tokenizer.save_pretrained(str(output_path))

    # Save training config
    with open(output_path / "training_config.json", "w") as f:
        json.dump(config, f, indent=2)

    print(f"\nTraining complete!")
    print(f"LoRA adapter saved to: {output_path}")
    print(f"\nTo merge and export GGUF:")
    print(f"  python export_gguf.py --adapter {output_path}")


if __name__ == "__main__":
    main()
