#!/usr/bin/env python3
"""
TorchSight LoRA Fine-Tuning Script

Fine-tunes a base model (Llama 3.2 / Qwen2.5) on the TorchSight
security classification dataset using LoRA/QLoRA.

Requirements:
    pip install torch transformers peft datasets accelerate bitsandbytes trl

Usage:
    # Full fine-tune (requires ~24GB VRAM)
    python train_lora.py --base-model meta-llama/Llama-3.2-3B-Instruct

    # QLoRA 4-bit (requires ~8GB VRAM)
    python train_lora.py --base-model meta-llama/Llama-3.2-3B-Instruct --quantize 4bit

    # Custom settings
    python train_lora.py --base-model Qwen/Qwen2.5-3B-Instruct --epochs 3 --lr 2e-4

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

# Default hyperparameters — tuned for high-VRAM GPU (GH200/A100/H100)
DEFAULTS = {
    "base_model": "meta-llama/Llama-3.2-3B-Instruct",
    "format": "chatml",
    "epochs": 3,
    "lr": 1e-4,
    "batch_size": 16,
    "grad_accum": 2,
    "max_seq_length": 4096,
    "lora_r": 64,
    "lora_alpha": 128,
    "lora_dropout": 0.05,
    "warmup_ratio": 0.05,
    "weight_decay": 0.01,
    "quantize": None,  # None = full bf16 (best quality)
    "resume": None,
}

# LoRA target modules per model family — all linear layers for maximum adaptation
LORA_TARGETS = {
    "llama": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj", "lm_head"],
    "qwen": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj", "lm_head"],
    "mistral": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj", "lm_head"],
    "phi": ["q_proj", "k_proj", "v_proj", "dense", "fc1", "fc2", "lm_head"],
    "gemma": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj", "lm_head"],
}


def detect_model_family(model_name: str) -> str:
    name_lower = model_name.lower()
    for family in LORA_TARGETS:
        if family in name_lower:
            return family
    return "llama"  # default


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
        "device_map": "auto",
    }
    if bnb_config:
        model_kwargs["quantization_config"] = bnb_config

    model = AutoModelForCausalLM.from_pretrained(
        config["base_model"],
        **model_kwargs,
    )

    if config["quantize"]:
        model = prepare_model_for_kbit_training(model)

    # LoRA config
    family = detect_model_family(config["base_model"])
    target_modules = LORA_TARGETS.get(family, LORA_TARGETS["llama"])
    print(f"\nModel family: {family}")
    print(f"LoRA targets: {target_modules}")

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
    if config["format"] == "chatml":
        def formatting_func(examples):
            texts = []
            for messages in examples["messages"]:
                text = tokenizer.apply_chat_template(
                    messages, tokenize=False, add_generation_prompt=False
                )
                texts.append(text)
            return texts
    elif config["format"] == "alpaca":
        def formatting_func(examples):
            texts = []
            for inst, inp, out in zip(examples["instruction"], examples["input"], examples["output"]):
                text = f"### Instruction:\n{inst}\n\n### Input:\n{inp}\n\n### Response:\n{out}"
                texts.append(text)
            return texts
    else:
        def formatting_func(examples):
            texts = []
            for prompt, completion in zip(examples["prompt"], examples["completion"]):
                texts.append(f"{prompt}{completion}")
            return texts

    # Training arguments
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / f"torchsight-{family}-lora"

    has_eval = val_file.exists()
    training_args = SFTConfig(
        output_dir=str(output_path),
        num_train_epochs=config["epochs"],
        per_device_train_batch_size=config["batch_size"],
        gradient_accumulation_steps=config["grad_accum"],
        learning_rate=config["lr"],
        warmup_ratio=config["warmup_ratio"],
        weight_decay=config["weight_decay"],
        max_seq_length=config["max_seq_length"],
        logging_steps=10,
        save_strategy="steps",
        save_steps=250,
        save_total_limit=5,
        eval_strategy="steps" if has_eval else "no",
        eval_steps=250 if has_eval else None,
        load_best_model_at_end=has_eval,
        metric_for_best_model="eval_loss" if has_eval else None,
        greater_is_better=False if has_eval else None,
        bf16=torch.cuda.is_bf16_supported() if torch.cuda.is_available() else False,
        fp16=not torch.cuda.is_bf16_supported() if torch.cuda.is_available() else False,
        gradient_checkpointing=True,
        optim="paged_adamw_8bit" if config["quantize"] else "adamw_torch_fused",
        lr_scheduler_type="cosine",
        report_to="none",
        dataloader_num_workers=4,
        dataloader_pin_memory=True,
        seed=42,
    )

    # Trainer
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset["train"],
        eval_dataset=dataset.get("validation"),
        processing_class=tokenizer,
        formatting_func=formatting_func,
    )

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
