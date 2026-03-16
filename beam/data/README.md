# Training Data

This directory is populated by `beam/train.sh`. All data files are gitignored.

```
data/
├── raw/          Downloaded datasets (18 sources, ~2GB)
├── processed/    Normalized JSONL per source + combined_train.jsonl
├── synthetic/    Generated samples (synth + hard negatives)
└── sft/          Final SFT format (train_alpaca.jsonl + val_alpaca.jsonl)
```

**Pipeline:** raw → processors → processed → rebalance → sft → training

See [beam/README.md](../README.md) for dataset sources and sample counts.
