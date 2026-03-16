# TorchSight Sentinel

> On-premise cybersecurity document classifier — trained to detect threats, sensitive data, and policy violations in text and images.

## Model Overview

| | |
|---|---|
| **Name** | `torchsight/sentinel` |
| **Base model** | Llama 3.1 8B Instruct |
| **Method** | LoRA fine-tuning (rank 64, alpha 128) |
| **Training data** | 105,168 samples across 51 subcategories |
| **Output format** | GGUF (q4_k_m) for Ollama (~5GB) |
| **License** | Apache 2.0 |

---

## How It Works

The model classifies text into 7 top-level categories with 51 subcategories. Given any document, it outputs a JSON array of findings with category, severity, and explanation.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {
  'primaryColor': '#7c3aed',
  'primaryTextColor': '#e5e7eb',
  'primaryBorderColor': '#c4b5fd',
  'lineColor': '#22d3ee',
  'secondaryColor': '#111118',
  'tertiaryColor': '#1e1e2e',
  'background': '#0a0a0f',
  'mainBkg': '#111118',
  'nodeBorder': '#7c3aed',
  'clusterBkg': '#1e1e2e',
  'titleColor': '#c4b5fd',
  'edgeLabelBackground': '#111118'
}}}%%

graph LR
    A[📄 Document] --> B[TorchSight CLI]
    B --> C{File Type}
    C -->|Text| D[LLM Analysis]
    C -->|Image| E[Tesseract OCR]
    E --> F[Vision Description]
    F --> D
    D --> G[Sentinel Model]
    G --> H["JSON Findings"]

    style A fill:#1e1e2e,stroke:#7c3aed,color:#e5e7eb
    style B fill:#7c3aed,stroke:#c4b5fd,color:#fff
    style C fill:#1e1e2e,stroke:#22d3ee,color:#e5e7eb
    style D fill:#1e1e2e,stroke:#7c3aed,color:#e5e7eb
    style E fill:#1e1e2e,stroke:#f97316,color:#e5e7eb
    style F fill:#1e1e2e,stroke:#f97316,color:#e5e7eb
    style G fill:#7c3aed,stroke:#c4b5fd,color:#fff
    style H fill:#22d3ee,stroke:#22d3ee,color:#0a0a0f
```

---

## Training Pipeline

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {
  'primaryColor': '#7c3aed',
  'primaryTextColor': '#e5e7eb',
  'primaryBorderColor': '#c4b5fd',
  'lineColor': '#22d3ee',
  'secondaryColor': '#111118',
  'tertiaryColor': '#1e1e2e',
  'background': '#0a0a0f',
  'mainBkg': '#111118',
  'nodeBorder': '#7c3aed',
  'clusterBkg': '#1e1e2e',
  'edgeLabelBackground': '#111118'
}}}%%

graph TD
    subgraph COLLECT ["① Data Collection"]
        NVD["NVD CVEs<br/>50,000"]
        OSSF["OSSF Malicious<br/>5,000"]
        SEC["SecLists<br/>3,229"]
        GHSA["GitHub Advisories<br/>3,000"]
        ENR["Enron Emails<br/>2,000"]
        MTS["MTSamples<br/>2,000"]
        MIT["MITRE ATT&CK<br/>1,620"]
        PI["Prompt Injection<br/>263"]
        CRS["CRS Reports<br/>156"]
    end

    subgraph PROCESS ["② Processing"]
        PROC["9 Processors<br/>Map to taxonomy"]
        SYNTH["40 Generators<br/>Synthetic data"]
    end

    subgraph COMBINE ["③ Combine & Convert"]
        COMB["combined_train.jsonl<br/>105,168 samples"]
        SFT["SFT Converter<br/>ChatML format"]
    end

    subgraph TRAIN ["④ Train"]
        BASE["Llama 3.1 8B<br/>Instruct"]
        LORA["LoRA Adapter<br/>r=64, α=128"]
        BEST["Best Checkpoint<br/>by eval loss"]
    end

    subgraph EXPORT ["⑤ Export"]
        MERGE["Merge LoRA<br/>+ Base Model"]
        GGUF["Quantize<br/>q4_k_m GGUF"]
        OLLAMA["Ollama<br/>torchsight/sentinel"]
    end

    NVD & OSSF & SEC & GHSA & ENR & MTS & MIT & PI & CRS --> PROC
    PROC --> COMB
    SYNTH --> COMB
    COMB --> SFT
    SFT --> LORA
    BASE --> LORA
    LORA --> BEST
    BEST --> MERGE
    MERGE --> GGUF
    GGUF --> OLLAMA

    style NVD fill:#ef4444,stroke:#ef4444,color:#fff
    style OSSF fill:#f43f5e,stroke:#f43f5e,color:#fff
    style SEC fill:#f97316,stroke:#f97316,color:#fff
    style GHSA fill:#fb923c,stroke:#fb923c,color:#fff
    style ENR fill:#eab308,stroke:#eab308,color:#0a0a0f
    style MTS fill:#22c55e,stroke:#22c55e,color:#fff
    style MIT fill:#3b82f6,stroke:#3b82f6,color:#fff
    style PI fill:#818cf8,stroke:#818cf8,color:#fff
    style CRS fill:#8b5cf6,stroke:#8b5cf6,color:#fff
    style PROC fill:#7c3aed,stroke:#c4b5fd,color:#fff
    style SYNTH fill:#22d3ee,stroke:#22d3ee,color:#0a0a0f
    style COMB fill:#1e1e2e,stroke:#7c3aed,color:#e5e7eb
    style SFT fill:#1e1e2e,stroke:#7c3aed,color:#e5e7eb
    style BASE fill:#1e1e2e,stroke:#22d3ee,color:#e5e7eb
    style LORA fill:#7c3aed,stroke:#c4b5fd,color:#fff
    style BEST fill:#7c3aed,stroke:#c4b5fd,color:#fff
    style MERGE fill:#1e1e2e,stroke:#22d3ee,color:#e5e7eb
    style GGUF fill:#22d3ee,stroke:#22d3ee,color:#0a0a0f
    style OLLAMA fill:#22d3ee,stroke:#22d3ee,color:#0a0a0f

    style COLLECT fill:#1e1e2e,stroke:#7c3aed,color:#c4b5fd
    style PROCESS fill:#1e1e2e,stroke:#7c3aed,color:#c4b5fd
    style COMBINE fill:#1e1e2e,stroke:#22d3ee,color:#c4b5fd
    style TRAIN fill:#1e1e2e,stroke:#7c3aed,color:#c4b5fd
    style EXPORT fill:#1e1e2e,stroke:#22d3ee,color:#c4b5fd
```

---

## Step-by-Step Explanation

### ① Data Collection

Nine real-world sources, all with verified licenses permitting AI training:

| Source | Samples | License | What it provides |
|---|---|---|---|
| NVD (CVEs 1988-2026) | 50,000 | Public Domain | Vulnerability descriptions mapped to exploit types |
| OSSF Malicious Packages | 5,000 | Apache-2.0 | npm/pypi supply chain attacks, credential theft |
| SecLists Payloads | 3,229 | MIT | XSS, SQLi, command injection, XXE payloads in context |
| GitHub Advisories | 3,000 | CC-BY-4.0 | Security advisories with CWE-to-taxonomy mapping |
| Enron Emails | 2,000 | Public Domain | Real emails with PII, credentials, financial data |
| MTSamples | 2,000 | CC0 | Medical transcriptions with diagnoses and prescriptions |
| MITRE ATT&CK | 1,620 | Apache-2.0 | Attack techniques and malware profiles |
| deepset Prompt Injection | 263 | Apache-2.0 | Prompt injection attacks in realistic contexts |
| CRS Reports | 156 | Public Domain | Military, intelligence, nuclear content |

### ② Processing

Each source has a dedicated processor that:
- Extracts relevant text content
- Maps it to the **51-subcategory taxonomy** using source-specific heuristics (CWE mapping for CVEs, keyword detection for emails, etc.)
- Assigns severity levels and compliance flags
- Outputs standardized JSONL

**40 synthetic generators** fill gaps where real data is sparse or unavailable — producing realistic examples for categories like biometric PII, cloud credentials, weapons systems specs, and safe business documents.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {
  'primaryColor': '#7c3aed',
  'primaryTextColor': '#e5e7eb',
  'primaryBorderColor': '#c4b5fd',
  'lineColor': '#22d3ee',
  'secondaryColor': '#111118',
  'tertiaryColor': '#1e1e2e',
  'background': '#0a0a0f',
  'mainBkg': '#111118',
  'nodeBorder': '#7c3aed',
  'clusterBkg': '#1e1e2e',
  'edgeLabelBackground': '#111118'
}}}%%

pie title Dataset Composition (105,168 samples)
    "Malicious" : 69708
    "Safe" : 18500
    "Credentials" : 9141
    "PII" : 8094
    "Confidential" : 6035
    "Medical" : 3956
    "Financial" : 2161
```

### ③ Combine & Convert

All processed JSONL files are merged into a single `combined_train.jsonl`, then converted to **ChatML format** for instruction tuning:

```json
{
  "messages": [
    {
      "role": "system",
      "content": "You are TorchSight, a cybersecurity document classifier..."
    },
    {
      "role": "user",
      "content": "Analyze this document for security findings.\n\n<document text>"
    },
    {
      "role": "assistant",
      "content": "[{\"category\": \"malicious\", \"subcategory\": \"malicious.injection\", ...}]"
    }
  ]
}
```

The converter:
- Randomizes instruction phrasing (7 templates) to prevent overfitting to specific prompts
- Splits 95/5 train/validation
- Truncates text to 4096 tokens

### ④ Train (LoRA Fine-Tuning)

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {
  'primaryColor': '#7c3aed',
  'primaryTextColor': '#e5e7eb',
  'primaryBorderColor': '#c4b5fd',
  'lineColor': '#22d3ee',
  'secondaryColor': '#111118',
  'tertiaryColor': '#1e1e2e',
  'background': '#0a0a0f',
  'mainBkg': '#111118',
  'nodeBorder': '#7c3aed',
  'clusterBkg': '#1e1e2e',
  'edgeLabelBackground': '#111118'
}}}%%

graph LR
    subgraph FROZEN ["Base Model (Frozen)"]
        direction TB
        EMB["Embeddings"]
        L1["Layer 1"]
        L2["Layer 2"]
        LN["Layer N"]
        EMB --> L1 --> L2 --> LN
    end

    subgraph LORA ["LoRA Adapters (Trained)"]
        direction TB
        A1["q,k,v,o_proj<br/>gate,up,down_proj<br/>lm_head"]
        A2["Rank 64<br/>Alpha 128"]
        A3["~3.5% params"]
        A1 --- A2 --- A3
    end

    INPUT["Training Data<br/>99,910 samples"] --> FROZEN
    LORA -.->|inject| FROZEN
    FROZEN --> LOSS["Loss Function<br/>Cross-Entropy"]
    LOSS -->|backprop| LORA

    style FROZEN fill:#1e1e2e,stroke:#6b7280,color:#c4b5fd
    style LORA fill:#1e1e2e,stroke:#7c3aed,color:#c4b5fd
    style EMB fill:#1e1e2e,stroke:#6b7280,color:#9ca3af
    style L1 fill:#1e1e2e,stroke:#6b7280,color:#9ca3af
    style L2 fill:#1e1e2e,stroke:#6b7280,color:#9ca3af
    style LN fill:#1e1e2e,stroke:#6b7280,color:#9ca3af
    style A1 fill:#7c3aed,stroke:#c4b5fd,color:#fff
    style A2 fill:#7c3aed,stroke:#c4b5fd,color:#fff
    style A3 fill:#7c3aed,stroke:#c4b5fd,color:#fff
    style INPUT fill:#22d3ee,stroke:#22d3ee,color:#0a0a0f
    style LOSS fill:#ef4444,stroke:#ef4444,color:#fff
```

**LoRA** (Low-Rank Adaptation) injects small trainable matrices into each attention layer of the frozen base model. Only these adapters are trained — the base model weights never change.

| Parameter | Value | Why |
|---|---|---|
| Rank (r) | 64 | High rank = more expressive adaptation |
| Alpha (α) | 128 | Scaling factor (2×r rule for stability) |
| Target layers | All attention + lm_head | Maximum adaptation including output head |
| Trainable params | ~3.5% of model | Small adapter, full model knowledge retained |
| Batch size | 16 × 2 grad accum = 32 effective | Large batches for smooth gradients |
| Epochs | 3 | Full convergence on 100K samples |
| Learning rate | 1e-4 with cosine decay | Conservative for full-precision training |
| Precision | bf16 (no quantization) | Maximum quality — no information loss |
| Optimizer | AdamW fused | Kernel-fused for H100/GH200 |
| Checkpoint | Best model by eval loss | Prevents overfitting, saves optimal weights |

### ⑤ Export

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {
  'primaryColor': '#7c3aed',
  'primaryTextColor': '#e5e7eb',
  'primaryBorderColor': '#c4b5fd',
  'lineColor': '#22d3ee',
  'secondaryColor': '#111118',
  'tertiaryColor': '#1e1e2e',
  'background': '#0a0a0f',
  'mainBkg': '#111118',
  'nodeBorder': '#7c3aed',
  'clusterBkg': '#1e1e2e',
  'edgeLabelBackground': '#111118'
}}}%%

graph LR
    A["LoRA Adapter<br/>~100MB"] --> B["Merge with<br/>Base Model"]
    C["Llama 3.1 8B<br/>~16GB fp16"] --> B
    B --> D["Merged Model<br/>~16GB"]
    D --> E["llama.cpp<br/>Quantize"]
    E --> F["GGUF q4_k_m<br/>~5GB"]
    F --> G["Ollama<br/>Modelfile"]
    G --> H["torchsight/sentinel<br/>Ready to run"]

    style A fill:#7c3aed,stroke:#c4b5fd,color:#fff
    style C fill:#1e1e2e,stroke:#6b7280,color:#9ca3af
    style B fill:#1e1e2e,stroke:#22d3ee,color:#e5e7eb
    style D fill:#1e1e2e,stroke:#7c3aed,color:#e5e7eb
    style E fill:#1e1e2e,stroke:#22d3ee,color:#e5e7eb
    style F fill:#22d3ee,stroke:#22d3ee,color:#0a0a0f
    style G fill:#22d3ee,stroke:#22d3ee,color:#0a0a0f
    style H fill:#7c3aed,stroke:#c4b5fd,color:#fff
```

Three-step export process:

1. **Merge** — LoRA adapter weights are mathematically merged back into the base model, producing a single standalone model
2. **Quantize** — `q4_k_m` reduces model size from ~16GB to ~2GB using 4-bit quantization with k-quant importance-based precision allocation
3. **Modelfile** — Creates an Ollama Modelfile with the system prompt and inference parameters baked in

The final GGUF file runs on any machine with Ollama — CPU-only works fine, GPU just makes it faster.

---

## Taxonomy

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {
  'primaryColor': '#7c3aed',
  'primaryTextColor': '#e5e7eb',
  'primaryBorderColor': '#c4b5fd',
  'lineColor': '#22d3ee',
  'secondaryColor': '#111118',
  'tertiaryColor': '#1e1e2e',
  'background': '#0a0a0f',
  'mainBkg': '#111118',
  'nodeBorder': '#7c3aed',
  'clusterBkg': '#1e1e2e',
  'edgeLabelBackground': '#111118'
}}}%%

mindmap
  root((Sentinel<br/>51 subcategories))
    🔴 Malicious (14)
      exploit
      injection
      malware
      phishing
      prompt_injection
      supply_chain
      shell
      xxe
      ssti
      ssrf
      deserialization
      redos
      steganography
      prototype_pollution
    🟣 Confidential (9)
      internal
      classified
      military
      military_comms
      intelligence
      weapons_systems
      nuclear
      geospatial
      education
    🔵 PII (6)
      identity
      contact
      government_id
      biometric
      metadata
      behavioral
    🟠 Credentials (8)
      password
      api_key
      token
      private_key
      connection_string
      cloud_config
      cicd
      container
    🟢 Medical (4)
      diagnosis
      prescription
      lab_result
      insurance
    🟡 Financial (4)
      transaction
      credit_card
      bank_account
      tax
    ⚪ Safe (6)
      code
      documentation
      config
      media
      email
      business
```

---

## Usage

```bash
# Install
ollama pull torchsight/sentinel

# Run
ollama run torchsight/sentinel "Analyze this document for security findings."

# Via TorchSight CLI
torchsight scan ./documents/ --model torchsight/sentinel
```

## Output Format

```json
[
  {
    "category": "credentials",
    "subcategory": "credentials.api_key",
    "severity": "critical",
    "explanation": "AWS access key ID found in configuration file"
  },
  {
    "category": "pii",
    "subcategory": "pii.identity",
    "severity": "high",
    "explanation": "Full name and date of birth present in document header"
  }
]
```
