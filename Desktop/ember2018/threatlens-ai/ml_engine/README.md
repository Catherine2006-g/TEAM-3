# ML Engine

## Overview

The ML Engine provides the malware detection pipeline for ThreatLens AI.

## Training Pipeline

Training scripts are available in the training/ directory and include dataset preparation, validation, model training, evaluation, and feature-importance analysis.

## Inference Pipeline

The scanner loads the trained model, extracts EMBER features, runs YARA rule matching, and returns a structured JSON response through MalwareScanner.scan().

## Directory Structure

- engine/ - scanner, predictor, extractor, and YARA integration
- model/ - trained model and metadata
- training/ - dataset preparation and training scripts
- tests/ - verification scripts
- yara_rules/ - curated YARA rules and rule index

## Dependencies

Install dependencies with:

```bash
pip install -r requirements.txt
```

## Model Information

- Engine: ThreatLens Malware Detection Engine
- Version: 1.0.0
- Algorithm: LightGBM
- Dataset: EMBER 2018
- Features: 2381

## Evaluation Metrics

- Accuracy: 95.11%
- Precision: 95.23%
- Recall: 94.98%
- F1: 95.10%
- ROC AUC: 98.99%

## YARA Integration

YARA rules are discovered automatically from the yara_rules/yara directory.

## How to Run

```bash
python -c "from ml_engine.engine import MalwareScanner; print(MalwareScanner().scan('sample.exe'))"
```
