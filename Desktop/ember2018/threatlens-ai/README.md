# ThreatLens AI

ThreatLens AI is an AI-powered malware detection platform that combines EMBER feature extraction, a LightGBM classifier, and YARA-based rule matching into a single structured scanning engine.

## Architecture

Frontend
↓
Backend
↓
ML Engine
↓
EMBER Feature Extraction
↓
LightGBM
↓
YARA
↓
JSON Response

## Repository Structure

- backend/ - placeholder for the future FastAPI backend
- frontend/ - placeholder for the future React/Next.js frontend
- ml_engine/ - completed machine learning engine

## Features

- EMBER 2018 feature extraction
- LightGBM-based malware classification
- YARA rule scanning with automatic rule discovery
- Structured JSON response for backend integration

## Technology Stack

- Python
- LightGBM
- scikit-learn
- NumPy
- joblib
- YARA
- LIEF

## How to Run

1. Install dependencies:
   ```bash
   pip install -r ml_engine/requirements.txt
   ```
2. Run the scanner:
   ```bash
   python -c "from ml_engine.engine import MalwareScanner; print(MalwareScanner().scan('sample.exe'))"
   ```

## Future Work

- Backend API integration
- Frontend dashboard
- Broader YARA rule sets
- Model retraining and deployment

## Contributors

- ML Engineering Team
- Backend Team
- Frontend Team
