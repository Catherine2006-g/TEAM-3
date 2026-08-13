# ML Engine API Documentation

## MalwareScanner

The MalwareScanner class is the main entrypoint for the ML engine.

### Method: scan(file_path)

Scans a file and returns a structured JSON-compatible dictionary.

#### Input

- file_path: path to a local executable file

#### Output JSON

```json
{
  "engine": {
    "name": "EMBER Malware Detection Engine",
    "version": "1.0.0",
    "model": "LightGBM",
    "yara_enabled": true
  },
  "file": {
    "name": "sample.exe",
    "sha256": "...",
    "size_bytes": 20200
  },
  "ml": {
    "prediction": "BENIGN",
    "malware_probability": 5.11,
    "benign_probability": 94.89,
    "risk_level": "LOW"
  },
  "yara": {
    "matched": false,
    "matched_rules": [],
    "rule_count": 0,
    "rules_loaded": 2
  },
  "scan_status": "SUCCESS"
}
```

#### Error Handling

- Missing files will return metadata with null values and still preserve the scan result structure.
- Import or runtime issues should be surfaced as exceptions during initialization.

#### Example Usage

```python
from ml_engine.engine import MalwareScanner

scanner = MalwareScanner()
result = scanner.scan("sample.exe")
print(result)
```
