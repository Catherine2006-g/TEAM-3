import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from ml_engine.engine.scanner import MalwareScanner

sample_file = Path(__file__).parent / "sample_test.exe"
if not sample_file.exists():
    sample_file.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")

scanner = MalwareScanner()
result = scanner.scan(str(sample_file))

print("Scan result:")
print(result)

