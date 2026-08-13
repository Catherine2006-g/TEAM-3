import yara
from pathlib import Path

import sys

sys.path.append(str(Path(__file__).resolve().parent.parent))

from yara_rules.rules_index import RULE_FILES


class YaraScanner:
    def __init__(self):
        filepaths = {}

        for i, rule in enumerate(RULE_FILES):
            filepaths[f"rule{i}"] = rule

        self.rules = yara.compile(filepaths=filepaths) if filepaths else None

    def scan(self, file_path):
        if self.rules is None:
            return {
                "matched": False,
                "matched_rules": [],
                "rule_count": 0,
                "rules_loaded": 0,
            }

        matches = self.rules.match(file_path)

        return {
            "matched": len(matches) > 0,
            "matched_rules": [m.rule for m in matches],
            "rule_count": len(matches),
            "rules_loaded": len(RULE_FILES),
        }


def scan_with_yara(file_path):
    scanner = YaraScanner()
    return scanner.scan(file_path)
