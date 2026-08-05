from pathlib import Path

RULE_DIR = Path("yara_rules/yara")

RULE_FILES = sorted(
    str(file)
    for file in RULE_DIR.glob("*.yar")
)

RULE_FILES.extend(
    sorted(
        str(file)
        for file in RULE_DIR.glob("*.yara")
    )
)
