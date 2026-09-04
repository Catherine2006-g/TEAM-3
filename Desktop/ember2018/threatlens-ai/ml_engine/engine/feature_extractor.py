import sys
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

import numpy as np
import lief

# Patch missing numpy attributes removed in NumPy 1.24+ for compatibility with ember
if not hasattr(np, 'int'):
    setattr(np, 'int', int)
if not hasattr(np, 'float'):
    setattr(np, 'float', float)
if not hasattr(np, 'bool'):
    setattr(np, 'bool', bool)

# Patch missing lief error attributes for lief 1.0+ compatibility with EMBER
for attr in ['bad_format', 'bad_file', 'pe_error', 'parser_error', 'read_out_of_bound']:
    if not hasattr(lief, attr):
        setattr(lief, attr, Exception)

from ember.features import PEFeatureExtractor


# Initialize the official EMBER feature extractor
extractor = PEFeatureExtractor(feature_version=2)



def extract_features(file_path):
    """
    Extract the official EMBER feature vector (2381 features)
    from a Windows executable.
    """

    # Read the executable as raw bytes
    with open(file_path, "rb") as f:
        bytez = f.read()

    # Extract raw feature dictionary
    raw_features = extractor.raw_features(bytez)

    # Convert to 2381-dimensional feature vector
    feature_vector = extractor.process_raw_features(raw_features)

    return feature_vector
