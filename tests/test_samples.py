import hashlib
import os
import tempfile

import pefile
import pytest

import sfextract.setupfactory7
import sfextract.setupfactory8


@pytest.mark.parametrize("result", os.listdir(os.path.join(os.path.dirname(__file__), "results")))
def test_samples(result):
    sample = os.path.join(os.path.dirname(__file__), "samples", result)
    with open(os.path.join(os.path.dirname(__file__), "results", result), "r") as f:
        expected = sorted([x for x in f.read().split("\n") if x])  # should already be sorted, but just in case

    pe = pefile.PE(sample, fast_load=True)
    extractor = sfextract.setupfactory7.get_extractor(pe)
    if not extractor:
        extractor = sfextract.setupfactory8.get_extractor(pe)

    output = []
    with tempfile.TemporaryDirectory() as tmpdir:
        extractor.extract_files(tmpdir)
        for dirpath, _, fnames in os.walk(tmpdir):
            for fname in fnames:
                fhash = hashlib.sha256(open(os.path.join(dirpath, fname), "rb").read()).hexdigest()
                output.append(f"{dirpath[len(tmpdir):]}/{fname}:{fhash}")

    assert sorted(output) == expected
