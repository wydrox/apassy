#!/usr/bin/env python3
"""Download the Laya base weights into the Hugging Face cache (goal B8).

The same repository and pinned revision as the server (`common.BASE_REPO`,
`common.BASE_REVISION`), into the default cache of the user (`HF_HUB_CACHE`,
`HF_HOME`, or ~/.cache/huggingface/hub). Weights that are already there are not
downloaded again. "Install the model" in Apassy runs this script as its last step,
so the first start of the server does not wait for the download.

Run inside the Laya virtual environment:
  .venv/bin/python -B tools/basemodel/fetch_weights.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# Progress bars fill the install log with partial lines.
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")

# No __pycache__ next to this script: in Apassy.app it breaks the code signature.
_WRITE_BYTECODE = sys.dont_write_bytecode
sys.dont_write_bytecode = True
import common  # noqa: E402

sys.dont_write_bytecode = _WRITE_BYTECODE


def main():
    print("fetch: %s at %s" % (common.BASE_REPO, common.BASE_REVISION), flush=True)
    folder = common.base_dir()
    weights = os.path.join(folder, "model.safetensors")
    if not os.path.isfile(weights):
        print("fetch: %s is missing after the download" % weights, file=sys.stderr)
        return 1
    print("fetch: the base weights are in %s" % folder, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
