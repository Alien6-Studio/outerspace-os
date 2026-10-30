import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("serving", Path(__file__).with_name("verify-serving.py"))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
root = Path(__file__).parent
expected = json.loads((root / "independent-verification.json").read_text())
for name, digest in expected["files_sha256"].items():
    assert v.digest(root / name) == digest, name
observations = json.loads((root / "observations.json").read_text())
assert v.verify_serving(observations["serving"]) == expected["cpu_serving"]
assert v.verify_startup_records(observations["serving"]["observations"]["startup_waits"], root) == expected["startup_waits"]
print("passed: OuterSpace serving and cold recovery; not a matched Ubuntu comparison")
