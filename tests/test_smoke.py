from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.analyse import analyse

def test_finds_issues():
    issues = {f["issue"] for f in analyse(ROOT / "data" / "sample_directory.csv")["findings"]}
    assert "disabled_but_still_privileged" in issues
    assert "standing_priv_on_daily_upn" in issues

if __name__ == "__main__":
    test_finds_issues(); print("smoke_ok")
