import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from runner.scanners.base import BaseScanner, ScanResult, Finding


class BanditScanner(BaseScanner):
    def __init__(self):
        super().__init__("bandit")

    def scan(self, target_dir: str = "bench_app") -> ScanResult:
        start_time = time.time()
        output_file = Path("materials/raw_output_bandit.json")
        output_file.parent.mkdir(parents=True, exist_ok=True)

        bandit_bin = Path(sys.executable).parent / "bandit"
        cmd_bin = str(bandit_bin) if bandit_bin.exists() else "bandit"

        cmd = [
            cmd_bin,
            "-r", target_dir,
            "-f", "json",
            "-o", str(output_file),
            "-ll", "-ii"
        ]

        # Bandit returns 1 if issues are found, which is expected
        subprocess.run(cmd, capture_output=True, text=True, check=False)
        elapsed = time.time() - start_time

        raw_data = {}
        findings = []

        if output_file.exists():
            try:
                with open(output_file, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)
                
                results = raw_data.get("results", [])
                for item in results:
                    filename = item.get("filename", "")
                    # Normalize to relative path
                    if "bench_app" in filename:
                        filename = filename[filename.index("bench_app"):]

                    findings.append(
                        Finding(
                            file=filename,
                            line=item.get("line_number", 0),
                            vuln_type=item.get("test_name", item.get("issue_text", "Unknown")),
                            severity=item.get("issue_severity", "MEDIUM"),
                            confidence=item.get("issue_confidence", "MEDIUM"),
                            description=item.get("issue_text", "")
                        )
                    )
            except Exception as e:
                raw_data = {"error": str(e)}

        return ScanResult(
            scanner_name=self.name,
            execution_time_seconds=round(elapsed, 3),
            input_tokens=0,
            output_tokens=0,
            estimated_cost_usd=0.0,
            findings=findings,
            raw_output=raw_data
        )


if __name__ == "__main__":
    scanner = BanditScanner()
    result = scanner.scan("bench_app")
    scanner.save_output(result, "materials/scan_bandit.json")
    print(f"[Bandit] Scan complete. Found {len(result.findings)} issues in {result.execution_time_seconds}s")
