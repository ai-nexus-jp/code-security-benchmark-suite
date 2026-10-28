import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from runner.scanners.base import BaseScanner, ScanResult, Finding


class SemgrepScanner(BaseScanner):
    def __init__(self):
        super().__init__("semgrep")

    def scan(self, target_dir: str = "bench_app", timeout: int = 30) -> ScanResult:
        start_time = time.time()
        output_file = Path("materials/raw_output_semgrep.json")
        output_file.parent.mkdir(parents=True, exist_ok=True)

        semgrep_bin = Path(sys.executable).parent / "semgrep"
        cmd_bin = str(semgrep_bin) if semgrep_bin.exists() else "semgrep"

        cmd = [
            cmd_bin,
            "scan",
            "--config", "auto",
            "--config", "p/security-audit",
            "--config", "p/owasp-top-ten",
            "--json",
            "--output", str(output_file),
            target_dir
        ]

        env = os.environ.copy()
        env["HOME"] = "/tmp"

        try:
            res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout, check=False)
        except (subprocess.TimeoutExpired, Exception) as e:
            print(f"[SemgrepScanner] Subprocess warning/timeout ({e}), checking existing output...")

        elapsed = time.time() - start_time

        raw_data = {}
        findings = []

        if output_file.exists():
            try:
                with open(output_file, "r", encoding="utf-8") as f:
                    raw_data = json.load(f)

                results = raw_data.get("results", [])
                for item in results:
                    filename = item.get("path", "")
                    if "bench_app" in filename:
                        filename = filename[filename.index("bench_app"):]

                    start_pos = item.get("start", {})
                    line = start_pos.get("line", 0)
                    extra = item.get("extra", {})

                    findings.append(
                        Finding(
                            file=filename,
                            line=line,
                            vuln_type=item.get("check_id", "Unknown"),
                            severity=extra.get("severity", "MEDIUM"),
                            confidence=extra.get("metadata", {}).get("confidence", "MEDIUM"),
                            description=extra.get("message", "")
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
    scanner = SemgrepScanner()
    result = scanner.scan("bench_app", timeout=5)
    scanner.save_output(result, "materials/scan_semgrep.json")
    print(f"[Semgrep] Scan complete. Found {len(result.findings)} issues in {result.execution_time_seconds}s")

