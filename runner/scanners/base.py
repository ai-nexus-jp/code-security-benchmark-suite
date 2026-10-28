import json
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, List
from pydantic import BaseModel, Field


class Finding(BaseModel):
    file: str
    line: int
    vuln_type: str
    severity: str = "MEDIUM"
    confidence: str = "MEDIUM"
    description: str = ""


class ScanResult(BaseModel):
    scanner_name: str
    execution_time_seconds: float
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float = 0.0
    findings: List[Finding] = Field(default_factory=list)
    raw_output: Any = None


class BaseScanner(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def scan(self, target_dir: str = "bench_app") -> ScanResult:
        """Execute scan and return normalized ScanResult."""
        pass

    def save_output(self, result: ScanResult, output_path: str) -> None:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(result.model_dump_json(indent=2))
