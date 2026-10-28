import ast
import os
from pathlib import Path
from typing import Dict, Any, List


class ASTSummarizer:
    """
    Implements the core hierarchical security summary approach from Google Mantis (mantis-summarize).
    Extracts security-focused structural metadata:
    - API Endpoints & Exports
    - Trust Boundaries & External Inputs
    - Sensitive Operations (SQL, Filesystem, Process Execution, Deserialization)
    - Upstream/Downstream Guardrails & Decorators
    """
    def __init__(self, target_dir: str = "bench_app"):
        self.target_dir = Path(target_dir)

    def summarize_file(self, file_path: Path) -> Dict[str, Any]:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(file_path))

        imports = []
        functions = []
        classes = []

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}")
            elif isinstance(node, ast.FunctionDef):
                functions.append(self._summarize_function(node))
            elif isinstance(node, ast.ClassDef):
                classes.append(node.name)

        return {
            "file": str(file_path.relative_to(self.target_dir.parent)),
            "imports": imports,
            "classes": classes,
            "functions": functions
        }

    def _summarize_function(self, node: ast.FunctionDef) -> Dict[str, Any]:
        args = [arg.arg for arg in node.args.args]
        decorators = [ast.unparse(d) if hasattr(ast, "unparse") else type(d).__name__ for d in node.decorator_list]
        
        calls = []
        sensitive_ops = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                if hasattr(ast, "unparse"):
                    try:
                        c_name = ast.unparse(sub.func)
                        calls.append(c_name)
                        # Tag sensitive security operations (Mantis pattern)
                        if any(k in c_name.lower() for k in ["execute", "urlopen", "popen", "system", "loads", "pickle", "join", "unquote", "render"]):
                            sensitive_ops.append(c_name)
                    except Exception:
                        pass

        doc = ast.get_docstring(node) or ""
        doc_summary = doc.splitlines()[0] if doc else ""

        return {
            "name": node.name,
            "line": node.lineno,
            "args": args,
            "decorators": decorators,
            "calls": list(set(calls)),
            "sensitive_ops": list(set(sensitive_ops)),
            "doc_summary": doc_summary
        }

    def generate_compact_tree(self) -> str:
        """
        Bottom-up security summary rollup following Google Mantis mantis-summarize.
        Rolls up components into hierarchical directory and file summaries.
        """
        summary_blocks = [
            "# Google Mantis Hierarchical Security Index",
            "Trust Boundaries & Sensitive Operations Rollup:"
        ]

        for p in sorted(self.target_dir.rglob("*.py")):
            if "__pycache__" in str(p):
                continue
            f_summary = self.summarize_file(p)
            lines = [f"\n[FILE: {f_summary['file']}]"]
            if f_summary["imports"]:
                lines.append(f"  External Dependencies: {', '.join(f_summary['imports'])}")
            for fn in f_summary["functions"]:
                dec = f" [Guards/Decorators: {', '.join(fn['decorators'])}]" if fn['decorators'] else ""
                sens = f" [Sensitive Ops: {', '.join(fn['sensitive_ops'])}]" if fn['sensitive_ops'] else ""
                lines.append(f"  Line {fn['line']:3d}: def {fn['name']}({', '.join(fn['args'])}){dec}{sens}")
            summary_blocks.append("\n".join(lines))
        return "\n".join(summary_blocks)
