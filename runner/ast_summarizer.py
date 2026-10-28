import ast
from pathlib import Path
from typing import Dict, Any, List


class ASTSummarizer:
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
        
        # Collect external calls and interesting calls
        calls = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                if hasattr(ast, "unparse"):
                    try:
                        calls.append(ast.unparse(sub.func))
                    except Exception:
                        pass

        # Extract docstring or key comment summary if present
        doc = ast.get_docstring(node) or ""
        doc_summary = doc.splitlines()[0] if doc else ""

        return {
            "name": node.name,
            "line": node.lineno,
            "args": args,
            "decorators": decorators,
            "calls": list(set(calls)),
            "doc_summary": doc_summary
        }

    def generate_compact_tree(self) -> str:
        summary_blocks = []
        for p in sorted(self.target_dir.rglob("*.py")):
            if "__pycache__" in str(p):
                continue
            f_summary = self.summarize_file(p)
            lines = [f"FILE: {f_summary['file']}"]
            if f_summary["imports"]:
                lines.append(f"  Imports: {', '.join(f_summary['imports'])}")
            for fn in f_summary["functions"]:
                dec = f" [Decorators: {', '.join(fn['decorators'])}]" if fn['decorators'] else ""
                calls = f" -> Calls: {', '.join(fn['calls'][:8])}" if fn['calls'] else ""
                doc = f" ({fn['doc_summary']})" if fn['doc_summary'] else ""
                lines.append(f"  Line {fn['line']:3d}: def {fn['name']}({', '.join(fn['args'])}){dec}{calls}{doc}")
            summary_blocks.append("\n".join(lines))
        return "\n\n".join(summary_blocks)
