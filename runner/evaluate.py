import csv
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def load_ground_truth(path: str = "runner/ground_truth.json") -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_scan_result(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {
            "scanner_name": Path(path).stem.replace("scan_", ""),
            "execution_time_seconds": 0.0,
            "input_tokens": 0,
            "output_tokens": 0,
            "estimated_cost_usd": 0.0,
            "findings": []
        }
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate_scanner(gt_items: List[Dict[str, Any]], scan_data: Dict[str, Any]) -> Dict[str, Any]:
    findings = scan_data.get("findings", [])
    
    tp_count = 0
    fn_count = 0
    fp_count = 0
    tn_count = 0
    
    case_results = {}

    for gt in gt_items:
        cid = gt["id"]
        is_vuln = gt["is_vulnerable"]
        t_file = gt["target_file"]
        t_line = gt["target_line"]

        # Check if any finding matches target_file and target_line within +- 8 lines (accounting for function def vs sink offset)
        matched = False
        for f in findings:
            f_file = f.get("file", "")
            f_line = int(f.get("line", 0))

            # Normalize paths
            if Path(t_file).name == Path(f_file).name or t_file in f_file or f_file in t_file:
                if abs(f_line - t_line) <= 8:
                    matched = True
                    break

        if is_vuln:
            if matched:
                case_results[cid] = "TP"
                tp_count += 1
            else:
                case_results[cid] = "FN"
                fn_count += 1
        else:
            if matched:
                case_results[cid] = "FP"
                fp_count += 1
            else:
                case_results[cid] = "TN"
                tn_count += 1

    total_vuln = tp_count + fn_count  # 15
    total_safe = fp_count + tn_count  # 15

    recall = (tp_count / total_vuln) * 100 if total_vuln > 0 else 0.0
    fallout = (fp_count / total_safe) * 100 if total_safe > 0 else 0.0
    precision = (tp_count / (tp_count + fp_count)) * 100 if (tp_count + fp_count) > 0 else 0.0
    
    f1 = 0.0
    if (precision + recall) > 0:
        f1 = 2 * ((precision / 100) * (recall / 100)) / ((precision / 100) + (recall / 100))

    return {
        "name": scan_data.get("scanner_name", "unknown"),
        "tp": tp_count,
        "fn": fn_count,
        "fp": fp_count,
        "tn": tn_count,
        "recall": round(recall, 1),
        "fallout": round(fallout, 1),
        "precision": round(precision, 1),
        "f1": round(f1, 3),
        "execution_time_seconds": scan_data.get("execution_time_seconds", 0.0),
        "input_tokens": scan_data.get("input_tokens", 0),
        "output_tokens": scan_data.get("output_tokens", 0),
        "estimated_cost_usd": scan_data.get("estimated_cost_usd", 0.0),
        "case_results": case_results
    }


def generate_reports():
    gt = load_ground_truth()
    scanners = ["bandit", "semgrep", "raw_llm", "mantis"]
    
    evaluations = {}
    for sc in scanners:
        data = load_scan_result(f"materials/scan_{sc}.json")
        evaluations[sc] = evaluate_scanner(gt, data)

    # 1. Output benchmark_results.csv
    csv_path = Path("materials/benchmark_results.csv")
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "case_id", "category", "ground_truth",
            "bandit_result", "semgrep_result", "raw_llm_result", "mantis_result", "notes"
        ])
        for item in gt:
            cid = item["id"]
            cat = item["category"]
            g_label = "VULN" if item["is_vulnerable"] else "SAFE"
            b_res = evaluations["bandit"]["case_results"].get(cid, "N/A")
            s_res = evaluations["semgrep"]["case_results"].get(cid, "N/A")
            r_res = evaluations["raw_llm"]["case_results"].get(cid, "N/A")
            m_res = evaluations["mantis"]["case_results"].get(cid, "N/A")
            desc = item["description"]
            writer.writerow([cid, cat, g_label, b_res, s_res, r_res, m_res, desc])

    # 2. Output benchmark_summary.md
    summary_path = Path("materials/benchmark_summary.md")
    md_lines = [
        "# 静的解析・LLM脆弱性スキャン比較ベンチマーク集計レポート",
        "",
        "## 1. 比較マトリクス概要",
        "",
        "| 手法 | TP (見抜いた数/15) | FP (誤報数/15) | Recall (検知率) | Precision (適合率) | F1-Score | 実行時間 (秒) | 消費トークン (In/Out) | 推定コスト ($) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    ]

    method_labels = {
        "bandit": "① Bandit (第1世代 ASTマッチ)",
        "semgrep": "② Semgrep (第2世代 Taint解析)",
        "raw_llm": "③ 素のLLM丸投げ (第3世代 全文投入)",
        "mantis": "④ Mantis式 (第4世代 AST要約+PoC検証)"
    }

    for sc in scanners:
        ev = evaluations[sc]
        label = method_labels.get(sc, sc)
        tokens_str = f"{ev['input_tokens']} / {ev['output_tokens']}" if ev['input_tokens'] > 0 else "0"
        cost_str = f"${ev['estimated_cost_usd']:.4f}"
        md_lines.append(
            f"| {label} | {ev['tp']}/15 | {ev['fp']}/15 | {ev['recall']}% | {ev['precision']}% | {ev['f1']} | {ev['execution_time_seconds']}s | {tokens_str} | {cost_str} |"
        )

    md_lines.extend([
        "",
        "## 2. メトリクス定義",
        "- **Recall (再現率 / 真陽性率)**: `TP / (TP + FN)` (脆弱性15問中、検知できた割合)",
        "- **Fall-out (偽陽性率)**: `FP / (FP + TN)` (安全な引っ掛け15問中、誤って警告した割合)",
        "- **Precision (適合率)**: `TP / (TP + FP)` (警告したもののうち、本当に脆弱だった割合)",
        "- **F1-Score**: PrecisionとRecallの調和平均",
        "",
        "> ※ 手法④ Mantis式は、Google Mantis公式仕様（`skills/mantis-summarize` によるAST要約 ＋ `skills/mantis-reproduce` による動的PoC検証）に準拠したパイプライン実装による実測値です。",
        "",
        "詳細な設問別判定結果は `materials/benchmark_results.csv` を参照してください。"
    ])

    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    print("\n" + "="*85)
    print("           静的解析・LLM脆弱性スキャン比較ベンチマーク集計結果 (30問)")
    print("="*85)
    print(f"{'手法':<32} | {'TP':^5} | {'FP':^5} | {'Recall':^8} | {'Precision':^9} | {'F1':^5} | {'時間':^6} | {'コスト':^7}")
    print("-" * 85)
    for sc in scanners:
        ev = evaluations[sc]
        label = method_labels.get(sc, sc)
        cost_str = f"${ev['estimated_cost_usd']:.4f}"
        print(f"{label:<32} | {ev['tp']:^5} | {ev['fp']:^5} | {ev['recall']:>6.1f}% | {ev['precision']:>7.1f}% | {ev['f1']:^5.3f} | {ev['execution_time_seconds']:>5.2f}s | {cost_str:>7}")
    print("="*85)
    print(f"[*] レポートMarkdown: {summary_path}")
    print(f"[*] 設問別詳細CSV:   {csv_path}\n")


if __name__ == "__main__":
    generate_reports()

