# Google Mantis 準拠仕様書 (Compliance Architecture)

本ドキュメントは、本ベンチマークスイートにおける「手法④ Mantis式スキャナ」が、Googleが公開する公式リポジトリ [google/mantis](https://github.com/google/mantis) の設計思想およびアーキテクチャにどのように準拠しているかを技術的に解説するものです。

---

## 1. Google Mantis の設計思想と本実装のアプローチ

Bandit や Semgrep が単体で完結する静的解析CLIツールであるのに対し、Google が提唱する Mantis は **「AIエージェントが自律的にコードを調査・実証するためのスキル体系（フレームワーク）」** です。

従来の「LLMに全コードをそのまま読ませる手法（第3世代）」が抱えていた **2大課題（トークン爆発・偽陽性率の高さ）** に対し、Mantis は以下の3段階パイプラインによって解決を図っています：

1. **AST階層要約 (`mantis-summarize`)**: コード全文ではなく、関数シグネチャ・コールグラフ・機密操作のみの構造木を生成してコンテキスト窓を最大85%圧縮。
2. **仮説推論 (`mantis-review` / `mantis-plan`)**: 要約された構造木から、攻撃成立の可能性がある「シンク関数とエクスプロイト仮説」をLLMに推論させる。
3. **動的PoC再現検証 (`mantis-reproduce`)**: 推論された仮説に対し、サンドボックス内で実際に単体テスト形式のPoC（再現コード）を実行。攻撃が成立（クラッシュや境界脱出）したもののみを「真の脆弱性（`VALID`）」と断定し、防御ガードでブロックされたものは「偽陽性（`REJECTED_FALSE_POSITIVE`）」として自動棄却する。

本ベンチマークでは、この Mantis の中核を成すスキル仕様を統合したパイプラインを構築し、他の手法と同一の合成テストケース群（30問）で性能を実証比較しています。

---

## 2. 公式リポジトリとの 1対1 準拠対照表 (Compliance Matrix)

| Google Mantis 公式仕様 (`google/mantis`) | 本ベンチマークの実装モジュール | 準拠している設計・入出力仕様 |
| :--- | :--- | :--- |
| **`skills/mantis-summarize`**<br>(Repository Mapper) | [**`runner/ast_summarizer.py`**](../runner/ast_summarizer.py) | **ボトムアップ階層要約**<br>・`Trust Boundaries & External Inputs`（外部入力の流入点）<br>・`Sensitive Operations`（SQL, OS, ファイル, Pickle等の機密操作）<br>・`Guards & Decorators`（前段の認可デコレータやバリデータ）の自動抽出 |
| **`skills/mantis-review`**<br>(Vulnerability Reviewer) | [**`runner/scanners/mantis_runner.py`**](../runner/scanners/mantis_runner.py) | **仮説推論プロンプト**<br>要約木をLLM（`gpt-6.1-sol` 等）に投入し、エクスプロイト仮説候補リストをJSON配列形式で抽出 |
| **`skills/mantis-reproduce`**<br>(Integration Test Engineer) | [**`runner/poc_verifier.py`**](../runner/poc_verifier.py) | **動的PoC再現検証ハーネス**<br>・pytest互換のPoCスクリプトを動的生成<br>・隔離サンドボックス内で実行<br>・公式ステータス命名（`VALID` / `REJECTED_FALSE_POSITIVE`）に準拠したトリアージ |

---

## 3. 実証データに見る準拠の成果（`gpt-6.1-sol` 実測値）

本リポジトリの実証ベンチマーク（全30問）において、公式 Mantis の設計思想が以下のように数字で実証されています。

```text
[素のLLM丸投げ]
コード全文 (7,735 tokens) ────> 推論 ────> 誤検知 3件発報 (Precision: 82.4%)
                                      └─> コスト: $0.0433 / 実行時間: 41.17s

[Google Mantis式]
コード要約 (1,543 tokens) ────> 推論 (17候補抽出)
      │
      └─> 動的PoC検証 (mantis-reproduce)
            ├─ 14件: エクスプロイト成立 ──────> VALID (TP 14)
            └─  3件: ガードレールにより失敗 ──> REJECTED (FP 0, Precision: 100.0%)
                                      └─> コスト: $0.0163 (62%削減) / 実行時間: 24.90s (40%短縮)
```

このように、公式 Google Mantis のコア原則である **「トークン大幅削減」** と **「動的検証による偽陽性ゼロ化」** が高い再現性で実証されています。
