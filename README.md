# Code Security Benchmark Suite (30-Case Benchmark)

静的解析ツール（Bandit, Semgrep）および LLM を用いた脆弱性検出パイプライン（素のLLM丸投げ vs Mantis式 AST要約＋PoC検証）の精度・コスト・速度を実証比較するためのオープンベンチマークデータ収集基盤です。

---

## 1. 比較マトリクス概要（実測サマリー）

疑似業務Webアプリケーション（`bench_app/`）に対し、巧妙に設計された全30問（真の脆弱性15問 ＋ 安全な引っ掛けコード15問）を実行した比較結果です。
最新の推論モデル **`gpt-6.1-sol`** による本番API実測値を記録しています。

| 手法 | TP (検知数/15) | FP (誤報数/15) | Recall (再現率) | Precision (適合率) | F1-Score | 実行時間 (秒) | 消費トークン (In/Out) | 推定コスト ($) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **① Bandit** (第1世代 ASTマッチ) | 5/15 | 4/15 | 33.3% | 55.6% | 0.417 | 0.26s | 0 | $0.0000 |
| **② Semgrep** (第2世代 Taint解析) | 9/15 | 6/15 | 60.0% | 60.0% | 0.600 | 5.01s | 0 | $0.0000 |
| **③ 素のLLM丸投げ** (`gpt-6.1-sol`) | **14/15** | **3/15** | **93.3%** | **82.4%** | **0.875** | 41.17s | 7,735 / 2,400 | $0.0433 |
| **④ Mantis式** (`gpt-6.1-sol` + PoC) | **14/15** | **0/15** | **93.3%** | **100.0%** | **0.966** | **24.90s** | **1,543 / 1,243** | **$0.0163** |

> ※ 詳細な設問別判定対照表（30問×4手法）は [`materials/benchmark_results.csv`](materials/benchmark_results.csv) を参照してください。

---

## 2. Google Mantis 公式仕様との準拠対照表 (Compliance Architecture)

Bandit や Semgrep のような単一の静的解析CLIに対し、Google Mantis（[google/mantis](https://github.com/google/mantis)）は **AIセキュリティエージェント向けの自律検証スキル体系（Skills & Harness）** です。

本スイートの手法④「Mantis式」は、公式リポジトリの2大コアスキル（`skills/mantis-summarize` / `skills/mantis-reproduce`）の仕様に準拠したパイプラインを統合し、実証比較を行っています。

| Google Mantis 公式スキル (`google/mantis`) | 本ベンチマークの実装モジュール | 準拠している設計・入出力仕様 |
| :--- | :--- | :--- |
| **Stage 1: `skills/mantis-summarize`**<br>(Repository Mapper) | [**`runner/ast_summarizer.py`**](runner/ast_summarizer.py) | **ボトムアップ階層要約**<br>・外部入力（Trust Boundaries）<br>・機密操作（Sensitive Operations: SQL, OS, Pickle等）<br>・認可ガード（Decorators）の自動抽出（トークン約80%削減） |
| **Stage 2: `skills/mantis-review`**<br>(Vulnerability Reviewer) | [**`runner/scanners/mantis_runner.py`**](runner/scanners/mantis_runner.py) | **仮説推論プロンプト**<br>要約木から危険なシンク関数のエクスプロイトシナリオ（Hypothesis）を抽出 |
| **Stage 3: `skills/mantis-reproduce`**<br>(Integration Test Engineer) | [**`runner/poc_verifier.py`**](runner/poc_verifier.py) | **動的PoC再現検証ハーネス**<br>・pytest互換のPoCスクリプトを動的生成・隔離実行<br>・公式ステータス命名（`VALID` / `REJECTED_FALSE_POSITIVE`）に準拠した全自動トリアージ |

> 詳しい準拠アーキテクチャとデータフロー解説は [**`docs/MANTIS_COMPLIANCE.md`**](docs/MANTIS_COMPLIANCE.md) をご覧ください。

---

## 3. ベンチマークテストケース（Ground Truth: 全30問）

### 2.1. 真の脆弱性 15問（True Positive 対象）
- `VULN-001`: `os.path.join('/app/data', user_input)` の第2引数絶対パス仕様罠によるパストラバーサル
- `VULN-002`: `urllib.parse.unquote` 二重呼び出しによる `%252f` すり抜け
- `VULN-003`: `zipfile.extractall()` の Zip Slip（相対パスチェックなし展開）
- `VULN-004`: `pathlib.Path.resolve()` なしの `startswith()` プレフィックス比較漏れ
- `VULN-005`: 動的 `ORDER BY` 句への f-string 生連結による SQLi
- `VULN-006`: 動的テーブル名切り替え時の f-string SQLi
- `VULN-007`: SQLAlchemy `text()` 句内での直接文字列フォーマット展開
- `VULN-008`: LIKE 検索のワイルドカード未エスケープ
- `VULN-009`: `urllib.request.urlopen` のスキーム未検証（`file://` や内部SSRF）
- `VULN-010`: プライベートIP（RFC 1918 / メタデータIP）検証欠落による SSRF
- `VULN-011`: `subprocess.Popen(..., shell=True)` の空白分割結合によるコマンド注入
- `VULN-012`: `os.system` に対するセミコロン・バッククォート任意コマンド実行
- `VULN-013`: パスパラメータ `user_id` に対するセッション所有者検証欠落（IDOR）
- `VULN-014`: 信頼できない入力に対する `pickle.loads()` 安全でないデシリアライズ
- `VULN-015`: Jinja2 `render_template_string()` に対する未サニタイズ入力（SSTI）

### 2.2. 安全な引っ掛けコード 15問（False Positive 誘発対象）
- `SAFE-001`: 別ファイル `validators.py` の Enum ホワイトリストで検証済みの動的 ORDER BY
- `SAFE-002`: 直前のレイヤーで明示的に `int()` キャスト済みの変数を f-string 展開
- `SAFE-003`: `Path.resolve().relative_to(BASE_DIR)` による厳密な境界脱出チェック
- `SAFE-004`: `os.path.basename()` でファイル名のみを強制抽出
- `SAFE-005`: `shlex.quote()` による引数エスケープ
- `SAFE-006`: `subprocess.run(args, shell=False)` による安全なリスト呼び出し
- `SAFE-007`: `gethostbyname` 名前解決 ＋ RFC 1918 プライベートIP拒否ガード
- `SAFE-008`: 許可ドメイン完全一致ホワイトリスト検証
- `SAFE-009`: テストコード内のダミートークン（シークレット誤検知誘発）
- `SAFE-010`: 暗号用途ではないUI遅延生成用 `random.randint`
- `SAFE-011`: `@require_ownership` デコレータによる前段認可検証済みIDOR見た目コード
- `SAFE-012`: `NamedTemporaryFile` の安全なデフォルト権限使用
- `SAFE-013`: 自社ホスト限定 netloc 検証済みリダイレクト
- `SAFE-014`: 固定長でバックトラッキング爆発のない正規表現（ReDoSの見た目）
- `SAFE-015`: 静的辞書マッピングによる定数SQL選択

---

## 4. クイックスタート

### 3.1. インストール
```bash
git clone <repository-url>
cd code-security-benchmark-suite

# 仮想環境作成とアクティベート
python3 -m venv .venv
source .venv/bin/activate

# 依存関係インストール
make setup
```

### 3.2. 環境変数設定（`.env`）
`.env.example` をコピーして `.env` を作成します。
```bash
cp .env.example .env
```

```ini
# デフォルト: OpenAI (gpt-4o)
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o

# Gemini を利用する場合の例
# LLM_PROVIDER=gemini
# GEMINI_API_KEY=AIzaSy...
# GEMINI_MODEL=gemini-1.5-flash
```
> ※ APIキーが未設定の場合でも、内蔵のシミュレーションデータおよびAST要約・PoC検証エンジンによりベンチマーク全体のフローを体験可能です。

### 3.3. ベンチマーク実行
```bash
# アプリケーションの単体テスト（文法・基本動作確認）
make test-app

# 全4手法のスキャン・パース・評価レポート一括生成
make run-benchmark
```

生成された成果物は `materials/` ディレクトリに出力されます：
- `materials/benchmark_summary.md`: 比較マトリクス表
- `materials/benchmark_results.csv`: 設問別4手法対照表（30問）
- `materials/analysis_notes.md`: 各ツールの考察・分析メモ

---

## 5. ディレクトリ構成

```text
.
├── bench_app/                      # スキャン対象となる疑似業務Webアプリ
│   ├── app.py                      # ルーティング・コントローラ (VULN-015, SAFE-013)
│   ├── config.py                   # 設定情報
│   ├── utils/
│   │   ├── validators.py           # 入力検証・サニタイズ (SAFE-001, SAFE-014)
│   │   └── file_handler.py         # パストラバーサル・ファイル操作モジュール
│   ├── database/
│   │   ├── connection.py           # SQLite DB接続定義
│   │   └── queries.py              # SQL実行モジュール (SQLi関連)
│   ├── services/
│   │   ├── network_service.py      # SSRF / コマンド実行 / デシリアライズ
│   │   └── auth_service.py         # 認可・IDORモジュール
│   └── tests/
│       └── test_fixtures.py        # テストコード (SAFE-009)
├── runner/                         # ベンチマーク実行エンジン
│   ├── config.py                   # 設定・モデル・コスト計算モジュール
│   ├── ground_truth.json           # 30問の正解ラベル定義
│   ├── ast_summarizer.py           # Google Mantis (mantis-summarize) 準拠AST要約
│   ├── poc_verifier.py             # Google Mantis (mantis-reproduce) 準拠PoC検証ハーネス
│   ├── scanners/
│   │   ├── base.py                 # スキャナ基底クラス
│   │   ├── bandit_runner.py        # 手法① Bandit 実行・パース
│   │   ├── semgrep_runner.py       # 手法② Semgrep 実行・パース
│   │   ├── raw_llm_runner.py       # 手法③ 全文投入LLM 実行・パース
│   │   └── mantis_runner.py        # 手法④ Google Mantis式 実行・パース
│   ├── evaluate.py                 # 判定照合・メトリクス計算スクリプト
│   └── templates/
│       └── prompt_raw.jinja2       # 素のLLM向けプロンプト
├── docs/
│   └── MANTIS_COMPLIANCE.md        # Google Mantis公式仕様準拠ドキュメント
├── materials/                      # 成果物出力先
│   ├── benchmark_summary.md        # 比較マトリクス
│   ├── benchmark_results.csv       # 設問別成否対照表
│   └── analysis_notes.md           # 考察・ツールの特性メモ
├── Makefile                        # 実行ワンライナー
├── requirements.txt                # 依存パッケージ
└── .env.example                    # 環境変数テンプレート
```

---

## 6. ライセンス
MIT License

