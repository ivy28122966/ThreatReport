"""
產生層 (Static Generator) —— 純渲染，不呼叫任何 LLM/外部 API。

輸入：一份已經符合 docs/report-schema.md 格式的 JSON（n8n 產出，或測試用的範例資料）
輸出：
  1. dailyreport/YYYY-MM-DD.html（套用 Jinja2 模板）
  2. dailyreport/index.html（重新掃描所有日報檔案，按月分組建樹狀導覽）
  3. dailyreport/style.css（從模板目錄同步）

這支程式故意「fail fast」：輸入格式不符就直接報錯中斷，不做靜默容錯，
避免 n8n 那邊格式跑掉時，渲染出一個看起來正常但內容壞掉的網頁卻沒人發現。

使用方式：
  python3 generate/build_report.py data/2026-10-14.json
  或
  cat data/2026-10-14.json | python3 generate/build_report.py
"""
import json
import os
import re
import sys
from collections import defaultdict

from jinja2 import Environment, FileSystemLoader

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, "generate", "templates")
OUTPUT_DIR = os.path.join(BASE_DIR, "dailyreport")

REQUIRED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
SEVERITY_LABEL = {
    "critical": "🔴 CRITICAL", "high": "🟠 HIGH", "medium": "🟡 MEDIUM",
    "low": "🟢 LOW", "info": "🔵 INFO",
}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def validate(data):
    """基本格式檢查，不符合直接丟例外中斷，不嘗試猜測修補。"""
    errors = []

    if not DATE_RE.match(data.get("date", "")):
        errors.append(f"date 格式錯誤: {data.get('date')!r}，應為 YYYY-MM-DD")

    if data.get("threat_level") not in REQUIRED_SEVERITIES:
        errors.append(f"threat_level 不在允許值內: {data.get('threat_level')!r}")

    if not isinstance(data.get("sections"), list):
        errors.append("sections 必須是陣列")
    else:
        for i, section in enumerate(data["sections"]):
            for key in ("id", "title", "icon", "cards"):
                if key not in section:
                    errors.append(f"sections[{i}] 缺少欄位: {key}")
            for j, card in enumerate(section.get("cards", [])):
                if card.get("severity") not in REQUIRED_SEVERITIES:
                    errors.append(
                        f"sections[{i}].cards[{j}].severity 不在允許值內: "
                        f"{card.get('severity')!r}"
                    )
                for key in ("title", "url", "source_name", "advisory_actions"):
                    if key not in card:
                        errors.append(f"sections[{i}].cards[{j}] 缺少欄位: {key}")

    if "analyst_note" not in data:
        errors.append("缺少 analyst_note")

    if errors:
        raise ValueError(
            "輸入 JSON 不符合 docs/report-schema.md 定義：\n  - " + "\n  - ".join(errors)
        )


def render_report(data):
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report.html.j2")
    html = template.render(**data, SEVERITY_LABEL=SEVERITY_LABEL)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(OUTPUT_DIR, f"{data['date']}.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path


def rebuild_index():
    """掃描 dailyreport/ 底下所有 YYYY-MM-DD.html（排除 _example 等測試檔），
    依月份分組重建 index.html"""
    pattern = re.compile(r"^(\d{4})-(\d{2})-(\d{2})\.html$")
    by_month = defaultdict(list)
    for fname in os.listdir(OUTPUT_DIR):
        m = pattern.match(fname)
        if m:
            year, month, _day = m.groups()
            by_month[(year, month)].append(fname[:-5])

    months = []
    for (year, month) in sorted(by_month.keys()):
        days = sorted(by_month[(year, month)])
        months.append({"label": f"{year} 年 {int(month)} 月", "days": days})

    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("index.html.j2")
    html = template.render(months=months)
    with open(os.path.join(OUTPUT_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)


def ensure_style_css():
    """確保 dailyreport/style.css 跟模板目錄同步（樣式只改模板目錄這一份即可）"""
    src = os.path.join(TEMPLATE_DIR, "style.css")
    dst = os.path.join(OUTPUT_DIR, "style.css")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(src, "r", encoding="utf-8") as f:
        content = f.read()
    with open(dst, "w", encoding="utf-8") as f:
        f.write(content)


def load_input():
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            return json.load(f)
    return json.load(sys.stdin)


if __name__ == "__main__":
    data = load_input()
    validate(data)
    ensure_style_css()
    out_path = render_report(data)
    rebuild_index()
    print(f"已產生: {out_path}", file=sys.stderr)
    print(f"已更新: {os.path.join(OUTPUT_DIR, 'index.html')}", file=sys.stderr)
