"""
LLM 處理層 (Enrichment)
對每則原始情資呼叫 Anthropic Claude API，產出：
  1. 中文摘要
  2. 風險分級 (critical/high/medium/low/info)
  3. 1~3 條簡短建議行動
  4. 分類標籤
輸出為固定 JSON schema，供後續模板套用。

防幻覺原則：prompt 明確要求 LLM 只能根據提供的原文摘要，不得推測未證實的細節；
沒有把握的欄位（如 CVSS、KEV 狀態）要明確標示「未知/N/A」，不可以瞎猜。
"""
import json
import os
import sys
import time

import anthropic

MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929")

SYSTEM_PROMPT = """你是一位資深資安威脅情資分析師（CTI Analyst），任務是把一則原始情資
（新聞/安全公告/部落格文章摘要）轉換成結構化的日報卡片資料。

嚴格規則：
1. 只能根據提供的原文內容進行摘要與判斷，不可以編造或推測未在原文中出現的細節。
2. 如果原文沒有提到 CVSS 分數、KEV 狀態、具體 IOC，欄位請明確填「N/A」或「未提及」，絕對不要瞎猜。
3. 摘要與建議必須使用繁體中文。
4. 風險分級只能是以下五種之一：critical, high, medium, low, info。
5. 建議行動必須具體可執行（例如包含時限、對象、動作），不要空泛描述。
6. 只輸出 JSON，不要有任何其他文字、不要用 markdown code block 包起來。

輸出 JSON 格式：
{
  "severity": "critical|high|medium|low|info",
  "category": "瀏覽器安全|漏洞與修補|威脅獵捕|惡意程式|網路攻擊|資料外洩|其他",
  "tags": ["標籤1", "標籤2"],
  "summary_paragraphs": ["摘要段落1", "摘要段落2（可選）"],
  "advisory_title": "建議行動標題（例如：🔔 建議行動）",
  "advisory_actions": ["建議行動1（含時限與對象）", "建議行動2"],
  "cve_ids": ["CVE-xxxx-xxxxx"],
  "cvss": "N/A 或實際分數",
  "kev_status": "未提及 / 已列入 KEV / 未列入 KEV"
}
"""


def enrich_item(client, item, retries=3):
    user_prompt = f"""原始情資：
標題：{item['title']}
來源：{item['source_name']}（{item['org']}）
發布日期：{item['published']}
連結：{item['url']}
原文摘要：
{item['raw_summary']}
"""

    last_err = None
    for attempt in range(retries):
        try:
            resp = client.messages.create(
                model=MODEL,
                max_tokens=1200,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
            text = resp.content[0].text.strip()
            # 容錯：若 LLM 仍包了 code block，去掉
            if text.startswith("```"):
                text = text.strip("`")
                if text.lower().startswith("json"):
                    text = text[4:]
            parsed = json.loads(text)
            return {**item, "llm": parsed}
        except Exception as e:
            last_err = e
            print(f"[WARN] LLM 處理失敗 (attempt {attempt+1}/{retries}): {item['id']} - {e}",
                  file=sys.stderr)
            time.sleep(2 * (attempt + 1))

    # 三次都失敗，回傳一個安全的 fallback，不中斷整條 pipeline
    print(f"[ERROR] 放棄處理: {item['id']} - {last_err}", file=sys.stderr)
    return {
        **item,
        "llm": {
            "severity": "info",
            "category": "其他",
            "tags": ["處理失敗"],
            "summary_paragraphs": [f"LLM 摘要失敗，原始標題：{item['title']}"],
            "advisory_title": "⚠️ 待人工複核",
            "advisory_actions": ["本則情資 LLM 自動摘要失敗，請人工檢視原文連結。"],
            "cve_ids": item.get("cve_id") and [item["cve_id"]] or [],
            "cvss": "N/A",
            "kev_status": "未提及",
        },
    }


def enrich_all(items):
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("缺少 ANTHROPIC_API_KEY 環境變數")

    client = anthropic.Anthropic(api_key=api_key)
    enriched = []
    for item in items:
        enriched.append(enrich_item(client, item))
    return enriched


if __name__ == "__main__":
    raw_items = json.load(sys.stdin)
    result = enrich_all(raw_items)
    print(json.dumps(result, ensure_ascii=False, indent=2))
