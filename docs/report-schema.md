# 日報資料交接 Schema

本文件定義 n8n workflow 產出、GitHub Actions 渲染腳本消費的 JSON 格式。
**這是 n8n 與 repo 之間唯一的契約**：n8n 只要產出符合這個格式的 JSON，渲染端保證能正確產生網頁；
渲染端不會、也不需要知道 n8n 內部怎麼抓資料、怎麼呼叫 LLM。

## 檔案位置與命名

- 正式資料：`data/YYYY-MM-DD.json`（例如 `data/2026-10-14.json`）
- 去重狀態：`data/seen.json`（格式固定為 `{"ids": ["...", "..."]}`，記錄已處理過的情資 ID，
  n8n 讀取後比對、處理完再寫回。**注意：最外層必須是物件，不能是裸陣列 `[]`**——
  n8n 的 HTTP Request 節點遇到最外層是陣列的 JSON 回應時，會把陣列每個元素拆成獨立 item，
  空陣列會變成 0 個 item，導致後面的 Merge 節點配對不到資料、沒有輸出。
- 範例/測試資料：`data/_example-*.json`（檔名底線開頭，渲染腳本測試用，**不會**被 index 產生器收錄進導覽樹）

## 頂層結構

```json
{
  "date": "2026-10-14",
  "stats": {
    "total": 3,
    "high_risk": 1,
    "cve_count": 2
  },
  "threat_level": "high",
  "sections": [ /* 見下方 Section 結構 */ ],
  "analyst_note": { /* 見下方 Analyst Note 結構 */ }
}
```

| 欄位 | 型別 | 說明 |
|---|---|---|
| `date` | string | `YYYY-MM-DD`，必須與檔名一致 |
| `stats.total` | int | 當日情資總數 |
| `stats.high_risk` | int | severity 為 critical 或 high 的數量 |
| `stats.cve_count` | int | 當日所有卡片的 CVE 總數（去重後） |
| `threat_level` | string | `critical\|high\|medium\|low\|info`，取當日所有卡片中最高風險等級 |
| `sections` | array | 依分類分組的卡片清單 |
| `analyst_note` | object | 分析師總評 |

## Section 結構

```json
{
  "id": "section-0",
  "title": "瀏覽器漏洞與修補",
  "icon": "🌐",
  "cards": [ /* 見下方 Card 結構 */ ]
}
```

- `id`：唯一值，用於頁內錨點 `#section-0`
- `icon`：單個 emoji，無對應分類時用 `📰`

## Card 結構

```json
{
  "anchor": "card-0-0",
  "severity": "high",
  "severity_label": "HIGH",
  "tags": ["瀏覽器安全"],
  "title": "Firefox 157 安全更新：聚焦兩項沙箱逃逸漏洞",
  "url": "https://www.mozilla.org/en-US/security/advisories/mfsa2026-97/",
  "source_name": "Mozilla Security Advisories",
  "org": "Mozilla",
  "published": "2026-10-14",
  "paragraphs": ["摘要段落1", "摘要段落2"],
  "advisory_title": "🔔 建議行動",
  "advisory_actions": ["建議1（含時限）", "建議2"],
  "cve_ids": ["CVE-2026-100758", "CVE-2026-100760"],
  "cvss": "N/A",
  "kev_status": "未列入 KEV"
}
```

**重要限制（防幻覺）**：`cvss`、`kev_status` 若原文沒提及，必須填 `"N/A"` 或 `"未提及"`，
不可以由 LLM 推測填入實際數字或狀態。這是在 n8n 的 Anthropic 呼叫 prompt 裡要求的，渲染端不做二次判斷。

## Analyst Note 結構

```json
{
  "highlight": "當日重點（1段文字）",
  "blind_spot": "防禦盲點分析（1段文字）",
  "ioc_note": "IOC偵測與獵捕意義（1段文字，若無可驗證IOC要明確說明）",
  "actions": ["[P0] 48小時內：...", "[P1] 本週內：..."]
}
```

## severity 允許值

只能是以下五種字串（小寫）：`critical`、`high`、`medium`、`low`、`info`。
渲染端的 `SEVERITY_LABEL`、CSS class（`severity-critical` 等）都是依這五個值對應，
n8n 那邊的 LLM prompt 必須強制輸出這五個值之一，不可以有其他拼法（例如 `High`、`緊急` 會對不上）。

## 驗證方式

渲染前建議先用這個指令確認範例資料格式正確、模板能吃：

```bash
python3 generate/build_report.py < data/_example-2026-10-14.json
```

如果 n8n 產出的 JSON 格式跟這份文件對不上，渲染腳本應該直接報錯中斷（fail fast），
而不是硬套然後產出壞掉的網頁——錯誤比壞掉的靜默輸出更好debug。
