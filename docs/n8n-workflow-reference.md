# n8n Workflow 節點參考文件 — ThreatReport Daily

本文件記錄 n8n workflow「ThreatReport Daily」目前已定案的節點設定與程式碼，
作為實作時的對照依據，也作為日後重建/交接用的文件。

對應架構：n8n 負責「抓取 + 正規化 + 去重」這段（Step 3），
產出的清單接下來會送進 LLM 摘要階段（尚未定案，待補）。

## Workflow 設定

畫布右上角 `...` → Settings → Timezone: `Asia/Taipei`

## 節點總覽

| # | 節點名稱 | 類型 | 輸入 |
|---|---|---|---|
| 1 | Schedule Trigger | Schedule Trigger | （起點）|
| 2 | Webhook | Webhook | （起點，手動補跑用）|
| 3 | Fetch Sources Config | HTTP Request | 節點1 + 節點2 |
| 4 | Fetch Seen List | HTTP Request | 節點1 + 節點2 |
| 5 | Merge Config | Merge (Combine/Position) | 節點3 + 節點4 |
| 6 | Expand Sources | Code | 節點5 |
| 7 | Route By Type | Switch | 節點6 |
| 8 | RSS Read | RSS Read | 節點7 的 rss 分支 |
| 9 | Fetch CISA KEV | HTTP Request | 節點7 的 cisa_kev 分支 |
| 10 | Normalize RSS | Code | 節點8 |
| 11 | Normalize KEV | Code | 節點9 |
| 12 | Merge New Items | Merge (Append) | 節點10 + 節點11 |

## 節點設定細節

### 1. Schedule Trigger
- Trigger Interval: Custom (Cron)
- Cron Expression: `0 0 6 * * *`（n8n 用 6 欄位含秒，不是 Linux 5 欄位格式）

### 2. Webhook
- HTTP Method: GET
- Path: 自訂隨機字串（例如 `threatreport-manual-run-x7k2`），避免被亂觸發

### 3. Fetch Sources Config
- Method: GET
- URL: `https://raw.githubusercontent.com/ivy28122966/ThreatReport/main/config/sources.json`
- Response Format: JSON

### 4. Fetch Seen List
- Method: GET
- URL: `https://raw.githubusercontent.com/ivy28122966/ThreatReport/main/data/seen.json`
- Response Format: JSON

### 5. Merge Config
- Mode: Combine
- Combine By: Position（不是 Matching Fields，因為兩邊資料結構不同、只是要湊成一筆）

⚠️ **地雷**：`data/seen.json` 的最外層絕對不能是裸陣列 `[]`，必須是 `{"ids": []}`。
n8n 的 HTTP Request 節點遇到回應最外層是陣列時，會把每個陣列元素拆成獨立 item，
空陣列會變成 0 個 item，導致 `Merge Config` 配不到資料、完全沒有輸出。

### 6. Expand Sources（Code / JavaScript）
```js
const sources = $input.first().json.sources;
const seenIds = $input.last().json.ids;
const maxPerSource = $input.first().json.max_items_per_source || 5;
const lookbackHours = $input.first().json.lookback_hours || 30;

return sources.map(s => ({
  json: { ...s, seenIds, maxPerSource, lookbackHours }
}));
```

### 7. Route By Type（Switch）
- Mode: Rules
- Rule 1: `{{ $json.type }}` equals `rss` → 輸出 `rss`
- Rule 2: `{{ $json.type }}` equals `cisa_kev` → 輸出 `cisa_kev`

### 8. RSS Read
- Feed URL: `{{ $json.url }}`

### 9. Fetch CISA KEV
- Method: GET
- URL: `{{ $json.url }}`
- Response Format: JSON

### 10. Normalize RSS（Code / JavaScript）

重要：n8n Code 節點預設不允許 `require()` Node.js 內建模組（含 `crypto`），
所以 ID 用純 JS 寫的雜湊函式（非密碼學等級，但對去重用途足夠）。

```js
function hashId(str) {
  let h1 = 0xdeadbeef ^ str.length, h2 = 0x41c6ce57 ^ str.length;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0');
}

const source = $('Expand Sources').item.json;
const cutoff = Date.now() - source.lookbackHours * 3600 * 1000;
const items = $input.all();

const results = [];
for (const item of items.slice(0, source.maxPerSource)) {
  const d = item.json;
  const published = d.isoDate ? new Date(d.isoDate).getTime() : Date.now();
  if (published < cutoff) continue;

  const id = hashId(d.link + d.title);
  if (source.seenIds.includes(id)) continue;

  results.push({
    json: {
      id, source_id: source.id, source_name: source.name, org: source.org,
      category_hint: source.category, title: d.title, url: d.link,
      published: new Date(published).toISOString().slice(0, 10),
      raw_summary: (d.contentSnippet || d.content || '').slice(0, 3000),
    }
  });
}
return results;
```

### 11. Normalize KEV（Code / JavaScript）
```js
function hashId(str) {
  let h1 = 0xdeadbeef ^ str.length, h2 = 0x41c6ce57 ^ str.length;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0');
}

const source = $('Expand Sources').item.json;
const cutoff = Date.now() - source.lookbackHours * 3600 * 1000;
const data = $input.first().json;

const results = [];
for (const v of (data.vulnerabilities || []).slice(0, source.maxPerSource)) {
  const added = new Date(v.dateAdded).getTime();
  if (added < cutoff) continue;

  const title = `${v.cveID} — ${v.vulnerabilityName}`;
  const url = `https://nvd.nist.gov/vuln/detail/${v.cveID}`;
  const id = hashId(url + title);
  if (source.seenIds.includes(id)) continue;

  results.push({
    json: {
      id, source_id: source.id, source_name: source.name, org: source.org,
      category_hint: source.category, title, url,
      published: v.dateAdded, cve_id: v.cveID,
      raw_summary: `廠商/產品: ${v.vendorProject} ${v.product}\n說明: ${v.shortDescription}\n要求行動: ${v.requiredAction}`,
    }
  });
}
return results;
```

### 12. Merge New Items
- Mode: Append
- Input 1: Normalize RSS
- Input 2: Normalize KEV

## 驗證方式

跑到這裡，`Merge New Items` 的輸出應該是一份「當日新情資清單」，每筆都有：
`id, source_id, source_name, org, category_hint, title, url, published, raw_summary`
（KEV 來源的項目額外多一個 `cve_id`）。

第一次執行因為 `data/seen.json` 是空的 `[]`，所有抓到的項目都應該視為「新」。

## 待補（尚未定案）

- 節點 13 起：LLM 摘要（呼叫 Anthropic API）
- 組裝成 docs/report-schema.md 定義的最終 JSON
- GitHub 節點：commit `data/YYYY-MM-DD.json` + 更新 `data/seen.json`
