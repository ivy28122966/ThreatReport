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

const items = $input.all();
const counts = {};
const results = [];

for (let i = 0; i < items.length; i++) {
  const item = items[i];
  // 用 itemMatching 正確配對「這一筆是從哪個來源展開來的」
  // 因為多個 rss 來源會同時通過這個節點，用 .item（單數）會抓到錯的來源設定
  const source = $('Expand Sources').itemMatching(i).json;
  const cutoff = Date.now() - source.lookbackHours * 3600 * 1000;

  counts[source.id] = counts[source.id] || 0;
  if (counts[source.id] >= source.maxPerSource) continue;

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
  counts[source.id]++;
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

const source = $('Expand Sources').itemMatching(0).json;
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

## 實測驗證紀錄

2026-10-13 完整跑通節點 1~12，`Merge New Items` 正確輸出多筆情資，
欄位齊全（`id/source_id/source_name/org/category_hint/title/url/published/raw_summary`）。
過程中修正了三個 bug：
1. `seen.json` 要用 `{"ids": []}` 物件包陣列，不能是裸陣列（見節點5的地雷說明）
2. Route By Type 的 Rule 比對值欄位必須真的填入 `rss`/`cisa_kev`，不能留空 placeholder
3. Normalize RSS/KEV 原本用 `.item`（單數）只抓到一組來源設定，多來源混合時配對錯誤，
   改用 `itemMatching(i)` 依每筆資料實際來源正確配對（已更新上方程式碼）
4. Mozilla 官方 Security Advisories RSS feed 已下線（404），改用 Mozilla Security Blog 官方 RSS

## 待補（尚未定案）

- 節點 13 起：LLM 摘要（呼叫 Anthropic API）
- 組裝成 docs/report-schema.md 定義的最終 JSON
- GitHub 節點：commit `data/YYYY-MM-DD.json` + 更新 `data/seen.json`

---

# Part 2：LLM 摘要與自動發布（節點 13~22）

架構調整：改用 **Claude Code CLI + Claude Pro 訂閱**做摘要，不呼叫 Anthropic API，不產生 API 費用。
詳細理由與成本比較見對話紀錄；n8n 透過 `Execute Command` 節點呼叫容器內安裝好的 `claude` CLI。

## 前置：n8n 容器需要的改動

### Docker image 加裝 Claude Code CLI

`~/n8n-docker/Dockerfile`：
```dockerfile
FROM n8nio/n8n:latest
USER root
RUN npm install -g @anthropic-ai/claude-code \
 && mkdir -p /home/node/.claude \
 && chown -R node:node /home/node/.claude
COPY --chown=node:node claude-settings.json /home/node/.claude/settings.json
USER node
```

`~/n8n-docker/claude-settings.json`（鎖死工具權限，Claude Code 在容器內只能做純文字生成，
不能碰檔案系統/網路/執行指令——就算抓到的 RSS 內容裡藏了 prompt injection，也無法真的執行任何操作）：
```json
{
  "permissions": {
    "deny": ["Bash","Edit","Write","Read","Glob","Grep","WebFetch","WebSearch","NotebookEdit","Task"]
  },
  "env": {
    "DISABLE_TELEMETRY": "1",
    "DISABLE_AUTOUPDATER": "1"
  }
}
```

### docker-compose.yml 需要的環境變數

```yaml
services:
  n8n:
    build:
      context: .
      dockerfile: Dockerfile
    image: threatreport-n8n-claude:latest
    container_name: n8n
    restart: unless-stopped
    ports:
      - "5678:5678"
    environment:
      - CLAUDE_CODE_OAUTH_TOKEN=${CLAUDE_CODE_OAUTH_TOKEN}
      - NODES_EXCLUDE=[]
      - N8N_RESTRICT_FILE_ACCESS_TO=/tmp
    volumes:
      - n8n_data:/home/node/.n8n

volumes:
  n8n_data:
    external: true
```

三個環境變數各自的用途：

| 變數 | 作用 |
|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | 讓容器內的 `claude` CLI 用 Claude Pro 訂閱額度登入，不走 API 計費 |
| `NODES_EXCLUDE=[]` | n8n v2 起預設停用 `Execute Command`、`Local File Trigger` 節點（安全考量），設空陣列解除停用 |
| `N8N_RESTRICT_FILE_ACCESS_TO=/tmp` | `Read/Write Files from Disk` 節點預設不給存取任意路徑，白名單只開放 `/tmp` |

**`CLAUDE_CODE_OAUTH_TOKEN` 不要用 `env_file: .env` 整包匯入**——容易把 `N8N_ENCRYPTION_KEY`
之類不該被覆蓋的變數也一起帶進去（跟 volume 裡已存在的金鑰對不起來會讓 n8n 開不了機）。
只明確列出要傳的變數。

容器內測試 Claude Code CLI 是否正常：
```bash
docker exec n8n claude -p 'Reply with exactly: OK'
```

## 節點總覽（接續節點 12 之後）

| # | 節點名稱 | 類型 | 輸入 |
|---|---|---|---|
| 13 | Aggregate | Aggregate | Merge New Items |
| 14 | Build Prompt | Code | Aggregate |
| 15 | Convert to File | Convert to File | Build Prompt |
| 16 | Write Prompt File | Read/Write Files from Disk | Convert to File |
| 17 | Execute Command | Execute Command | Write Prompt File |
| 18 | Parse Claude Output | Code | Execute Command |
| 19 | Commit Report JSON | GitHub（File / Create or Edit） | Parse Claude Output |
| 20 | Get Seen File | GitHub（File / Get） | Parse Claude Output |
| 21 | Merge Seen IDs | Code | Get Seen File |
| 22 | Update Seen File | GitHub（File / Edit） | Merge Seen IDs |

節點 19 跟節點 20→21→22 是**兩條平行分支**，都接在節點 18 之後。

## 為什麼不直接把資料塞進 Execute Command 的指令字串

不可信內容（RSS 文章標題/摘要）絕對不能直接組進 shell 指令字串——萬一某篇文章標題剛好含有
`` ` ``、`$()`、`;` 之類字元，可能被當成 shell 指令解析（command injection）。
解法：先用 n8n 原生節點把內容寫成**檔案**（完全不經過 shell），再讓 Execute Command 的
指令字串**固定不變**，只用 `$(cat 檔案路徑)` 去讀檔案內容當參數——這個寫法底下讀出來的內容
只會被當成純字串代入參數，不會被 shell 重新解析。

## 節點 13：Aggregate

- Aggregate: `Aggregate All Item Data`
- Put Output in Field: `items`
- Include: All Fields

把 `Merge New Items` 的 N 筆資料合併成一個 item，`items` 欄位是陣列。

## 節點 14：Build Prompt（Code / JavaScript）

把完整提示詞（見 `docs/manual-llm-workflow.md` 的「重用提示詞」）寫成 JS 模板字串，
動態代入日期和資料：

```js
const items = $input.first().json.items;
const reportDate = $now.toFormat('yyyy-LL-dd'); // workflow設定了Asia/Taipei

const instructions = `你是繁體中文資安威脅情資日報編輯。...
（完整提示詞內容，含 schema 範例，見 docs/manual-llm-workflow.md）
...
n8n Merge New Items 的完整 JSON 輸出：
${JSON.stringify(items, null, 2)}`;

return [{ json: { prompt: instructions, date: reportDate } }];
```

## 節點 15：Convert to File

- Operation: `Convert to Text File`
- **Text Input Field**: `prompt`（必填，沒填會報錯）
- **Put Output File in Field**: `data`
- **File Name**: `threatreport_prompt.txt`（純文字固定檔名，**不要**用日期動態組，
  因為節點 17 的 Execute Command 指令字串要完全寫死，不含任何運算式）

## 節點 16：Write Prompt File

- Operation: `Write File to Disk`
- **File Path and Name**: `/tmp/threatreport_prompt.txt`（純文字固定值，不要用運算式）
- **Input Binary Field**: `data`

⚠️ **地雷**：這個欄位如果殘留舊的運算式（例如之前測試用的
`{{ '/tmp/threatreport_prompt_' + $json.date + '.txt' }}`），但輸入資料已經不含 `date` 欄位
（`Convert to File` 的輸出只有檔案中繼資料，沒有原本 `Build Prompt` 的 `date`），
會解析成 `undefined`，變成去找一個真的不存在的檔案。要固定寫死路徑。

⚠️ **地雷**：這個節點需要 `N8N_RESTRICT_FILE_ACCESS_TO` 環境變數允許 `/tmp`（見上方前置設定），
否則會報 `Access to the file is not allowed`。

## 節點 17：Execute Command

- **Command**（純文字，絕對不要放任何 `{{ }}` 運算式）：
  ```
  claude -p "$(cat /tmp/threatreport_prompt.txt)"
  ```

⚠️ **地雷**：這個節點在 n8n v2 之後預設被停用（連節點面板都搜不到），
要設定 `NODES_EXCLUDE=[]` 環境變數才會出現（見上方前置設定）。

輸出的 `stdout` 欄位是 Claude 的回覆文字。`stderr` 可能會有一行
`Warning: no stdin data received...` 的無害警告，`exitCode: 0` 就代表成功。

## 節點 18：Parse Claude Output（Code / JavaScript）

```js
let text = $input.first().json.stdout.trim();

if (text.startsWith('```')) {
  text = text.replace(/^```(json)?/i, '').replace(/```$/, '').trim();
}

let data;
try {
  data = JSON.parse(text);
} catch (e) {
  throw new Error('Claude 回傳的內容不是合法 JSON，請檢查 stdout 原文: ' + text.slice(0, 500));
}

const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
if (!validSeverities.includes(data.threat_level)) {
  throw new Error('threat_level 不合法: ' + data.threat_level);
}

return [{ json: data }];
```

輸出就是符合 `docs/report-schema.md` 的完整日報 JSON（`date/stats/sections/analyst_note`
直接在最外層，沒有任何包裝）。

## 節點 19：Commit Report JSON（GitHub）

- Credential：GitHub fine-grained PAT，**只給這一個 repo**、只開 `Contents: Read and write` 權限
- Resource: `File`
- Operation: `Edit`（不要用 `Create`——如果當天已經有檔案存在（例如用 Webhook 補跑過一次），
  `Create` 會因為「檔案已存在但沒給 SHA」而失敗；`Edit` 這個版本的 GitHub 節點內部會自動先查
  現有檔案的 SHA 再更新，檔案不存在時也能正常當成新建處理，兩種情境都適用）
- Owner / Repository: `ivy28122966` / `ThreatReport`
- **File Path**（點 `fx` 進 **Expression** 分頁，純 JS，不要加 `=` 或 `{{ }}`）：
  ```
  'data/' + $json.date + '.json'
  ```
- **File Content**（同樣切到 Expression 分頁）：
  ```
  JSON.stringify($json, null, 2)
  ```
- **Commit Message**：
  ```
  'feat: 新增 ' + $json.date + ' 日報（n8n自動化產出）'
  ```
- Additional Parameters → Branch: `main`

## 節點 20：Get Seen File（GitHub）

- Resource: `File`，Operation: `Get`
- Owner / Repository / Branch 同上
- File Path: `data/seen.json`（固定文字即可，不需要運算式）

這個版本的 GitHub 節點，`Get` 操作回傳的是**二進位檔案**格式（檔名/副檔名/MimeType 中繼資料），
不是 `json.content` 這種 base64 文字欄位。

## 節點 21：Merge Seen IDs（Code / JavaScript）

```js
const buffer = await this.helpers.getBinaryDataBuffer(0, 'data');
const existing = JSON.parse(buffer.toString('utf-8'));

const newItems = $('Aggregate').item.json.items;
const newIds = newItems.map(i => i.id);

const merged = Array.from(new Set([...existing.ids, ...newIds])).slice(-5000);

return [{ json: { ids: merged } }];
```

⚠️ **地雷**：不要用 `$input.first().binary.data.data` 手動 base64 解碼——不同儲存模式下
（例如改成檔案系統模式存二進位資料）這個欄位可能是參照代碼而不是真正的 base64 內容，解出來會是亂碼。
用官方的 `this.helpers.getBinaryDataBuffer(itemIndex, 二進位欄位名)` 輔助方法最穩，不管底層怎麼存都能正確讀到。

## 節點 22：Update Seen File（GitHub）

- Resource: `File`，Operation: `Edit`
- Owner / Repository / Branch 同上
- File Path: `data/seen.json`（固定文字）
- **File Content**：點進欄位右上角的 **`Expression`** 分頁（不是 `Fixed`！），
  切過去之後純打 JS，不要加任何符號：
  ```
  JSON.stringify({ids: $json.ids}, null, 2)
  ```
- Commit Message: `chore: 更新 seen.json`
- 這個版本不需要手動提供 File SHA，`Edit` 操作會自動處理

## 這個版本 GitHub 節點欄位的「Fixed / Expression」切換地雷（花最多時間除的錯）

這個 n8n 版本的字串參數欄位，右上角有兩個分頁：**`Fixed`** 和 **`Expression`**。
**目前選取的是哪個分頁，直接決定這格內容怎麼被解讀**：

- 選 `Fixed`：整格內容**當成純文字字面值**送出去，就算你打了 `{{ }}` 符號，也不會被求值，
  會連 `{{ }}` 符號本身都原封不動送出去
- 選 `Expression`：整格內容當成 **JS 運算式**求值，**不要加 `{{ }}`、不要加開頭的 `=`**，
  直接打純 JS 程式碼本身

踩過的三種錯誤組合（照時間順序）：
1. 在 `Fixed` 模式打 `={{ expr }}`（含開頭等號）→ 結果是字面上的 `=<求值結果>`
   （只有外層 `{{ }}` 語法本身有被 mustache 模板替換，但多出來的 `=` 變成字面文字殘留）
2. 在 `Fixed` 模式打 `JSON.stringify(...)`（沒有 `{{ }}` 也沒有 `=`）→ 整段純文字字面值送出，
   完全沒有被求值，寫進檔案的是程式碼本身
3. 在 `Fixed` 模式打 `{{ JSON.stringify(...) }}`（看起來應該要能動）→ 如果沒有真的切到
   `Expression` 分頁，這串包含 `{{ }}` 符號的文字一樣會整個被當成字面值，原封不動存進檔案

**唯一可靠的判斷方式**：欄位下方的「預覽」文字如果跟你打的內容一字不差，代表沒有被求值；
預覽文字變成實際計算結果（例如變成 `data/2026-10-20.json` 而不是
`'data/' + $json.date + '.json'`），才代表真的在 Expression 模式下運作。

**每次改完運算式欄位，先看預覽再執行**，不要假設切換成功。

## 實測除錯紀錄（2026-10-20）

完整跑通節點 13~22，過程中額外修正：
1. `Execute Command` 節點 v2 後預設停用，需要 `NODES_EXCLUDE=[]`
2. `Read/Write Files from Disk` 需要 `N8N_RESTRICT_FILE_ACCESS_TO` 白名單路徑
3. `Merge Seen IDs` 讀二進位資料要用 `this.helpers.getBinaryDataBuffer()`，不要手動解 base64
4. `Commit Report JSON` 要用 `Edit` 不要用 `Create`，因為同一天可能被補跑多次、檔案可能已存在
5. GitHub 節點字串欄位的 `Fixed`/`Expression` 分頁切換是最容易出錯的地方，
   寫壞的 `seen.json` 前後修復了 3 次才抓到根本原因

另外發現：`build_report.py` 是依照 **JSON 內容裡的 `date` 欄位**決定輸出檔名，不是依照輸入檔名。
拿正式日期當測試資料的 `date` 會跟正式檔案撞名、互相覆蓋。測試時務必用不會撞期的日期
（例如 `2099-01-01`），測完手動清掉對應產生的 `dailyreport/*.html`。

