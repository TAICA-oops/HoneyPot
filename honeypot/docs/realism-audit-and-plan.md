# 蜜罐擬真度審查與後續計劃

> 目的：以「滲透測試者會怎麼戳破這個蜜罐」為主軸,系統性檢查回傳內容的一致性破綻
> (consistency tells)、LLM prompt 品質與結構問題,記錄已修項目與後續待辦。
> 對應分支：`fix/honeypot-consistency`（2026-06,測試 38 → 84 全過）。

蜜罐最大的弱點通常不是會崩潰的 bug,而是**攻擊者用三五個指令交叉比對就能發現「這台機器是假的」**。
下面依「被識破的容易度」分級記錄。

---

## 一、本次已修正

### 1. 假終端一致性（commit「修正假終端一致性」）

| 問題 | 為什麼會穿幫 | 怎麼修 |
|---|---|---|
| `ls` 列得出的目錄 `cd` 進不去 | `ls /var` 有 `log`,但 `cd /var/log` 回 No such file。`cd /tmp`、`cd /var/log` 是攻擊者進來第一個動作 | `FAKE_DIRS` 改由 `shared/fake_fs.py` 提供,涵蓋所有 `ls` 會列出的目錄;`cd` 進檔案回 `Not a directory` |
| `ls dir/`（尾斜線）、`ls .`、`ls ..` 失敗 | 路徑沒正規化,`ls /home/admin/` 找不到但 `ls /home/admin` 正常 | 新增 `fake_fs.normalize_path`,`cd`/`ls` 共用 |
| 任何人都讀得到任何檔 | dbadmin 能 `cat /home/admin/.bash_history`（明明是 600）;root 反而讀不到 `/etc/shadow` | `fake_fs.can_read` + `PRIVATE_FILES`：私密檔只有檔主與 root 能讀 |
| `.env` 的 AWS 金鑰是官方範例值 | `AKIAIOSFODNN7EXAMPLE` 任何掃描器一眼認出是假的 | 換成格式合法的隨機假值 |
| `.env` 三處內容不一致 | HTTP `/.env` 與 SSH `cat .env` 不同（MAIL_* 有無） | 全部 import `fake_fs.ENV_FILE` |
| `ls -l` 大小與實際內容對不上 | `backup.sql` 宣稱 8748 bytes,`cat` 只有 ~200 | `ls -l` 大小改用 `len(實際內容)` |
| `history` 與 `~/.bash_history` 兩套劇本 | 真實 bash 兩者高度重疊,這裡完全不同 | 共用 `fake_fs.STATIC_HISTORY_COMMANDS` |
| 登入永遠落在 `/home/admin` | 登入 dbadmin 卻在 admin 家目錄 | `create()` 用 `fake_fs.home_for(user)` |
| `ubuntu` 可登入卻不存在於系統觀 | `id` uid 與 admin 撞號、passwd/`/home` 沒有它 | 補進 passwd / `/home` / UID_MAP（uid 1004） |

### 2. 提權狀態持續（commit「提權後身分持續」）

- **問題**：Layer 1 的 user 狀態永不變。`sudo su -` 之後 `whoami` 仍回登入帳號 → 提權劇情自相矛盾。
- **修法**：`session_manager` 加 `user_stack`;`detect_escalation()` 區分「持續提權 shell」(`sudo su`/`-i`/`bash`) 與「單次執行」(`sudo ... -c`);`push_user`/`pop_user` 維護 effective user;`exit`/Ctrl-D 逐層退回。
- 提示符動態化：root 用 `#`、家目錄收合成 `~`。
- 一次性 `sudo <讀取指令>` 在 cache 內以 root 重跑,確保與提權後讀取一致;`sudo -l` 給確定性授權清單。

### 3. LLM Prompt 動態化（commit「LLM prompt 動態化」）

- 移除寫死的 `USER=admin`/`HOME=/home/admin` → 改用 user message 的 Current user（登入 dbadmin 不再 `echo $USER` 回 admin）。
- 移除 prompt 自身的 UTC+8 ↔ 系統 UTC 矛盾;明確告知凍結系統時間,要求生成的日誌時間不晚於該時間。
- 灌入 canonical 檔案系統總覽 + 完整使用者清單 → cache miss 時 LLM 不再編出與快取衝突的目錄/檔案。
- KNOWN FILES 改用 `fake_fs` 單一來源。

### 4. HTTP（commit「HTTP 同 IP 請求聚合」）

- 同 IP 請求聚合成單一 session（`http-<ip>`），掃描器不再每條路徑各開一個 session 洗版 dashboard。
- `session_touch` 保留期間出現過的「最高」威脅等級。
- phpMyAdmin POST 改讀完整 body 並 URL 解碼 → 捕捉 `sql_query` 作為 SQL injection 證據。

### 5. SSH 協定（commit「SSH 支援非互動式 exec」）

- 實作 `check_channel_exec_request` → 支援 `ssh user@host 'cmd'`（攻擊工具/橫向移動最常用,先前完全失敗且不被記錄）。
- host key 由純 RSA 改為 **RSA + ECDSA**,貼近真實 sshd 同時提供多型別金鑰。

### 6. 雜項（commit「ss/netstat 顯示攻擊者自身連線」）

- 來源 IP 串接進 `RespondRequest.attacker_ip` → `ss`/`netstat` 顯示攻擊者自己的連線而非寫死的 10.0.0.1。
- `id` 對 admin 加 `27(sudo)` 群組,與 sudoers / `sudo -l` 一致。
- `_dynamic_fs` 加 2000 筆上限（FIFO 逐出）。

---

## 二、仍存在的限制 / 後續待辦（forward plan）

依優先序：

1. **SSH 指紋仍可被識別（高,難全修）**
   paramiko 的 KEX/cipher/MAC 協商清單與真實 OpenSSH 7.6 不同,`nmap --script ssh2-enum-algos`、
   `ssh -vv` 可識別為非 OpenSSH（Cowrie/蜜罐偵測經典手法）。
   *選項*：(a) 在 `Transport` 上自訂 `_preferred_kex`/ciphers/MACs 對齊 OpenSSH 7.6 清單;
   (b) 接受限制,在報告/簡報誠實標註「網路層指紋仍可被進階偵測」。
   另：Ed25519 host key 未生成（paramiko 3.4 無 `Ed25519Key.generate`）—— 可改為預先用
   `ssh-keygen` 產生檔案再 `Ed25519Key(filename=...)` 載入。

2. **誘餌檔的非確定性讀取（中）**
   `head`/`tail`/`wc -c`/`stat`/`grep` 對誘餌檔仍走 LLM,可能與 `cat` 的確定性內容對不上
   （例：`head .env` vs `cat .env`）。
   *建議*：在 `cache` 對已知誘餌檔攔截 `head/tail/wc -c/stat`,由 `_FILE_CONTENT` 程式化產生。

3. **報告生成併發（中低）**
   每個 SSH session 結束都開一條 daemon thread 打 Ollama（120s）。大量 session 同時結束會互相排隊。
   *建議*：改用單一 worker + 佇列串行化,或加上同時併發上限。

4. **Stats API 安全（部署才需要）**
   `CORS allow_origins=["*"]` 且無認證;`POST /api/reports/{id}/generate` 可被外部狂打 Ollama（DoS）。
   *建議*：部署時加 API token 或限制來源;`/api/config` 可考慮不對外。

5. **時間不前進（低）**
   `date` 永遠回同一時間,`date; sleep 5; date` 不變。
   *建議*：以「啟動時間 + 真實流逝」計算,或接受此限制。

6. **shell 進階功能（低）**
   方向鍵/Tab 補全會被當成字元塞進指令;管線/重導向的 `cat .env | grep` 走 LLM 非確定性。
   多為互動式攻擊者才會踩到。

---

## 三、驗證方式

```bash
cd honeypot
.venv/bin/pytest tests/ -q          # 84 個測試,聚焦一致性與權限
```

關鍵測試檔：
- `tests/test_consistency.py` —— 跨層誘餌一致性、AWS 金鑰
- `tests/test_fake_terminal.py` —— 權限、history/.bash_history、ls 大小/正規化、sudo、ss、id
- `tests/layer1/test_privilege_state.py` —— 提權堆疊與提權前後一致性整合測試
- `tests/layer1/test_http_server.py` —— 同 IP 聚合、phpMyAdmin SQL 收割、威脅取最高

---

## 四、攻擊者「測蜜罐」檢查清單（回歸測試靈感）

做新功能前可拿這些自我檢查是否又產生破綻：

- [ ] `ls <dir>` 顯示的每個子目錄都能 `cd` 進去
- [ ] `cd <檔案>` 回 `Not a directory`,`cd <不存在>` 回 `No such file`
- [ ] 以非 root 身分讀 600/640 檔被拒;root 讀得到
- [ ] `ls -l` 宣稱大小 ≈ `cat | wc -c`
- [ ] `history` 與 `~/.bash_history` 內容重疊
- [ ] 登入身分 = `whoami` = `id` = `echo $USER` = passwd 條目（含家目錄）
- [ ] `sudo su -` 後 `whoami`/`id`/讀 shadow 都維持 root,`exit` 退回原身分
- [ ] HTTP `/.env` 與 SSH `cat /var/www/html/.env` 內容一致
- [ ] `date`/`uname`/日誌時間彼此不矛盾（都 UTC、都 ≤ 凍結時間）
- [ ] 沒有任何「教科書範例」憑證（AWS 範例金鑰、`password` 之類）
