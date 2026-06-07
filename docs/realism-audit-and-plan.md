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

## 二、第二輪已解決的限制

第一輪後針對「仍存在的限制」再做一輪處理,以下皆已修並有測試：

1. **SSH 指紋對齊（原「高,難全修」）** — `_harden_transport` 把 KEX/cipher/MAC/key 協商清單
   收斂成 OpenSSH 7.6 風格（取 paramiko 支援的交集並依 OpenSSH 順序）,移除 `3des-cbc`/
   `group1-sha1`/`hmac-md5`/`ssh-dss` 等老演算法;host key 補上 **Ed25519**（用 `cryptography`
   產生）,現提供 ed25519 + ecdsa + rsa 三型別。實機驗證協商出 `aes128-ctr` / `curve25519` /
   `ssh-ed25519`。**殘留**：paramiko 仍非真正的 OpenSSH,極深入的指紋分析仍可能有差異,但常見
   `nmap ssh2-enum-algos`/`ssh -vv` 看到的演算法清單已與 OpenSSH 7.6 一致。

2. **誘餌檔非確定性讀取** — `cache` 對已知誘餌檔攔截 `head`/`tail`/`wc`,由 `_FILE_CONTENT`
   程式化計算（套用相同權限模型）;`head .env`、`wc -c .env` 已與 `cat .env` 一致。
   （`stat`、`grep`、管線仍走 LLM,見下方「剩餘」。）

3. **報告生成併發** — 改 `report_generator.enqueue_report` 單一 worker 佇列串行消化,
   單一工作失敗不影響後續。

4. **Stats API CORS** — `CORS_ORIGINS` 環境變數可鎖定來源,預設仍 `*` 不影響本地 demo。

5. **時間前進** — `fake_fs.date_str()/uptime_str()` 回傳即時 UTC 時間,uptime 隨真實時間增加;
   prompt 改在每次請求附上 `System time`。`date` 兩次不再相同、也不再卡在 2023。

## 三、第三輪：狀態化擬真（分支 feat/stateful-realism）

針對「LLM 蜜罐的狀態一致性」再做一輪,讓蜜罐不只「世界固定」,還能反映攻擊者的改動、並記得攻擊者。

### 1. 可變狀態覆寫層 (mutable-state overlay)
攻擊者的 `echo>檔案`、`>>`、`mkdir`、`touch`、`useradd`、`rm`、寫 `/etc/passwd` 等寫入,存進共用
SQLite `fs_overlay`(`layer2/overlay.py`),跨連線/跨程序/跨重啟持久。後續 cat/ls/grep/head/wc 與
Layer1 的 cd 都先查覆寫層再回落基準。修正最大的「狀態快照」破綻:先前 useradd 後 `cat /etc/passwd`
看不到新帳號、mkdir 後 cd 不進去。寫入套用真實權限(`can_write`:非 root 不能寫系統路徑;經 sudo
以 root 寫入),讀取套用 700 目錄規則(`/root` 與 `.ssh` 非擁有者讀不到)。

### 2. 跨連線記憶 (cross-connection memory by IP)
SSH 重連時,用該來源 IP 在 commands 表的既有指令脈絡(最近 15 筆、僅 SSH)預載回新 session 歷史
(`logger.recent_pairs_for_ip` → `session_manager.seed_history`),讓 LLM 延續先前對話而非每次失憶。

### 3. grep / readline
- grep(單檔)對誘餌檔確定性化(支援 -i/-n/-v、shlex 引號),與 cat 一致。
- 互動式吞掉 ANSI 跳脫序列(方向鍵/功能鍵)與 Tab,避免 `^[[A` 亂碼塞進指令。

### 4. Codex 獨立審查後強化
經 Codex 審查修正:overlay 寫入權限模型、`/root` 與 `.ssh` 讀取權限、`mkdir -p` 建父層、`rm -r`
刪子項與存在性/目錄錯誤訊息、`ls -l` overlay 大小、改針對性查詢(避免全表掃描)、複合指令
(`&&`/`|`/`;`)與 `> /dev/null` 交給 LLM、overlay 列數上限。

---

## 四、剩餘限制（影響低,暫不處理）

- **`stat` 與管線走 LLM**：head/tail/wc/grep(單檔)已確定性化,但 `stat` 與 `cat … | grep …` 等
  管線仍交給 LLM(`stat` 需補齊 inode/owner/mode 才不會與 `ls -l` 打架)。
- **可變狀態覆寫層範圍**：涵蓋常見寫入指令,但 `cp`/`mv`/`tar` 與複合指令不持久化。
- **paramiko 協定層**：演算法清單已對齊 OpenSSH 7.6,但極深入的時序/實作指紋仍非 100% 一致。
- **跨連線記憶以 IP 為索引**：NAT/動態 IP 下多名攻擊者會被當成同一人(蜜罐情境多可接受)。
- **`useradd` 並發配號未加鎖**(蜜罐並發低,SQLite 已序列化寫入)。
- **Stats API 認證 / 報告端點 rate-limit**：部署對外時建議再加(目前僅 CORS 可設定)。

---

## 五、驗證方式

```bash
cd honeypot
.venv/bin/pytest tests/ -q          # 137 個測試,涵蓋一致性、權限、提權、覆寫層、跨連線記憶、SSH 指紋
```

關鍵測試檔：
- `tests/test_consistency.py` —— 跨層誘餌一致性、AWS 金鑰
- `tests/test_fake_terminal.py` —— 權限、history/.bash_history、ls 大小/正規化、sudo、ss、id、時間
- `tests/test_bait_read_consistency.py` —— head/tail/wc/grep 與 cat 一致
- `tests/test_overlay.py` —— 可變狀態覆寫層(寫入/讀回、權限、mkdir -p、rm -r、跨連線持久)
- `tests/layer1/test_privilege_state.py` —— 提權堆疊與提權前後一致性整合測試
- `tests/layer1/test_cross_session_memory.py` —— 跨連線記憶(by IP)的脈絡重建
- `tests/layer1/test_ssh_fingerprint.py` —— SSH 演算法對齊、三型別 host key
- `tests/layer1/test_http_server.py` —— 同 IP 聚合、phpMyAdmin SQL 收割、威脅取最高
- `tests/layer3/test_report_queue.py`、`test_cors_config.py` —— 報告佇列、CORS 設定

---

## 六、攻擊者「測蜜罐」檢查清單（回歸測試靈感）

做新功能前可拿這些自我檢查是否又產生破綻：

- [ ] `ls <dir>` 顯示的每個子目錄都能 `cd` 進去
- [ ] `cd <檔案>` 回 `Not a directory`,`cd <不存在>` 回 `No such file`
- [ ] 以非 root 身分讀 600/640 檔被拒;root 讀得到
- [ ] `ls -l` 宣稱大小 ≈ `cat | wc -c`
- [ ] `history` 與 `~/.bash_history` 內容重疊
- [ ] 登入身分 = `whoami` = `id` = `echo $USER` = passwd 條目（含家目錄）
- [ ] `sudo su -` 後 `whoami`/`id`/讀 shadow 都維持 root,`exit` 退回原身分
- [ ] HTTP `/.env` 與 SSH `cat /var/www/html/.env` 內容一致
- [ ] `date`/`uname`/日誌時間彼此不矛盾（都 UTC、`date` 兩次會前進）
- [ ] 沒有任何「教科書範例」憑證（AWS 範例金鑰、`password` 之類）
- [ ] 寫入後讀得回：`echo x > f; cat f`、`useradd u; cat /etc/passwd`、`mkdir d; cd d`
- [ ] 寫入套權限：非 root 寫 `/etc`、`/root` 被拒;`/root/.ssh` 內容非 root 讀不到
- [ ] 同 IP 重連後,LLM 仍「記得」先前的指令脈絡
- [ ] 方向鍵/Tab 不會在指令列留下 `^[[A` 之類亂碼
