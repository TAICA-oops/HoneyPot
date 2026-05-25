# HoneyPot
<img width="1472" height="1480" alt="image" src="https://github.com/user-attachments/assets/7a22e541-e520-404f-a50f-c12a68143814" />

各層說明

Layer 1（人 1），左邊那排珊瑚色的元件：

* SSH 跟 HTTP 兩個入口分開處理
* 快取層（橘色）是效能優化的關鍵，常見指令直接秒回不經過 LLM
* 日誌全部存 SQLite，之後 Layer 3 用

Layer 2（人 2），右邊那排紫色的元件：

* 角色 Prompt 定義假系統的「人設」
* LLM 推理用 Ollama 跑 Qwen2.5
* 意圖分類器跟 Payload 分析器各自處理 SSH 跟 HTTP 的攻擊

Layer 3（兩人合作），最下面綠色：

* 報告生成器把日誌整理成可讀的攻擊摘要
* Dashboard 做視覺化統計，截圖放報告很好看


兩人中間傳的 JSON 格式

Layer 1 送出：
json

{
  "session_id": "abc123",
  "command": "cat /etc/passwd",
  "current_dir": "/etc",
  "user": "admin",
  "history": ["whoami", "ls -la", "cd /etc"]
}



Layer 2 回傳：
json

{
  "session_id": "abc123",
  "response": "root:x:0:0:root:/root:/bin/bash\n...",
  "intent": "reconnaissance",
  "confidence": 0.87
}

