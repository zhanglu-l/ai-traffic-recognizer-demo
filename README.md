# AI Traffic Recognizer Demo

这是上一阶段的 AI 流量识别 Demo，已从 `agent-sample-lab` 拆出为独立目录。

## 目录

```text
ai-traffic-recognizer-demo/
├── docker-compose.yml       # 一键启动识别后端、SSH 蜜罐和可选攻击者
├── backend/
│   └── demo_server.py       # 页面服务、场景 API、LLM 代理
├── honeypot/
│   ├── Dockerfile
│   ├── honeypot_server.py   # 模拟 SSH 登录、命令响应和诱饵
│   └── data/                # 蜜罐事件 JSONL
├── tools/
│   ├── ai_attacker.py       # 模拟 AI Agent 攻击者
│   └── human_attacker.py    # 模拟非 AI / 人工攻击者
├── frontend/
│   └── AI流量识别Demo.html  # 单文件前端
└── samples/
    ├── sessions.jsonl       # SSH 蜜罐会话样本
    └── raw/                 # SSH 传感器事件
```

## 启动

```bash
cd "/Users/xiaoluer/Desktop/项目/xiaoluer/谛听/需求/05.AI 攻击识别/ai-traffic-recognizer-demo"
LLM_API_KEY=<your-api-key> DEMO_PORT=8000 python3 backend/demo_server.py
```

访问：

```text
http://127.0.0.1:8000
```

## 容器化蜜罐演示

在 shell 里设置 `LLM_API_KEY=<your-api-key>`，然后执行：

```bash
docker compose -f docker-compose.yml up --build backend ssh-honeypot
```

再开一个终端触发攻击者：

```bash
docker compose -f docker-compose.yml --profile demo run --rm ai-attacker
docker compose -f docker-compose.yml --profile demo run --rm human-attacker
```

如果本机 8000 端口被占用，可改用：

```bash
LLM_API_KEY=<your-api-key> DEMO_PORT=8201 docker compose up --build backend ssh-honeypot
```

访问 `http://127.0.0.1:8201`。

页面只保留两个核心对照场景：「SSH 蜜罐 · AI 诱导确认」和「SSH 蜜罐 · 人工排查」。选择场景后：

1. 页面每 5 秒轮询最新 SSH 蜜罐会话，规则层自动提取特征、聚合证据并显示 Prompt。
2. 页面提供「发起 AI 攻击」和「发起非 AI 攻击」按钮，后端串行执行对应模拟脚本。
3. 后端在「触碰诱饵 + 工具/MCP 执行」强信号出现，或会话静默超过 10 秒时自动调用 LLM 研判。
4. LLM 高置信度判定 AI 后自动启用拟态反制；前端展示自动研判结果和触发原因。
5. 「手动重新研判」和「手动启用 AI 反制」仅作为兜底入口。

每次重新攻击后，页面只显示每个类型最新的一次会话，历史会话不再进入演示列表。

### 攻击会话模板

`ai-attacker` 和 `human-attacker` 分别会从 `tools/profiles/ai_profiles.jsonl` 和 `tools/profiles/human_profiles.jsonl` 随机选择一个会话模板执行。每次仍会通过真实 SSH 蜜罐产生事件，LLM 研判输入依旧来自蜜罐事件链。

攻击器容器已设置 `pull_policy: build`，`docker compose run` 时会自动使用最新代码构建；终端会打印本次命中的 `profile_id`，页面顶部也会显示模板 ID 和任务名。随机选择不保证两次一定不同，可通过下面的 `ATTACK_PROFILE_ID` 固定复现。

如需复现某个模板，可设置 `ATTACK_PROFILE_ID`：

```bash
ATTACK_PROFILE_ID=ai_009 docker compose -f docker-compose.yml --profile demo run --rm ai-attacker
ATTACK_PROFILE_ID=human_001 docker compose -f docker-compose.yml --profile demo run --rm human-attacker
```

模板里的 AI / 人工标注只用于演示列表分组，不会写入 LLM Prompt。当前 AI 模板包含纯侦察、审计、诱饵读取和诱导工具执行等不同链路，并非所有 AI 会话都必须触碰诱饵。

蜜罐密码默认是 `root / admin123456`，仅用于本地演示。诱饵文件是模拟响应，不会创建真实凭据或外传数据。

## API

- `GET /healthz`
- `GET /api/scenarios`
- `POST /api/attacks/run`
- `GET /api/attacks/status`
- `POST /api/llm/prompt`
- `POST /api/llm/judge`

## 自动研判与反制

`/api/scenarios` 会先聚合 SSH 蜜罐会话，再按以下时机触发 LLM：

- 诱导确认同时出现「触碰诱饵」和「工具/MCP 执行」时立即研判。
- 会话出现工具回调时立即研判。
- 会话静默超过 `AUTO_JUDGE_IDLE_SECONDS`（默认 10 秒）时研判。
- 证据内容发生变化时重新研判；未变化时使用持久化缓存，避免重复调用。

LLM 返回 `ai` 且置信度不低于 `0.7` 时，默认自动创建拟态反制。可用环境变量调整：

```bash
AUTO_LLM_JUDGE=true
AUTO_COUNTERMEASURE=true
AUTO_JUDGE_IDLE_SECONDS=10
```
