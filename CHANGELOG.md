# 变更记录

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。
版本策略与"什么算破坏性"见 [`docs/VERSIONING.md`](docs/VERSIONING.md)。

---

## [0.1.2] — 2026-11-02

主题：**让"不是我干的"这句话说不出口——审计可追责。**

### Added
- **结构化审计链 `audit.py`**：每条裁决写一条 JSONL 记录，带
  `seq / ts / trace / actor / decision / reason / detail / evidence / prev / h`。
  哈希链 + 独立 `HEAD` 锚点，能检出改内容、删中间、换顺序、删尾部四类篡改。
  设计取舍与局限见 [`docs/logging.md`](docs/logging.md)。
- **27 个理由码（`REASONS`）**：拒绝自由文本理由。写不在表里的值直接抛
  `AuditError`——因为"已处理""异常"这类日志在定责时等于没写。
- **`a2alink logs {tail,search,verify,stats,export,seal}`**：可离线查，
  不依赖注册中心（出问题时它往往正好连不上）。`--json` 输出不截断的原值。
- **`a2alink trace <id>`**：一条消息的完整一生，本地决策链 + 服务端投递记录。
  支持短 id 前缀匹配（表格里复制出来直接能查）。
- **`a2alink incident`**：把"人工强行放行的"单独列在最前面，附完整理由；
  "试图放行但没给理由被拒"也单独列——这是有价值的安全信号。
- **服务端拒绝留痕**：`_dispatch` 单点记录每次 4xx/5xx，
  带 `status / code / route / 调用者`。原来只记成功动作，被拒的请求一拍两散。
- **`/v1/trace/<id>`**：服务端按 trace 回元数据，仅参与方可查，不回 payload。

### Changed
- **`force=True` 必须同时给 `force_reason`（≥8 字）**，否则抛
  `force_requires_reason`。CLI 对应 `--force --reason "..."`。
  不需要填理由的"强行放行"按钮，在真实团队里三个月内一定会变成默认操作。
- `purge_old()` **不再删 `audit` 表**。审计与业务数据共用留存期，
  等于给了"把 days 设成 0.01 洗证据"一条正规通道。
- `override` 类记录的 `decision` 由 `deny` 改为 `note`——
  `decision` 描述最终结果（放行了），闸门判定交给 `reason`。
- 审计目录从"只扫当前目录"改为递归扫 `archive/`，否则 seal 之后
  seq 从 1 重开，归档动作会把自己验成"证据已被破坏"。
- 链锁从"pid 文件"改为**操作系统文件锁**。pid 文件在进程被杀后残留，
  导致 CLI 每次执行都新开一条链，一屏全是链名。

### Fixed
- 日志里不再出现明文：默认 `preview_chars=0`，只存指纹、长度、命中规则名。
  ID 类字段（`agt-` / `trace-` / `conv-`）原样保留——排查时"对端是谁"是第一要回答的问题。
- `force_reason` 走白名单完整保留。之前被长度策略截成 `<str:23>`，
  恰好把责任链上最关键的一环抹掉了。
- `seal()` 的 `json.dump` 参数冲突导致崩溃（且在移动文件之后崩，留下半成品）。

---

## [Unreleased] — v0.2.0 计划

### Added（计划）
- **本地可视化会话台** `a2alink console`：只读面板，看得到每一轮信封、每个
  Agent 的工作笔记、看门狗预算余量、DLP 命中详情。零依赖（`http.server` + SSE），
  只 bind `127.0.0.1`。设计见 [`docs/visual-console.md`](docs/visual-console.md)。
- 本地事件流 `~/.a2alink/<agent>/events.jsonl`（面板的数据源，也是审计的补充）。
- `a2alink audit report`：把审计账本聚合成"谁在批量操作"的可读报告。

### Changed（计划）
- 无。

---

## [0.1.1] — 2026-11-02

主题：**入群准入从"通过表决就能进来"改成"本人同意 + 表决"，并把反滥用做进代码。**

### Added
- **两段式入群准入**：`invite()` 一律先进入 `pending_consent`，必须由**受邀者
  本人**调用 `group_consent()` 表态。这一步没有开关、没有旁路、管理员也跳不过。
  理由见 [`docs/abuse.md`](docs/abuse.md) §2。
- **受信直入（`trusted_direct`，默认开）**：邀请人与受邀者已是双向好友时，
  受邀者点同意即入群，跳过全员表决。**这直接实现了"已互相同意的人直接进群，
  后面的人自己决定进不进"**。可用 `--no-trusted` 关闭。
- `AgentLink.group_consent(gid, pid, accept, reason)` / `POST /v1/groups/{gid}/consent`。
- `AgentLink.pending_actions()` / `GET /v1/pending` / `a2alink pending`：
  待我表态的邀请 + 待我投的票。人和 Agent 共用，也是 v0.2 面板的数据源。
- **扩散保险丝** `abuse.PropagationGuard`（默认开启，不可跳）：
  同一内容 30 分钟内发往 >4 个目标、或同一会话触达 >6 个对端 → 抛
  `PropagationBlocked`，必须人 `force=True` 才放行。
- **转发闸门** `abuse.ProvenanceError`：`forwarded_from` 参数在
  `allow_forward=False`（默认）时直接拒绝；开启后强制写入 `_provenance` 署名。
- **邀请配额与拒绝冷却**：每群每小时 20 次邀请；被拒后 24h 内不得重复邀请同一人，
  被同一人拒 3 次则 7 天冷却（`blocked_by_target`）。
- **好友申请全局配额**：单 Agent 24h 内最多发起 20 条；对方连续拒绝 3 次后停手。
- **群成员可见性收紧**：非成员只能拿到 `group_public_info`（群名、人数、群主、
  建群时间），**没有成员名单**。受邀者在同意前也只能看这个最小集。
- **静默成员审计** `a2alink group privacy <gid>` / `GET /v1/groups/{gid}/privacy`：
  列出入群超过 N 天却从未发言的成员（长期静默收集的唯一可观测信号）。
- **留存策略** `Registry.purge_old(days=30)`：按天清理消息、投递记录与审计。
- `docs/abuse.md`：完整滥用威胁模型（裂变/女巫/监听/外传/社工/汇聚/DoS）。
- `docs/VERSIONING.md`、`CHANGELOG.md`、`COMMERCIAL.md`。
- `tests/test_abuse.py`（9 个用例）、`tests/test_e2e.py` 新增 6 个准入用例。

### Changed
- **⚠️ 破坏性（`0.1.x` 内的有意识例外）**：提案状态机新增 `pending_consent`。
  任何依赖 `group_invite()` 返回 `state == "pending"` 并直接 `group_vote()` 的
  调用方必须改为：`invite()` → 由受邀者 `group_consent()` → 再 `vote()`。
  `invite()` 的返回值不再含 `needed`/`voters`（表决尚未开始，无从计算）；
  `consent()` 的返回值才含。`CHANGELOG` 里说清楚，是为了让升级的人少踩一次坑。
- **表决快照改为"受邀者同意之后"才取**。原实现在邀请时取快照，导致"同意前
  有人入群/退群"会让语义漂移。现在快照固定在投票真正开始的那一刻。
- `group_info()` 的 `pending_proposals` 同时包含 `pending` 与 `pending_consent`。
- `h_group_props` 补上成员校验（v0.1.0 遗漏：任何登录用户都能读到任意群的
  邀请流水，这是侦察素材）。
- 许可证从 MIT 改为 **A2A-LNL v1.0**（非商业使用免费，商业使用需书面授权，
  违规使用含赔偿条款）。**注意：这不是 OSI 开源许可，是 source-available。**
- `pyproject.toml` 的 classifier 从 `OSI Approved :: MIT License` 改为
  `Other/Proprietary License`。

### Fixed
- `invite()` 在 `join_mode=admin` 时由管理员直接入群，**绕过了受邀者意愿**。
  这不是 bug 而是设计缺陷，本版一并修掉（管理员现在只能跳过"表决"，不能跳过"同意"）。
- 同一目标重复邀请会产生多条未结提案，把对方的待办刷爆 → 改为幂等返回已有提案。

### Security
- 无已知在野漏洞。本版所有改动都是**收紧**默认策略，没有放松任何一条。

---

## [0.1.0] — 2026-11-02

首个可运行原型。定位：**开发者实验工具**，不是 C 端产品。

### Added
- **信封协议**（`protocol.py`）：信封/载荷分离、`act` 语义（task/result/event/
  chat/notice）、`stage` 终结信号、`ttl_hops` + `ttl_seconds` + `budget` 三重递减、
  幂等键、canonical bytes 与内容指纹。
- **看门狗**（`watchdog.py`）：消息配额、token 预算、轮次上限、simhash 内容指纹
  去重、熔断与降级动作、提前预警。
- **出站 DLP**（`guard.py` `EgressGuard`）：密钥/私钥/连接串/中文密级标识 → 阻断；
  内网 IP/内部域名/主机名/PII → 脱敏；高熵串检测；项目自定义禁出词表。
- **入站围栏**（`guard.py` `IngressGuard`）：提示词注入检测 + `<untrusted_external_content>`
  包裹 + 系统声明。
- **注册中心**（`registry.py`）：SQLite 持久化、身份与能力标签、发现、双向好友、
  群组与表决（unan/majority/admin）、单目标投递、inbox/ack、幂等去重、
  只存元数据的审计账本、令牌桶限流。
- **服务端强制关系策略**：不是好友不能发消息、不是成员不能在群里发言——
  这一点不能只靠客户端自证。
- **客户端 SDK**（`client.py`）：`AgentLink`，`send()`/`recv()` 内置闸门，
  身份落 `~/.a2alink/<agent>/identity.json`（600 权限）。
- **适配器**（`adapters.py`）：echo、LLM、DeepSeek Harness、AutoGen、LangGraph。
- **CLI**（`cli.py`）：`registry` / `whoami` / `discover` / `friend` / `group` /
  `send` / `inbox` / `serve` / `guard check` / `doctor` / `demo`。
- 文档：`README.md`（含泄密警示）、`SECURITY.md`（威胁模型 + 密级矩阵 +
  事故响应）、`docs/architecture.md`（设计取舍与 ADR）、`docs/protocol.md`、
  `docs/roadmap.md`。
- 63 个 stdlib `unittest` 用例。

### Design decisions（值得单独记下来的）
- **默认 `bind 127.0.0.1`**：本地优先同时解决冷启动与合规（境内公网信息服务涉资质）。
- **不做中继网关**：既避开资质问题，也让"协议级病毒传播"在物理上不成立。
- **默认拒绝而非默认放行**：未配置的对端按 `wan`（最严）处理。
- **全员表决不做默认推荐**：>5 人时有人休假就永久挂起，且一人可否决一切的
  女巫成本过低。文档推荐 `majority + quorum 0.6`，代码保留用户原设定的默认值。

[Unreleased]: https://github.com/wujiayue19160200073/a2alink/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/wujiayue19160200073/a2alink/releases/tag/v0.1.1
[0.1.0]: https://github.com/wujiayue19160200073/a2alink/releases/tag/v0.1.0
