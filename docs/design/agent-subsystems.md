# Agent 子系统设计(coland)

本文记录 Coland 当前 Agent participation、治理策略和通知子系统的实现边界。规范真源是
`arkret-spec/spec/v1`；本文只说明服务端内部结构。

设计原则：controller selection、Realm/Circle/Strand policy、capability 与生命周期是四个独立权威；
在执行动作时求交并逐项校验，不互相复制或物化。数据库直接采用当前 schema，不保留兼容层。

现状基线(已勘察):
- 事件提交:`routing/events/event_log.rs::submit_event_value` → `store.put(CanonicalEventRecord)` → `routing/events/projection.rs::project_accepted_operations_from_device` → `reducer.rs::ProjectionState::apply` 经 `APPLY_REGISTRY`(`kind → apply_*`)分发。
- reducer 范式:`apply_circle_update`(tighten-only floor + 字段 patch)、`apply_realm_policy_bundle`(floor ratchet + cell write `ak.component.realm.policy_bundle.v1`)。
- capability grant: 存于 cell `ak:cell:ak.component.capability.grant.v1:<capability_id>`，authz 经 durable current result 读取；Realm link 不传播 capability。
- 消息:`apply_message` 仅写 `MessageState`,无 fanout。
- 通知:**无** NotificationStore / fanout / mention→notification。mention 仅在 `wire_validators/mention.rs` + `routing/events/operations.rs::validate_mentions` 做语法校验。
- session:`routing/identity/auth.rs::authenticated_session` 直接验证 session grant + DPoP,成功后返回 SDK `DevLoginResponseBody`;无 `agent_key_proof`、无 `scope_details`。

---

## S0 — Controller selection

`PUT /_arkret/self/agents/{agent_id}/participation` 是 controller-only Account Authority 写入口。
请求体固定为 `{target_scope, selection, expected_version}`：首次写入使用 `expected_version=0`，
成功后该 agent/scope slot 的 version 加一；版本不一致返回 `cas_conflict`。

服务端以 bearer + DPoP session 证明 controller 身份，只保存 scope、version 与五个 selection bit。
该写入不创建 Event、不签发 receipt、不生成 capability，也不复制当前 Realm/Circle/Strand policy。
GET 返回每个 slot 的 `{target_scope, selection, version}`，供客户端诚实执行后续 CAS。

## S1 — Governance policy projection

Realm、Circle 与 Strand 的 `agent_participation.agent` 是 reducer 管理的治理策略。子级只能相对父级
tighten；放宽返回 `agent_participation_ceiling_widen`。投影层把当前策略写入
`agent_participation_ceiling`，读侧按目标 scope 求出当前最内层有效 policy。

治理 policy 与 controller selection 互不覆盖：policy 收紧不会改写 selection，后续放宽也不需要 controller
重新提交。执行时使用 `effective = selection ∩ current_target_policy`。

## S2 — Action-time authorization

每次 Agent 动作依次检查：

1. Agent lifecycle、membership 与 session/runtime key 状态；
2. 独立 capability/grant 是否允许该 action 与 resource；
3. 对应 participation bit 是否在 `selection ∩ current_target_policy` 中启用。

任何一项失败都拒绝动作。Participation 只是附加执行门，不签发、撤销或替代 capability。通知 fanout、
消息/Reaction 写入和 act-on-behalf 路径都复用同一 action-time resolver，不能信任客户端 session overlay
中复制的 effective 值。

---

## S3 — Notification fanout dispatcher(从零)

**目标**:消息创建时派生 per-recipient notification,应用既有覆盖规则 + **AKP-0016 §9.4.5 第三方 mention gate**,并推送给 floria。这是最大的新子系统;分阶段。

### 数据模型(直接建表)
新迁移列 / 表(改现有 `migrations` 下相关 up.sql;notification 属新表):
```sql
CREATE TABLE notification (
    notification_id   TEXT PRIMARY KEY,          -- ak:notification:<uuid>
    recipient_id      TEXT NOT NULL,             -- actor DID(可为 agent principal)
    realm_id          TEXT NOT NULL,
    source_event_id   TEXT NOT NULL,
    notification_kind TEXT NOT NULL,             -- mention | reply | assignment | reaction | watch
    reasons           JSONB NOT NULL DEFAULT '[]'::jsonb,  -- 合并的 reason set
    preview           JSONB,                     -- 按 history visibility 裁剪后的预览
    created_at        TIMESTAMPTZ NOT NULL,
    read_at           TIMESTAMPTZ
);
CREATE INDEX notification_recipient_idx ON notification(recipient_id, created_at DESC);
CREATE INDEX notification_source_idx ON notification(source_event_id);
```
`PushRuleStore` 补 SQL backing(当前仅内存)。新增 `NotificationStore`(trait + 内存 + Pg),接入 `PersistenceStore`(范式同 S 已建的 `AgentParticipationStore`)。

### Dispatcher
新文件 `routing/events/notify.rs`:
```rust
/// 在 MessageCreated 投影 effect 处理后调用。纯派生 + 落库 + 入队,不阻塞提交主路径
/// (best-effort,失败记 audit + metric,不回滚消息)。
pub(crate) async fn dispatch_message_notifications(
    state: &AppState,
    msg: &MessageState,           // 来自 ProjectionEffect::MessageCreated
) -> ();
```
流程:
1. **解析 target**:从 `msg.content.mentions[]` 提取 `subject_account_id`(direct,完整 `AccountId`,比较 MUST 覆盖 `principal_id` 与 `station_id` 两个分量)与 `audience_mention`(broadcast);从 Strand watch cell 提取 watcher(`ak.strand.watch.set` 已有投影)。
2. **逐 recipient gate**(顺序与 spec §9.4 覆盖序一致):
   - 去重:同 `(actor, source_event_id, type=mention)` 最多一条。
   - 发送者自我 mention 默认不通知。
   - `level=muted` / 个人 blocklist / DND / `dont_notify` push rule 覆盖。
   - **Agent 第三方 mention gate(AKP-0016 §9.4.5)**:若 recipient 经已验证的 Agent principal / accountability 历史证明为 Agent，且 mention 作者 ≠ 该 Agent 的 controller(经 `ak.identity.accountability_grant` 解析)且 effective `third_party_mention_delivery_allowed=false`(读 `agent_participation` selection ∩ `agent_participation_ceiling`,即复用 `resolve_effective_ceiling` + selection)→ **跳过该 recipient**,不写 notification、不入队。Actor Profile `actor_kind` 仅供显示，不参与该 gate。
3. **落库**:`NotificationStore::put`(合并 reason set;reply/assignment/reaction/watch 与 mention 命中同 recipient 时合并为单行)。
4. **入队 push**:对有 push device 的 recipient,构造 frame 调用既有 `routing/interop/push_outbound`(floria),受 `max_recipients` / rate-limit / review gate(audience mention)约束;不得先推后撤。

### 接入点
`routing/events/projection.rs` 处理 `ProjectionEffect::MessageCreated`(及 revise 的新增 mention)处,`spawn` 调 `dispatch_message_notifications`(或推入轻量队列 worker)。同一处也覆盖 `ak.message.revise` 仅对"新增 mention"派生(spec §9.4)。

### 读取 API
`GET /_arkret/self/notifications`(新 operation,后续补)读 `NotificationStore` 返回 recipient 的 inbox;agent runtime 经此 + `ak.self.committed_event.stream.subscribe.v1` 投影获得被允许的 mention。

### 验收
- alice @bob(普通)→ bob 收到 notification + push。
- carol @alice 的 agent,agent 在该 scope `third_party_mention_delivery_allowed=false` → agent **无** notification、无 subscribe 投影;`=true` → 有。
- controller alice @自己的 agent → 不受 gate(始终投递)。

---

## S4 — Agent session grant `scope_details.participation` overlay

**目标**:agent runtime 通过 `ak.session.grant` direct presentation 拿到 resolved 参与契约。当前 session-grant introspection outcome 需要覆盖 agent scope_details 与 agent_key_proof 分支。

### proof_kind 分支
`SessionGrantValidationInput.proof` 携带 `proof_kind` 所需证明；`agent_key_proof` 时走 agent 分支并携带 `agent_scope_request{realm_ids[], strand_ids[], track_names[]}`(`ak.profile.agent_auth.v1` overlay,见 AKP-0008 §4.6)。session-grant validation:
- `agent_key_proof`:校验 key 被 active 未撤销 `ak.agent.key.authorize` 授权 + challenge/audience/digest/nonce/expiry binding(AKP-0008 §4.6 校验链),不走 coauth human 分支;TTL ≤ 15min。
- 返回类型扩展:在 session-grant introspection outcome 中返回 `granted_scope[]` 与:

```jsonc
"scope_details": {
  "realm_ids": [...], "strand_ids": [...],
  "participation": [ { "participation_scope": {...}, "reply": true,
                      "third_party_mention_delivery_allowed": false, "acting_on_behalf_allowed": false } ]
}
```

### participation 解析
对 `agent_scope_request` 覆盖的每个 scope,复用 `agents.rs::resolve_effective_ceiling` + `AgentParticipationStore::list_selections`,算 effective = ceiling ∩ selection,填入 `scope_details.participation[]`(即把 `participation.get` 的解析逻辑抽成共享 fn,session 与 get 端点共用)。

### 防御纵深(已在 spec §7.3)
runtime 副本仅为主动遵守;硬边界仍是 S1 的 grant 校验(reply/aob)+ S3 的 dispatcher gate(mention)。session overlay 不是安全边界。

### 验收
- agent 以 `agent_key_proof` 换 session,响应 `scope_details.participation` 与 `participation.get` 一致;human 分支不受影响。

---

## 实施顺序与并行

```
S0(server_emit) ──► S1(grant 物化)         ┐
S2(ceiling reducer) ── 独立,依赖 S0 的 effect 落库范式 ─┤── 可与 S1 并行
S4(session overlay)── 依赖 participation 解析共享 fn(已存在) ── 独立可并行
S3(notification dispatcher)── 最大,独立子系统;mention gate 依赖 participation 读侧(已就绪)
```

- S1 + S2 + S4 较有界,优先;各自加 reducer/handler 单测 + coland 集成测试。
- S3 分两步:先 NotificationStore + mention 派生 + agent gate(本地可测),再 floria 推送联调。
- 每个子系统落地后回填 `_agents_todos.md` 对应项与 commit hash;cotest 真实联调在 S1–S4 就绪后统一跑。

## 与 spec 的关系
本设计是 coland 实现侧落点,不改协议语义;AKP-0016 与已 merge 的 normative 文本(capabilities §5.4、strand-and-message §9.4.5、realm-and-space §2、circle 字段表、private-objects §4.1)是真源。若实现中发现 spec 不完善,先改 spec 再改码。
