# Coland contracts 类型所有权登记

本表记录阶段 0 及后续新增公共 DTO 的逐项审计。审计范围包括
`arkret-spec/spec/v1/artifacts`、`arkret-rust-sdk` 的公开 wire 类型以及真实跨仓消费者。
结论是：这些类型均未命中 Arkret spec wire 定义，属于部署本地的管理面或集成契约，
因此保留在 `coland-contracts`；没有需要迁回 SDK 的本地重复定义。

| 模块 | 类型 | 所有权 | 已确认消费者 | spec/SDK 对照结论 |
| --- | --- | --- | --- | --- |
| `admin::account_localparts` | `AccountLocalpartView` | local contract | Coland、Codmin | `/_coland/admin` 本地账号映射投影；未命中 spec wire 类型 |
| `admin::account_localparts` | `AccountLocalpartsView` | local contract | Coland、Codmin | 部署本地列表 envelope；未命中 spec wire 类型 |
| `admin::account_localparts` | `AccountLocalpartAddRequestBody` | local contract | Coland、Codmin | 部署本地管理命令；未命中 spec wire 类型 |
| `admin::account_localparts` | `AccountLocalpartUpdateResponseBody` | local contract | Coland、Codmin | 部署本地变更结果；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleView` | local contract | Coland、Codmin | 部署本地 handle 管理投影；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleAuditEvent` | local contract | Coland、Codmin | 部署本地 handle 审计投影；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandlePage` | local contract | Coland、Codmin | 部署本地 handle 列表 envelope；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleAuditPage` | local contract | Coland、Codmin | 部署本地 handle 审计列表 envelope；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleReassignBody` | local contract | Coland、Codmin | 部署本地 handle 管理命令；未命中 spec wire 类型 |
| `admin::handles` | `AdminHandleRevokeBody` | local contract | Coland、Codmin | 部署本地 handle 管理命令；未命中 spec wire 类型 |
| `admin::device_signing_directory` | `DeviceSigningKeyDirectoryQueryRequestBody` | local contract | Coland、Coauth | 产品间 signing-key directory 查询；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::device_signing_directory` | `AuthorizedDeviceSigningKey` | local contract | Coland、Coauth | 产品间 signing-key directory 投影；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::device_signing_directory` | `DeviceSigningKeyDirectoryView` | local contract | Coland、Coauth | 产品间 signing-key directory 响应；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::invite_tokens` | `AdminInviteTokenItem` | local contract | Coland、Codmin | Realm invite 状态的只读管理投影；DTO 整体未命中 spec wire 类型 |
| `admin::queries` | `AdminActor` | local contract | Coland、Codmin | `/_coland/admin` 操作面投影；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::queries` | `AdminActorList` | local contract | Coland、Codmin | `/_coland/admin` 操作面列表 envelope；未命中 spec wire 类型 |
| `admin::queries` | `AdminAuditEntry` | local contract | Coland、Codmin | `/_coland/admin` 操作面审计投影；未命中 spec wire 类型 |
| `admin::queries` | `AdminAuditList` | local contract | Coland、Codmin | `/_coland/admin` 操作面列表 envelope；未命中 spec wire 类型 |
| `admin::queries` | `CapabilityGrantState` | local contract | Coland、Codmin | `/_coland/admin` 操作面枚举；未命中 spec wire 类型 |
| `admin::queries` | `CapabilitySummary` | SDK re-export | Coland、Codmin | Alias of SDK CurrentCapabilityGrant; operator metadata review preserves full Actor/subject and durable revision, never substitutes the registered effective-grants authoring carrier. |
| `admin::queries` | `AdminCapabilityList` | local contract | Coland、Codmin | `/_coland/admin` 操作面列表 envelope；未命中 spec wire 类型 |
| `admin::queries` | `AdminDevice` | local contract | Coland、Codmin | `/_coland/admin` 操作面投影；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::queries` | `AdminDeviceList` | local contract | Coland、Codmin | `/_coland/admin` 操作面列表 envelope；未命中 spec wire 类型 |
| `admin::seal` | `NotaryKind` | local contract | Coland、Codmin | SDK 有领域 notary 值，但无此管理面投影视图 |
| `admin::seal` | `BottomKind` | SDK re-export | Coland、Codmin | 直接复用 `arkret-wire` 的规范枚举，不在本 crate 重复定义 |
| `admin::seal` | `BottomKindExt` | local pure helper | Coland、Codmin | 仅提供产品管理 UI 标签/解析辅助，不改变 SDK wire 枚举 |
| `admin::seal` | `AdminNotaryValue` | local contract | Coland、Codmin | 未命中 spec wire 类型 |
| `admin::seal` | `SubmitControlMoveOutcome` | local contract | Coland | Bottom repair 的部署本地结果；未命中 spec wire 类型 |
| `admin::seal` | `BottomCandidateHead` | local contract | Coland、Codmin | 未命中 spec wire 类型 |
| `admin::seal` | `BottomEntry` | local contract | Coland、Codmin | 未命中 spec wire 类型 |
| `admin::seal` | `BottomRepairStrategy` | local contract | Coland | 只描述部署本地恢复前置检查；未命中 spec wire 类型 |
| `admin::seal` | `BottomRepairRequestBody` | local contract | Coland | 只描述部署本地恢复前置检查；未命中 spec wire 类型 |
| `admin::seal` | `SealLeaf` | local contract | Coland、Codmin | 未命中 spec wire 类型 |
| `admin::seal` | `SealChainSnapshot` | local contract | Coland、Codmin | 未命中 spec wire 类型 |
| `admin::seal` | `SealPruneRequestBody` | local contract | Coland | 部署本地历史存储 GC；未命中 spec wire 类型 |
| `admin::seal` | `SealPruneOutcome` | local contract | Coland | 部署本地历史存储 GC；未命中 spec wire 类型 |
| `admin::seal` | `SealPruneDiagnostics` | local contract | Coland | 部署本地历史存储 GC；未命中 spec wire 类型 |
| `admin::seal` | `MultisigPendingEntry` | local contract | Coland、Codmin | 未命中 spec wire 类型 |
| `admin::seal` | `MultisigPendingOutcome` | local contract | Coland、Codmin | 未命中 spec wire 类型 |
| `admin::collection` | `RealmClass` | local contract | Coland、Codmin | `/_coland/admin` Realm 行内分类封闭枚举；未命中 spec wire 类型 |
| `admin::collection` | `AdminRealmItem` | local contract | Coland、Codmin | `GET /_coland/admin/{resource}`（realms）与 `/_coland/admin/realms/{realm_id}` 详情投影；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::collection` | `SpaceHealth` | local contract | Coland、Codmin | Space 容器生命周期封闭枚举；未命中 spec wire 类型 |
| `admin::collection` | `AdminSpaceView` | local contract | Coland、Codmin | `/_coland/admin/spaces` 集合行投影；未命中 spec wire 类型 |
| `admin::collection` | `AdminFederationOperation` | local contract | Coland、Codmin | `/_coland/admin/federation` 联邦操作行投影；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::collection` | `AdminMediaView` | local contract | Coland、Codmin | `/_coland/admin/media` 集合行投影；未命中 spec wire 类型 |
| `admin::media` | `AdminMediaBucket` | local contract | Coland、Codmin | `/_coland/admin/media/statistics` 聚合分桶；Codmin 经 `AdminMediaStatistics` 内嵌字段消费；未命中 spec wire 类型 |
| `admin::media` | `AdminMediaUsageView` | local contract | Coland、Codmin | `/_coland/admin/media/{statistics,by-actor}` 按上传者聚合行；Codmin 经 `AdminMediaStatistics`/`AdminMediaByActorList` 内嵌消费；未命中 spec wire 类型 |
| `admin::media` | `AdminMediaStatistics` | local contract | Coland、Codmin | `GET /_coland/admin/media/statistics` 响应；未命中 spec wire 类型 |
| `admin::media` | `AdminMediaByActorList` | local contract | Coland、Codmin | `GET /_coland/admin/media/by-actor` 列表 envelope；未命中 spec wire 类型 |
| `admin::media` | `MediaServiceFocus` | SDK contract | Coland、Codmin | 直接使用 `arkret-models-collaboration` 中 spec `event-payload.schema.json` `$defs/media_service_focus` 的唯一实现 |
| `admin::media` | `AdminRealmMediaService` | local contract | Coland、Codmin | `GET /_coland/admin/realms/{realm_id}/media-service` 只读投影；未命中 spec wire 类型 |
| `admin::policy` | `PolicyEffect` | SDK re-export | Coland、Codmin | 直接复用 `arkret-wire` 的规范枚举（spec `governance-objects.md` `default_effect` / `policy.schema.json` `$defs/policy_effect` 四值闭集 `allow`/`deny`/`quarantine`/`require_review`），不在本 crate 重复定义 |
| `admin::policy` | `AdminPolicyPayload` | local contract | Coland、Codmin | `/_coland/self/policies` 文档决策体；`resource` 永久为 opaque operator data，Codmin 不得解析或展示其子结构；approval evidence、audit 与 policy decision 只走既有 typed API；未命中 spec wire 类型 |
| `admin::policy` | `AdminPolicyDocument` | local contract | Coland、Codmin | `GET /_coland/self/policies` 文档投影；未命中 spec wire 类型 |
| `admin::policy` | `AdminPolicyDocumentPage` | local contract | Coland、Codmin | `GET /_coland/self/policies` 分页 envelope；未命中 spec wire 类型 |
| `admin::policy` | `UpsertPolicyDocumentRequestBody` | local contract | Coland、Codmin | `POST /_coland/self/policies` 部署本地管理命令；未命中 spec wire 类型 |
| `admin::server` | `AdminServerInfo` | local contract | Coland、Codmin | `GET /_coland/admin/server/info` 节点信息投影；未命中 spec wire 类型 |
| `admin::server` | `AdminServerStats` | local contract | Coland、Codmin | `GET /_coland/admin/server/stats` 计数快照；未命中 spec wire 类型 |
| `admin::server` | `AdminServerStatusCounts` | local contract | Coland、Codmin | Codmin 经 `AdminServerStatus.counts` 内嵌字段消费；未命中 spec wire 类型 |
| `admin::server` | `AdminServerStatus` | local contract | Coland、Codmin | `GET /_coland/admin/server/status` 可达性探针响应；未命中 spec wire 类型 |
| `admin::service_routes` | `AdminServiceRouteSummary` | local contract | Coland、Codmin | `GET /_coland/admin/service-routes` 列表行；Codmin 经 `AdminServiceRouteList` 内嵌消费；字段复用 SDK 类型，整体未命中 spec wire 类型 |
| `admin::service_routes` | `AdminServiceRouteList` | local contract | Coland、Codmin | `GET /_coland/admin/service-routes` 列表 envelope；未命中 spec wire 类型 |
| `admin::service_routes` | `AdminServiceMethodState` | local contract | Coland、Codmin | Codmin 经 `AdminServiceRouteDetail.method_state` 内嵌字段消费；未命中 spec wire 类型 |
| `admin::service_routes` | `AdminServiceRouteCurrent` | local contract | Coland、Codmin | Codmin 经 `AdminServiceRouteDetail.current_route` 内嵌字段消费；未命中 spec wire 类型 |
| `admin::service_routes` | `AdminServiceRouteCache` | local contract | Coland、Codmin | Codmin 经 `AdminServiceRouteDetail.cache` 内嵌字段消费；未命中 spec wire 类型 |
| `admin::service_routes` | `AdminServiceRouteQuarantine` | local contract | Coland、Codmin | Codmin 经 `AdminServiceRouteDetail.quarantine` 内嵌字段消费；未命中 spec wire 类型 |
| `admin::service_routes` | `AdminServiceRouteDetail` | local contract | Coland、Codmin | `GET /_coland/admin/service-routes/{service_id}/{service_kind}` 详情投影；字段复用 SDK 类型，整体未命中 spec wire 类型 |

| `account_projection` | `AccountProjectionRequestBody`, `AccountLocalpartsBaseUrlError` | local contract/helper | Coland、Coauth | Deployment-private Account Authority projection of an already verified binding; fields reuse SDK identifiers. The URL helper error is not a wire model. |
| `agent_session_authority` | `AgentSessionAuthorityRequest`, `AgentSessionAuthorityView` | local contract | Coland、Coauth | Deployment-private source-snapshot binding; SDK-owned scope and identity types are reused. This projection cannot independently authorize an Arkret operation. |
| `admin::queries` | `CurrentCapabilityGrant` | SDK re-export | Coland、Codmin | Original SDK public name behind `CapabilitySummary`; no local definition. |

若以后出现同名或等价的规范类型，必须先在 `arkret-rust-sdk` 实现，并用规范固定样例做
canonical JSON 字节对比，再从本表和 `coland-contracts` 删除相应本地契约。
