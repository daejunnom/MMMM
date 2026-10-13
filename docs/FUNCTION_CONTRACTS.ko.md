# MMMM 함수 계약 · 입력/출력·효과·취소·재시도

계약판 0.2.0. 이 파일의 표는 `contracts/function-index.json`에서 생성한 구현 명세다. 실제 코드의 완료 목록이 아니다. input/output은 `contracts/mmmm.schema.json`의 `$defs` 이름이다. Rust 구현은 snake_case 메서드와 newtype ID를 사용하되 wire 의미는 유지한다.

## 전역 규칙

- 인증된 context는 서비스 경계에서 로드한다. 클라이언트가 보낸 principal, authority, policyRevision을 그대로 승인하지 않는다.
- `Result<T, DomainError>`는 dispatch 전 검증·순수 함수 실패에 사용한다. dispatch 후에는 ProviderResult/OperationReport로 알려진 effect와 불명을 반환한다.
- `pure`는 입력 미변경·I/O 없음. `staging/private_cache`는 사용자 원본·월드·외부 도구 미변경. `write`는 반드시 plan/apply 경로다.
- deadline은 기다림 한도이지 rollback 보장이 아니다. retry는 아래 계약의 범위만 허용한다.
- 의미 검증은 공통 라이브러리, 실제 target의 권한·상태·효과 관찰은 호스트/제공자다. 가짜 readback이 생성기와 같은 오류 구현을 공유하지 않게 한다.
- command cursor는 UTF-16 code unit 경계다. Rust byte offset과 직접 혼용하지 않는다. surrogate pair 중간은 거절한다.

## Rust 내부 port 형태

아래 서명은 역할 지시이며 제품 라이브러리의 현재 API가 아니다. DTO는 스키마에서 생성/검증하고 private handle은 wire로 직렬화하지 않는다.

```rust
// 대표 역할만 표시한다. 실제 타입은 계약 정본의 DTO + domain newtype이다.
pub trait DomainCompiler {
    fn compile(&self, request: &MathCompileRequest, target: &VerifiedTarget)
        -> Result<CompileFragmentDraft, DomainError>;
}
pub trait ProviderExecutor: Send + Sync {
    fn dispatch<'a>(&'a self, invocation: Invocation, cancel: CancelSignal)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = ProviderResult> + Send + 'a>>;
}
pub trait OperationJournal {
    fn reserve(&mut self, key: OperationKey, plan_hash: PlanHash)
        -> Result<Reservation, JournalError>;
    fn append_dispatch_intent(&mut self, intent: &DispatchIntent)
        -> Result<DurableReceipt, JournalError>;
}
```

`VerifiedTarget`은 문서에 버전 이름이 적혀 있다는 이유로 생성하지 않는다. 검사된 profile과 실제 실행 scope를 연결한다. `DurableReceipt` 뒤에만 dispatch하며 이 receipt 자체는 게임 변경 완료 증거가 아니다.

## 함수 목록

| ID | 함수 | 입력 → 출력 | 효과 | 첫 게이트 |
|---|---|---|---|---|
| FN01 | `project.inspect` | `ProjectQuery` → `ProjectView` | read | G1 |
| FN02 | `prefab.validate` | `Prefab` → `DiagnosticList` | pure | G0 |
| FN03 | `instance.instantiate` | `InstantiateRequest` → `InstanceDraft` | pure | G1 |
| FN04 | `instance.clone` | `CloneRequest` → `InstanceDraft` | pure | G1 |
| FN05 | `instance.relocate` | `RelocateRequest` → `InstanceDraft` | pure | G1 |
| FN06 | `command.layout` | `CommandLayoutRequest` → `CommandModule` | pure | G3 |
| FN07 | `math.compile` | `MathCompileRequest` → `CompileFragment` | staging | G3 |
| FN08 | `clip.retime` | `RetimeRequest` → `AnimationClip` | pure | G3 |
| FN09 | `plan.create` | `CreatePlanRequest` → `ExecutionPlan` | private_cache | G1 |
| FN10 | `plan.inspect` | `PlanQuery` → `ExecutionPlan` | read | G1 |
| FN11 | `plan.apply` | `ApplyRequest` → `OperationReport` | write | G1 |
| FN12 | `operation.get` | `OperationQuery` → `OperationReport` | read | G1 |
| FN13 | `operation.cancel` | `OperationQuery` → `OperationReport` | write | G1 |
| FN14 | `operation.reconcile` | `OperationQuery` → `OperationReport` | read_and_journal | G1 |
| FN15 | `recovery.plan` | `RecoveryRequest` → `ExecutionPlan` | private_cache | G1 |
| FN16 | `providers.discover` | `DiscoveryRequest` → `ProviderInventory` | private_cache | G1 |
| FN17 | `route.resolve` | `RouteRequest` → `RouteResolution` | pure | G1 |
| FN18 | `provider.invoke` | `Invocation` → `ProviderResult` | declared_by_action | G2 |
| FN19 | `compatibility.bind` | `CompatibilityBindRequest` → `ProviderDescriptor` | private_cache | G1 |
| FN20 | `catalog.search` | `CatalogQuery` → `CatalogPage` | read | G1 |
| FN21 | `catalog.describe` | `RecordQuery` → `DataRecord` | read | G1 |
| FN22 | `catalog.capture` | `SnapshotRequest` → `DataSnapshot` | private_cache | G2 |
| FN23 | `world.shape_query` | `ShapeQueryContext` → `ShapeResult` | read | G2 |
| FN24 | `exchange.prepare` | `ExchangeBuildRequest` → `SceneExchangeManifest` | staging | G3 |
| FN25 | `exchange.inspect` | `ArtifactQuery` → `BundleInspection` | read | G3 |
| FN26 | `bake.plan` | `BakePlanRequest` → `ExecutionPlan` | private_cache | G3 |
| FN27 | `bake.ingest` | `BakeIngestRequest` → `BakeArtifact` | staging | G3 |
| FN28 | `scene.diff` | `SceneImportRequest` → `ScenePatch` | pure | G3 |
| FN29 | `scene.plan` | `ScenePlanRequest` → `ExecutionPlan` | private_cache | G3 |
| FN30 | `pack.build` | `BuildRequest` → `ExportManifest` | staging | G3 |
| FN31 | `artifact.read` | `ArtifactReadRequest` → `ArtifactSlice` | read | G1 |
| FN32 | `command.complete` | `CompleteRequest` → `CommandSuggestions` | read | G2 |
| FN33 | `action.read` | `RegisteredActionRequest` → `ProviderResult` | declared_read | G2 |
| FN34 | `action.plan` | `RegisteredActionRequest` → `ExecutionPlan` | private_cache | G2 |
| FN35 | `dependency.admit` | `AdmissionRequest` → `AdmissionDecision` | pure | G0 |
| FN36 | `release.evaluate` | `ReleaseEvidence` → `GateReport` | pure | G4 |

## FN01 · `project.inspect`

구현 소유: **application**. 입력 `ProjectQuery`, 출력 `ProjectView`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | project root 권한; 요청 revision 또는 현재 revision 존재 |
| 후행조건 | 같은 revision의 요약과 불명 참조 반환; live 상태와 authoring revision 구분 |
| 부작용 | read |
| 오류 | `NOT_FOUND`, `REVISION_CONFLICT` |
| 취소 | 읽기 중단, 쓰기 없음 |
| 재시도 | 같은 snapshot 읽기만 재시도 |

## FN02 · `prefab.validate`

구현 소유: **domain**. 입력 `Prefab`, 출력 `DiagnosticList`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | bounded DTO 파싱 완료 |
| 후행조건 | 중복/parent 순환/참조/type 규칙의 진단; 입력 미변경 |
| 부작용 | pure |
| 오류 | `SCHEMA_INVALID` |
| 취소 | 효과 없이 중단 가능 |
| 재시도 | 결정적 |

## FN03 · `instance.instantiate`

구현 소유: **domain**. 입력 `InstantiateRequest`, 출력 `InstanceDraft`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | definition 의미 유효; 호출자가 미사용 instanceId 할당; 지원되는 placement |
| 후행조건 | authoring 초안만 생성; runtime UUID/실제 world는 아직 없음 |
| 부작용 | pure |
| 오류 | `ID_COLLISION`, `UNSUPPORTED_TRANSFORM` |
| 취소 | 효과 없이 중단 |
| 재시도 | 동일 ID/입력은 동일 의미 초안 |

## FN04 · `instance.clone`

구현 소유: **domain**. 입력 `CloneRequest`, 출력 `InstanceDraft`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | source prefab revision 일치; 독립 ID; explicit_snapshot 요청이면 참조 존재 |
| 후행조건 | local refs 재연결; project/external refs와 공유 정책 보존; 정책에 따른 state 초기화 |
| 부작용 | pure |
| 오류 | `REVISION_CONFLICT`, `STATE_SNAPSHOT_REQUIRED`, `REFERENCE_UNRESOLVED` |
| 취소 | 효과 없이 중단 |
| 재시도 | 할당 ID를 입력에 고정 |

## FN05 · `instance.relocate`

구현 소유: **domain**. 입력 `RelocateRequest`, 출력 `InstanceDraft`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 참조 의미를 알 수 있음; placement 변환 가능 |
| 후행조건 | 로컬 구조·포트·참조 이동 초안; 외부 목적지 유지 |
| 부작용 | pure |
| 오류 | `OPAQUE_RELOCATION`, `NONINVERTIBLE_TRANSFORM` |
| 취소 | 효과 없이 중단 |
| 재시도 | 결정적 |

## FN06 · `command.layout`

구현 소유: **domain**. 입력 `CommandLayoutRequest`, 출력 `CommandModule`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 체인 관계와 조건 원본 확인; target state 변환 규칙 |
| 후행조건 | rack/embedded 배치 계산; next와 conditionSource 관계 보존; 초안은 비활성 |
| 부작용 | pure |
| 오류 | `CHAIN_CYCLE`, `CONDITION_SOURCE_MISMATCH`, `UNSUPPORTED_TARGET_VERSION` |
| 취소 | 효과 없이 중단 |
| 재시도 | 결정적 |

## FN07 · `math.compile`

구현 소유: **compiler**. 입력 `MathCompileRequest`, 출력 `CompileFragment`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 타입/단위/연산 DAG 유효; profile에서 op 지원; symbolTable 읽기 허용 |
| 후행조건 | 소스/명령 조각과 defined/referenced 목록 반환; 게임 미실행 |
| 부작용 | staging |
| 오류 | `UNIT_MISMATCH`, `NUMERIC_RANGE`, `UNSUPPORTED_OPERATOR` |
| 취소 | staging만 폐기 가능 |
| 재시도 | input/target/compiler digest로 재사용 |

## FN08 · `clip.retime`

구현 소유: **domain**. 입력 `RetimeRequest`, 출력 `AnimationClip`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | duration>0; event 정책과 끝 범위 유효 |
| 후행조건 | 새 시간/동일 stable IDs; event 순서/hold/종료 보존 |
| 부작용 | pure |
| 오류 | `INVALID_TIME`, `EVENT_OUT_OF_RANGE` |
| 취소 | 효과 없이 중단 |
| 재시도 | 결정적 |

## FN09 · `plan.create`

구현 소유: **application**. 입력 `CreatePlanRequest`, 출력 `ExecutionPlan`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | context/grant/target policy; expected project revision; 변경 intent 유효 |
| 후행조건 | 고정 action/implementation/context/dependency pins; scope와 loss/승인 표시; 사용자/월드 미변경 |
| 부작용 | private_cache |
| 오류 | `STALE_CONTEXT`, `REVISION_CONFLICT`, `CAPABILITY_UNAVAILABLE`, `LOSS_APPROVAL_REQUIRED` |
| 취소 | 계획 폐기; live 효과 없음 |
| 재시도 | 새 ID 가능; 같은 intent 의미 유지 |

## FN10 · `plan.inspect`

구현 소유: **application**. 입력 `PlanQuery`, 출력 `ExecutionPlan`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | principal이 plan을 읽을 권한 |
| 후행조건 | 저장된 plan 반환; 동적으로 provider 변경 안 함 |
| 부작용 | read |
| 오류 | `PLAN_NOT_FOUND`, `PERMISSION_REQUIRED` |
| 취소 | 읽기만 |
| 재시도 | 동일 plan |

## FN11 · `plan.apply`

구현 소유: **application**. 입력 `ApplyRequest`, 출력 `OperationReport`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | hash/expiry/context/policy pins 일치; idempotency reserve; target precondition 재확인 |
| 후행조건 | dispatch 이전 durable 기록; 요구 검증 수준만 완료 표시; 기존 key 재호출은 같은 operation |
| 부작용 | write |
| 오류 | `STALE_PLAN`, `TARGET_DRIFT`, `IDEMPOTENCY_CONFLICT`, `OUTCOME_UNKNOWN` |
| 취소 | 취소 요청과 실제 중단 구분 |
| 재시도 | dispatch 후 맹목 재시도 금지 |

## FN12 · `operation.get`

구현 소유: **runtime**. 입력 `OperationQuery`, 출력 `OperationReport`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 원장 접근 권한 |
| 후행조건 | 현재 증거와 불명 상태 반환; 조회만으로 재실행 없음 |
| 부작용 | read |
| 오류 | `OPERATION_NOT_FOUND` |
| 취소 | 읽기만 |
| 재시도 | 같은 op 조회 |

## FN13 · `operation.cancel`

구현 소유: **application**. 입력 `OperationQuery`, 출력 `OperationReport`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 작업 소유권/관리 권한; 제공 취소 능력 확인 |
| 후행조건 | queued 취소 또는 cancel_requested; 효과/미확인 유지 |
| 부작용 | write |
| 오류 | `CANCEL_UNSUPPORTED`, `PERMISSION_REQUIRED` |
| 취소 | 본 작업이 취소 요청 |
| 재시도 | 같은 요청 idempotent, 완료 보장 아님 |

## FN14 · `operation.reconcile`

구현 소유: **application**. 입력 `OperationQuery`, 출력 `OperationReport`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 불명/진행 중 op; 같은 binding/job/관찰 대상 식별 |
| 후행조건 | 실제 관찰로 증거 보완; 다른 provider로 write 재발행 안 함 |
| 부작용 | read_and_journal |
| 오류 | `STALE_CONTEXT`, `RECONCILIATION_INSUFFICIENT` |
| 취소 | 조회만 중지; 원 effect 잔존 |
| 재시도 | 조회 재시도 가능 |

## FN15 · `recovery.plan`

구현 소유: **application**. 입력 `RecoveryRequest`, 출력 `ExecutionPlan`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 기록된 direct 변화/유효 undo token; 현재 상태가 after와 일치 |
| 후행조건 | 새 복구 plan; 간접 효과의 복구를 약속하지 않음 |
| 부작용 | private_cache |
| 오류 | `RECOVERY_CONFLICT`, `RECOVERY_EXPIRED` |
| 취소 | 실행 전 중단 가능 |
| 재시도 | 새 관찰로 재계획 |

## FN16 · `providers.discover`

구현 소유: **adapters**. 입력 `DiscoveryRequest`, 출력 `ProviderInventory`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 이미 연결된 environment; 정책 허용; allowEffects=false |
| 후행조건 | feature별 availability; 등록 출처/검증 수준 보존; 자동 설치 없음 |
| 부작용 | private_cache |
| 오류 | `STALE_CONTEXT`, `INCOMPATIBLE_CONTRACT` |
| 취소 | 조회 중지; mod unload 아님 |
| 재시도 | inventory 갱신 |

## FN17 · `route.resolve`

구현 소유: **runtime**. 입력 `RouteRequest`, 출력 `RouteResolution`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 고정 inventory; 필요 guarantees와 side |
| 후행조건 | 선택 binding과 digest 또는 unavailable; 강제 preferred가 불충족이면 자동 대체 안 함 |
| 부작용 | pure |
| 오류 | `INVENTORY_STALE`, `CAPABILITY_UNAVAILABLE` |
| 취소 | 효과 없음 |
| 재시도 | 같은 inventory 결정적 |

## FN18 · `provider.invoke`

구현 소유: **adapters**. 입력 `Invocation`, 출력 `ProviderResult`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | Coordinator가 만든 invocation; actual principal 권한; binding/implementation digest |
| 후행조건 | 자체 handler 보고만 반환; job_accepted는 jobHandle 필요 |
| 부작용 | declared_by_action |
| 오류 | `OUTPUT_INVALID`, `PROVIDER_DISCONNECTED`, `DEADLINE_EXCEEDED` |
| 취소 | 선언한 취소 능력만 |
| 재시도 | provider-keyed 범위만 |

## FN19 · `compatibility.bind`

구현 소유: **adapters**. 입력 `CompatibilityBindRequest`, 출력 `ProviderDescriptor`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | profile 승인 digest; 현재 interface match; 정적 public signature 확인 |
| 후행조건 | same ActionDescriptor; 사용 불가 이유 명시; 새 클래스 초기화/명령 실행 없음 |
| 부작용 | private_cache |
| 오류 | `PROFILE_UNTRUSTED`, `UNSUPPORTED_BINDING`, `INTERFACE_MISMATCH` |
| 취소 | 효과 없이 중지 |
| 재시도 | 같은 profile/environment 고정 |

## FN20 · `catalog.search`

구현 소유: **reference**. 입력 `CatalogQuery`, 출력 `CatalogPage`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | snapshot 존재; query 권한/limit/cursor 일치 |
| 후행조건 | snapshot 고정 page; 모름/누락을 값으로 바꾸지 않음 |
| 부작용 | read |
| 오류 | `STALE_CURSOR`, `SNAPSHOT_NOT_FOUND` |
| 취소 | 읽기만 |
| 재시도 | 동일 snapshot page |

## FN21 · `catalog.describe`

구현 소유: **reference**. 입력 `RecordQuery`, 출력 `DataRecord`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | record scope 읽기 권한 |
| 후행조건 | known/absent/unknown/unsupported/requires_runtime; 출처/단위/coverage 포함 |
| 부작용 | read |
| 오류 | `SNAPSHOT_NOT_FOUND`, `PERMISSION_REQUIRED` |
| 취소 | 읽기만 |
| 재시도 | 동일 snapshot |

## FN22 · `catalog.capture`

구현 소유: **reference**. 입력 `SnapshotRequest`, 출력 `DataSnapshot`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | approved source roots/runtime connection; no implicit mutation |
| 후행조건 | 새 immutable snapshot; source hashes/pack order/side; 로드 안 된 영역은 unknown |
| 부작용 | private_cache |
| 오류 | `SOURCE_UNAVAILABLE`, `SCHEMA_UNSUPPORTED`, `PERMISSION_REQUIRED` |
| 취소 | partial snapshot coverage 명시 |
| 재시도 | 새 snapshot 가능 |

## FN23 · `world.shape_query`

구현 소유: **reference**. 입력 `ShapeQueryContext`, 출력 `ShapeResult`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 게임 context/loaded region; position/state/neighbors/entity context 일치 |
| 후행조건 | queryDigest/observation window; unsupported를 empty geometry로 반환 안 함 |
| 부작용 | read |
| 오류 | `STALE_CONTEXT`, `SIDE_MISMATCH`, `TARGET_DRIFT` |
| 취소 | 실제 조회만 중단 |
| 재시도 | 문맥 갱신하면 다른 결과 가능 |

## FN24 · `exchange.prepare`

구현 소유: **exchange**. 입력 `ExchangeBuildRequest`, 출력 `SceneExchangeManifest`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 선택/source refs 고정; 단위와 자산 사용 범위; physics 있으면 관계 유효 |
| 후행조건 | 중립 manifest/payload만 작성; 모델러 이름 무관; 사용자 원본 미변경 |
| 부작용 | staging |
| 오류 | `REFERENCE_UNRESOLVED`, `UNIT_MISMATCH`, `RESOURCE_FORBIDDEN` |
| 취소 | staging 정리 |
| 재시도 | 내용 hash 재사용 |

## FN25 · `exchange.inspect`

구현 소유: **exchange**. 입력 `ArtifactQuery`, 출력 `BundleInspection`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | authorized resource; archive/size/path limits |
| 후행조건 | 모든 payload digest/ID/권리/loss 확인; 임의 tool 실행 안 함 |
| 부작용 | read |
| 오류 | `ARCHIVE_INVALID`, `RESOURCE_HASH_MISMATCH`, `UNSUPPORTED_FORMAT` |
| 취소 | 읽기 중지 |
| 재시도 | 같은 bytes 재시도 |

## FN26 · `bake.plan`

구현 소유: **application**. 입력 `BakePlanRequest`, 출력 `ExecutionPlan`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | source/physics pins; external context 권한; 필요 capability |
| 후행조건 | 외부 작업 scope와 output budget 고정; game 설치는 별도 plan |
| 부작용 | private_cache |
| 오류 | `CAPABILITY_UNAVAILABLE`, `BUDGET_EXCEEDED`, `LOSS_APPROVAL_REQUIRED` |
| 취소 | 실행 전 중단 |
| 재시도 | 새 plan |

## FN27 · `bake.ingest`

구현 소유: **exchange**. 입력 `BakeIngestRequest`, 출력 `BakeArtifact`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 결과 bytes hash; request ID/input digest 일치; 좌표/샘플/위상 검증 |
| 후행조건 | 검증된 부분과 미확인 구분; 실시간 solver로 오표시 안 함 |
| 부작용 | staging |
| 오류 | `INPUT_DIGEST_MISMATCH`, `TOPOLOGY_CHANGED`, `INCOMPLETE_OUTPUT` |
| 취소 | staging 중지 |
| 재시도 | 동일 result 검사 |

## FN28 · `scene.diff`

구현 소유: **exchange**. 입력 `SceneImportRequest`, 출력 `ScenePatch`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | stable ID 매핑; base revision; 허용 loss |
| 후행조건 | 명시적인 생성/수정/삭제; 누락 필드는 유지; target world 미변경 |
| 부작용 | pure |
| 오류 | `OBJECT_MAPPING_AMBIGUOUS`, `REVISION_CONFLICT` |
| 취소 | 효과 없음 |
| 재시도 | 결정적 |

## FN29 · `scene.plan`

구현 소유: **application**. 입력 `ScenePlanRequest`, 출력 `ExecutionPlan`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | base snapshot/context; ScenePatch 의미 유효 |
| 후행조건 | 일반 plan invariants 사용; 외부 결과로 권한 확대 안 함 |
| 부작용 | private_cache |
| 오류 | `STALE_PLAN`, `LOSS_APPROVAL_REQUIRED` |
| 취소 | 실행 전 |
| 재시도 | 재계획 |

## FN30 · `pack.build`

구현 소유: **compiler**. 입력 `BuildRequest`, 출력 `ExportManifest`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 현재 source revision/target version; target compiler 지원; dependency pins |
| 후행조건 | generated/reference/entry/symbol/source map 목록; pack install/reload는 미수행 |
| 부작용 | staging |
| 오류 | `UNSUPPORTED_TARGET_VERSION`, `REFERENCE_UNRESOLVED`, `UNOWNED_REQUIRED_CAPABILITY` |
| 취소 | staging cooperative stop |
| 재시도 | input/compiler digest 동일시 재사용 |

## FN31 · `artifact.read`

구현 소유: **runtime**. 입력 `ArtifactReadRequest`, 출력 `ArtifactSlice`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | resource ACL; offset/limit; digest 고정 |
| 후행조건 | bounded slice; UTF8 경계 또는 base64 명시; secret 경로 미노출 |
| 부작용 | read |
| 오류 | `RESOURCE_FORBIDDEN`, `RANGE_INVALID` |
| 취소 | 읽기만 |
| 재시도 | 동일 bytes |

## FN32 · `command.complete`

구현 소유: **application**. 입력 `CompleteRequest`, 출력 `CommandSuggestions`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 실제 executor/side/source 권한; cursor가 UTF16 코드포인트 경계 |
| 후행조건 | 기존 tree 제안; replacement span UTF16; 실행/설정 변경 없음 |
| 부작용 | read |
| 오류 | `CURSOR_INVALID`, `CONTEXT_REQUIRED`, `SIDE_MISMATCH` |
| 취소 | 읽기 중지 |
| 재시도 | tree/context 바뀌면 새 결과 |

## FN33 · `action.read`

구현 소유: **application**. 입력 `RegisteredActionRequest`, 출력 `ProviderResult`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 등록 action effect=read; schema/context/policy; 별도 승인된 read 범위 |
| 후행조건 | 실제 input/output schema 검증; 응답은 provider 보고 |
| 부작용 | declared_read |
| 오류 | `EFFECT_MISMATCH`, `OUTPUT_INVALID` |
| 취소 | 제공자 범위 |
| 재시도 | 정해진 read backoff만 |

## FN34 · `action.plan`

구현 소유: **application**. 입력 `RegisteredActionRequest`, 출력 `ExecutionPlan`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | write/unknown effect 명시; scope/approval requirement |
| 후행조건 | opaque 또는 typed action을 pinned plan화; 직접 실행하지 않음 |
| 부작용 | private_cache |
| 오류 | `UNKNOWN_CAPABILITY`, `PERMISSION_REQUIRED` |
| 취소 | 실행 전 |
| 재시도 | 재계획 |

## FN35 · `dependency.admit`

구현 소유: **runtime**. 입력 `AdmissionRequest`, 출력 `AdmissionDecision`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 실제 source/license/transitive 정보; 채택할 contract/version 범위 |
| 후행조건 | admit/rust_own/external_only/defer/reject; Rust 언어 이유의 예외 없음 |
| 부작용 | pure |
| 오류 | `EVIDENCE_MISSING` |
| 취소 | 효과 없음 |
| 재시도 | 동일 evidence 결정적 |

## FN36 · `release.evaluate`

구현 소유: **xtask**. 입력 `ReleaseEvidence`, 출력 `GateReport`.

| 계약 항목 | 구현 요구 |
|---|---|
| 선행조건 | 실제 시험 증거 refs와 artifact inventory |
| 후행조건 | 미실행과 실패 분리; v1 domain vendor 존재면 차단; specification_only는 release 승인 금지 |
| 부작용 | pure |
| 오류 | `RELEASE_EVIDENCE_INVALID` |
| 취소 | 효과 없음 |
| 재시도 | 동일 evidence 결정적 |

## 공급자 핸들러와 호스트 함수

Java SDK의 registrar는 ActionDescriptor와 handler를 등록한다. handler는 Invocation/LocalContext를 받고 CompletionStage<ProviderResult>를 반환한다. 결과가 job이면 jobHandle을 반환하며 완료는 별도 관찰한다. 선택 callback: pure prepare, operation.get, cooperative cancel, recovery prepare. 제공자가 callback을 제공하지 않으면 지원 없음으로 등록한다.

호스트 hello/inventory/describe/inspect/prepare/dispatch/operation.get/operation.cancel/events.since는 `HostRequest`/`HostResponse` 프레임을 쓴다. dispatch payload는 Invocation, completion payload는 ProviderResult를 선택해 검증한다. generic payload가 있다고 임의 메서드 실행을 허용하지 않는다.

## 구현별 계약 인수

함수 ID가 아니라 **기능 의미 계약** 단위로 구현체를 대체한다. temporary vendor가 FN30의 일부만 맡으면 parser/export/resource 통과 경로를 구체적인 contract ID로 분리한다. 새 Rust 구현의 성공·오류·숫자·취소·상태 소유 의미가 모두 동등하거나 명시된 승인 변경이어야 switched/retired로 이동한다. 허용되지 않는 upstream 버그는 복제하지 않고 별도 수정 증거를 남긴다.
