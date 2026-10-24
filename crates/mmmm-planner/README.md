# MMMM 불변 작성 계획 준비

이 crate는 원본 `CreatePlanRequest`와 `ChangeIntent`를 공통
`mmmm_application::PlanningPort`의 `PreparedPlan`으로 준비한다. 실행, 작업 원장,
승인, 재시도 판단과 복구 상태는 공통 Application이 소유한다. 계획 준비는 문서와
CAS 읽기, 순수 변환, 비공개 자료 staging만 수행한다.

`NativePlanner<'a>`는 요청 동안 소유 저장소를 빌리는 `ProjectSourcePort`와 실제
환경 관측을 제공하는 `PlanningEnvironmentPort`를 받는다. `inspect_project`의
문서 읽기는 현재 `ReadProject` 권한으로 수행하며 게임 `ExecutionContext`를
만들지 않는다. 계획의 읽기는 실제 context, principal, Project revision에
귀속된다. 각 owned 문서와 resource 읽기에 남은 byte 예산을 전달한다.

`ProjectCatalog`는 원본 Project의 `(kind, objectId, revision)`을 색인한다. 현재
목록은 역사 revision 읽기 권한의 증명이 아니므로 source 구현이 저장된 소유
기록과 현재 ACL을 확인해야 한다. Prefab, Instance, CommandModule,
AnimationClip, Asset, PhysicsDefinition을 원본 정의로 검증하며 실제 projected
digest를 비교한다.

지원되는 intent의 작성 준비는 다음과 같다.

- instantiate와 clone은 새 Instance를 만들며 명시적 상태 복제는 독립 관측
  snapshot의 정확한 source/actor/scope pin을 요구한다.
- relocate와 display patch는 선택 Instance만 변경하며 원본 raw command text를
  다시 쓰지 않는다. command relocation은 실제 환경의 명시적 지원을 요구한다.
- command module과 scene 구조 patch는 선택 Instance용 불변 Prefab/module/clip/
  physics variant를 만들고 그 Instance만 새 pin에 연결한다. 공유 원본은 계속
  소유 자료로 보존된다. 활성 그래프는 Instance의 정확한 Prefab pin에서 해석한다.
- clip retime은 원본 시간 계약과 event policy로 새 revision을 만든다.
- pack build는 실제 verified compiler target과 전체 owned source를 받으며 sealed
  scene/animation backend가 포함된 `PackBuildInputs`를 요구한다. 결과는 private
  staging 자료이며 설치나 reload를 수행하지 않는다.
- resource patch는 target identity를 유지하고 실제 이전 자료와 교체 source의
  CAS bytes를 고정한다.
- scene baked clip attachment는 `IngestedBake`의 sealed canonical clips와 exact
  resource bytes를 소비한다. 원본 artifact/source-map provenance와 좌표 정규화
  digest를 함께 유지한다. 원시 ScenePatch나 clip ID가 bake 검증 권한을 만들지 않는다.
- external action은 exact registered binding/action digest와 실제 footprint를
  사용한다. opaque assembly는 provider preview를 호출하지 않는다.
- recovery는 공통 Application의 보존된 before→after chain만 사용한다. 현재 after
  digest와 보존 scope가 같아야 하며 새 작업 원장을 만들지 않는다.

native 계획은 하나의 frozen composite action을 선택한다. 전체
`PreparedNativeChange`는 8 MiB 이내 정본 DTO `{change: ...}` JSON으로 private CAS에
저장하고, 원본 `Invocation.arguments`에는 `{preparedChange: ResourceRef}`만
넣는다. `native_action_input_schema()`는 작은 registered input schema,
`prepared_native_change_schema()`는 CAS 내부 자료 schema다.
`PreparedNativeChange::from_payload`는 shape와 typed identity/revision을 검증한다.
이 함수 호출만으로 source 권한이나 native 관측이 인증되지는 않는다.
CAS 저장에는 `encode_json`을 사용해 원본 finite float의 wire 표기를 보존한다.
JCS와 projected digest는 별도 계산하며 저장 codec을 대체하지 않는다.

독립 target snapshot은 정확한 raw before bytes, context digest, 완전한 write scope,
projection digest 및 실제 관측 대상 목록을 제공해야 한다. 대상 키는 같은 step의
`resourcesWritten`과 full-target precondition에 들어간다. block geometry 범위는
순수 변환으로 추가 검사하고, display/model/rack/physics footprint는 실제 native
codec의 complete projection witness를 요구한다. projected 객체 revision과 raw
target byte hash를 혼동하지 않는다.

실제 composition은 durable dispatch 이후 Rust에서 native engine instruction을
낮추고, 실제 세계 변경 및 독립 확인을 수행한 뒤 동일 invocation 안에서 canonical
Project·owned 문서·resource pin을 원자적으로 저장해야 한다. 최종 독립 readback은
세계와 작성 저장소를 모두 확인해야 한다. Project head 변경 뒤 후속 step을 두거나
revision 검사를 우회하는 경로는 없다. Java 호스트는 낮춰진 engine spec을 적용하고
관측하는 경계이며 Prefab이나 도메인 행렬을 설계하지 않는다.

`planner_digest()`와 `domain_digest()`는 실제 적용 때 확인할 owned source closure
pin이다. 컴파일된 호스트 artifact digest나 게임 인수 증거를 대체하지 않는다.
선택 binding의 dependency provenance는 authenticated environment의
`binding_dependency`가 제공하며 action implementation digest와 계약 목록을
계획에서 다시 확인한다.

현재 소스의 검사들은 원본 fixture로 작성 준비, immutable pin, reference closure,
shared instance 보존, coordinate derivative 소비, 예산과 target witness를 검증한다.
fake port나 정적 fixture 결과는 실제 게임 검증으로 승격하지 않는다. 실제
Coordinator source/environment, native 전체 lowerer와 host action, atomic authored
commit 및 dual readback의 통합 검증은 별도 필수 조건이다. 마지막 physics body와
binding을 제거하는 변경은 native 제거 및 before-target 경로가 확정될 때까지
명시적으로 거부한다. 이 제한을 포함한 미구현 native 경로는 MVP 완료로 간주하지
않는다.
