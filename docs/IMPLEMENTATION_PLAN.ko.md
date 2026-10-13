# 파일별 구현 지시와 게이트

이 목록은 실제 제품 구현용이다. 이 handoff의 예제 검사 통과로 G0~G6를 통과 처리하지 않는다. 경로는 새 MMMM 저장소에서 만들 위치다. Maven/Gradle·Cargo의 정확한 버전은 공식 artifact와 첫 빌드로 확인해 고정한다.

## G0 — 정본과 Rust 작업 기반

선행: 사용자 결정과 계약 0.2.0을 읽는다. 기존 TS 제품이 실제 있다면 먼저 데이터를 backup하고 migration 범위를 측정한다. 기존 설계만 있다면 TS 코드를 새로 만든 뒤 Rust로 옮기는 중간 단계는 만들지 않는다.

- [ ] 수정 파일: `Cargo.toml`, 구현 내용: workspace와 내부 crate 의존 방향을 정의한다. 새 도메인은 Rust, 임시 vendor runtime은 별도 worker로 둔다.
- [ ] 수정 파일: `rust-toolchain.toml`, 구현 내용: 실제 빌드한 stable toolchain과 component를 고정한다. 확인하지 않은 nightly 기능을 필수화하지 않는다.
- [ ] 수정 파일: `Cargo.lock`, 구현 내용: 정확한 crate/feature를 고정하고 일반 infrastructure와 domain vendor를 분류한다.
- [ ] 수정 파일: `contracts/mmmm.schema.json`, 구현 내용: 동봉 스키마를 정본으로 도입하고 schema URI·버전·이전 .1 migration을 고정한다.
- [ ] 수정 파일: `contracts/function-index.json`, 구현 내용: 함수 ID·입출력·부작용·오류·취소·재시도 소유권 목록을 도입한다.
- [ ] 수정 파일: `crates/mmmm-contracts/src/dto.rs`, 구현 내용: Rust serde DTO와 tagged union을 구성하고 unknown enum/field·null/omitted를 명시적으로 처리한다.
- [ ] 수정 파일: `crates/mmmm-contracts/src/ids.rs`, 구현 내용: project/prefab/instance/node/provider/binding/context/operation ID를 다른 newtype으로 분리한다.
- [ ] 수정 파일: `crates/mmmm-contracts/src/canonical.rs`, 구현 내용: JCS+SHA-256과 도메인별 digest projection을 구현한다. RFC 벡터와 Rust/Java 교차 시험을 통과시킨다.
- [ ] 수정 파일: `crates/mmmm-application/src/ports/mod.rs`, 구현 내용: ProjectStore, ResourceStore, HostPort, ProviderRegistry, CatalogSource, ExchangeCodec, CompilerBackend, OperationStore, Clock 포트를 정의한다.
- [ ] 수정 파일: `crates/mmmm-runtime/src/journal.rs`, 구현 내용: SQLite schema/migration·내구 dispatch 원장·단일 Coordinator 락·CAS 참조 수명을 구현한다.
- [ ] 수정 파일: `policies/vendor-registry.json`, 구현 내용: 검증된 실제 채택만 기록한다. 후보와 프로덕션 dependency lock을 섞지 않는다.
- [ ] 수정 파일: `docs/adr/0001-runtime-contract-and-ownership.md`, 구현 내용: Rust 코어/Java 최소 host/범용 dependency/외부 도구/v1 domain-vendor 0의 경계를 고정한다.

완료: UTF-8 입력→계약→도메인 ID→결정적 JSON 반환 경로, SQLite crash fixture와 해시 projection이 통과한다. Rust/Java DTO가 같은 의미를 처리한다. 제품 game_verified는 아직 false다.

## G1 — 객체·정보·가상 실행 수직 경로

- [ ] 수정 파일: `crates/mmmm-domain/src/graph.rs`, 구현 내용: 공간 DAG, behavior 연결, resource/reference 그래프를 분리하고 종류별 순환·참조를 검사한다.
- [ ] 수정 파일: `crates/mmmm-domain/src/prefab.rs`, 구현 내용: definition의 안정 node/port/state ID와 source map을 관리한다. runtime 진행 상태는 넣지 않는다.
- [ ] 수정 파일: `crates/mmmm-domain/src/instance.rs`, 구현 내용: revision 고정, override·clone·internal/external rebind·detach/drift 상태를 구현한다.
- [ ] 수정 파일: `crates/mmmm-domain/src/transform.rs`, 구현 내용: matrix/TRS·좌표계·피벗·초박형 값·quat 규약을 명시하고 독립 기저 기대값으로 시험한다.
- [ ] 수정 파일: `crates/mmmm-domain/src/state.rs`, 구현 내용: scope·type·unit·lifetime·초기화·임시 재진입·symbol collision을 관리한다.
- [ ] 수정 파일: `crates/mmmm-reference/src/snapshot.rs`, 구현 내용: 네 정보 층·출처·coverage·환경 fingerprint와 unknown 상태를 구현한다.
- [ ] 수정 파일: `crates/mmmm-reference/src/query.rs`, 구현 내용: ID·별명·태그·타입 검색과 snapshot-bound pagination을 구현한다. 별도 LLM/vector DB를 요구하지 않는다.
- [ ] 수정 파일: `crates/mmmm-adapters/src/provider.rs`, 구현 내용: 지원형 선언을 registry snapshot으로 등록한다.
- [ ] 수정 파일: `crates/mmmm-adapters/src/compatibility.rs`, 구현 내용: profile match·schema·typed binding을 해석한다. 특정 모드명을 분기하지 않는다.
- [ ] 수정 파일: `crates/mmmm-runtime/src/router.rs`, 구현 내용: required guarantee와 사용자 pin을 만족하는 기능을 고르고 immutable plan에 implementation digest를 고정한다.
- [ ] 수정 파일: `crates/mmmm-testkit/src/host.rs`, 구현 내용: 실제 상태를 가진 fake world와 외부 변경·부분 적용·단절 fault를 제공한다.
- [ ] 수정 파일: `crates/mmmm-application/src/execution.rs`, 구현 내용: fake world의 작은 영역 plan/apply/readback/충돌/복구를 완주한다.

완료: 실제 Minecraft 없이도 두 adapter가 같은 계약을 처리하고, 객체 두 개와 불명 쓰기의 중복 방지 경로가 작동한다. fake 관찰은 실제 게임 증거로 승격하지 않는다.

## G2 — 26.3 게임 호스트와 SDK

- [ ] 수정 파일: `jvm/gradle/libs.versions.toml`, 구현 내용: 실제 26.3 런타임·JDK·loader·API·Loom·Gradle artifact를 빌드로 확인해 고정한다.
- [ ] 수정 파일: `jvm/provider-api/`, 구현 내용: generated DTO·Registrar·Handler·optional prepare/poll/cancel/recover를 제공한다.
- [ ] 수정 파일: `jvm/host-common/`, 구현 내용: pairing·context epoch·scoped handle·host protocol·메시지 크기·권한·task queue를 구현한다.
- [ ] 수정 파일: `jvm/host-common/src/main/java/.../CommandExecutor.java`, 구현 내용: 실제 source의 parse/complete/execute와 UTF-16 cursor·feedback·returnCode를 반환한다.
- [ ] 수정 파일: `jvm/host-common/src/main/java/.../PublicApiExecutor.java`, 구현 내용: 승인 public signature·제한 codec·receiver handle·CompletionStage 관찰을 구현한다.
- [ ] 수정 파일: `jvm/host-fabric/`, 구현 내용: lifecycle·entrypoint·logical client/server·world selection/reload change를 공통 HostPort로 연결한다.
- [ ] 수정 파일: `jvm/fixture-provider/`, 구현 내용: MMMM SDK를 이용한 최소 read/write/job 제공자를 만든다.
- [ ] 수정 파일: `jvm/fixture-legacy/`, 구현 내용: MMMM SDK 없이 명령과 공개 메서드만 있는 모드를 만든다.
- [ ] 수정 파일: `crates/mmmm-runtime/src/host.rs`, 구현 내용: authenticated loopback RPC·context pin·dispatch·poll·event gap·reconnect를 구현한다.
- [ ] 수정 파일: `crates/mmmm-reference/src/source.rs`, 구현 내용: 호스트 registry/commands/packs 추출과 offline sources를 구분한다.
- [ ] 수정 파일: `crates/mmmm-reference/src/shape.rs`, 구현 내용: 정확한 blockstate·이웃·entity context·로드 coverage를 가진 shape 질의를 구현한다.

완료: 실제 26.3 복사 월드에서 작은 블록 작업과 명령·정보 조회를 수행한다. 호스트를 끄거나 도구가 미설치되어도 파일/계약/분석 기능은 남는다. 사용자별 권한과 client/server 문맥을 시험한다.

## G3 — 제작 워크플로와 모델링 교환

- [ ] 수정 파일: `crates/mmmm-application/src/objects.rs`, 구현 내용: capture 후보, instantiate/clone/relocate/update를 구현하고 내부 참조만 재배정한다.
- [ ] 수정 파일: `crates/mmmm-domain/src/commands.rs`, 구현 내용: source 원문+AST span+상태 참조, rack/embedded, next/conditionSource, 문맥을 유지한다.
- [ ] 수정 파일: `crates/mmmm-compiler-minecraft/src/commands.rs`, 구현 내용: 지원 grammar의 typed relocation과 실제 체인·블록 방향을 출력한다. opaque는 보존하고 제한한다.
- [ ] 수정 파일: `crates/mmmm-compiler-minecraft/src/target.rs`, 구현 내용: data/resource pack 형식·기능 세트·registry codec을 단일 profile에서 선택한다.
- [ ] 수정 파일: `crates/mmmm-compiler-minecraft/src/math.rs`, 구현 내용: ExprNode를 native provider/compute 및 score/NBT로 낮추고 실제 readback을 비교한다.
- [ ] 수정 파일: `crates/mmmm-domain/src/time.rs`, 구현 내용: decimal rational·기간·FPS/TPS·rounding·event order·sample invariants를 구현한다.
- [ ] 수정 파일: `crates/mmmm-compiler-minecraft/src/animation.rs`, 구현 내용: 절대 부모 공간 pose·parent chain·sparse frame·독립 timer·event·reset/cleanup을 생성한다.
- [ ] 수정 파일: `crates/mmmm-exchange/src/manifest.rs`, 구현 내용: 중립 bundle·payload hash·asset rights·archive limits·object map을 구현한다.
- [ ] 수정 파일: `crates/mmmm-exchange/src/physics.rs`, 구현 내용: native facts·모델링 물성·body/collider/joint 그래프와 unit/basis를 분리한다.
- [ ] 수정 파일: `crates/mmmm-exchange/src/bake.rs`, 구현 내용: provider 요구·샘플 요청·result slots·완료 검증·topology·loss·cost를 관리한다.
- [ ] 수정 파일: `crates/mmmm-exchange/src/patch.rs`, 구현 내용: 삭제는 명시적 operation만 허용하고 stable ID와 source revision으로 scene patch를 계획한다.
- [ ] 수정 파일: `crates/mmmm-testkit/src/editor.rs`, 구현 내용: 두 축/단위의 합성 편집기 출력과 정보 누락을 재현한다.
- [ ] 수정 파일: `crates/mmmm-testkit/src/solver.rs`, 구현 내용: solver 없이 알려진 분석 궤적을 반환하는 fixture와 불명 완료를 제공한다. 실제 physics engine으로 광고하지 않는다.
- [ ] 수정 파일: `crates/mmmm-compiler-minecraft/src/packs.rs`, 구현 내용: 실제 생성/참조 함수·외부 상태·자원·source map·검증 단계 manifest를 출력한다.

완료: 자체 제작 편의점 두 개와 금고문 2초 클립을 실제 game에서 확인한다. 중립 교환은 외부 프로그램 없이도 검증되고, 호환 제공자 없는 자동 베이크는 unavailable이다. 범용 Blender/스키닝 solver는 게이트가 아니다.

## G4 — MVP 출시 검토

- [ ] 수정 파일: `crates/mmmm-runtime/src/resources.rs`, 구현 내용: CAS·staging·타깃 충돌·source hash·pack reload 분리·Windows 경로 경계를 구현한다.
- [ ] 수정 파일: `crates/mmmm-application/src/recovery.rs`, 구현 내용: after-state 일치 확인·token epoch·새 recovery operation·partial/unknown 복구를 구현한다.
- [ ] 수정 파일: `crates/mmmm-runtime/src/policy.rs`, 구현 내용: 도구 재사용/새 설치/런타임 의존 분리·per-provider 토글·별도 설정 권한을 구현한다.
- [ ] 수정 파일: `crates/mmmm-runtime/src/workers.rs`, 구현 내용: 승인된 임시 vendor를 원형 runtime으로 실행하고 output contract와 작업 범위를 제한한다.
- [ ] 수정 파일: `crates/mmmm-mcp/src/tools.rs`, 구현 내용: 고정 tool 표면을 공통 함수에 연결하고 structured result·isError·pending/unknown을 일치시킨다.
- [ ] 수정 파일: `crates/mmmm-mcp/src/resources.rs`, 구현 내용: snapshot-bound 정보와 승인 artifact URI를 제공한다.
- [ ] 수정 파일: `apps/mmmm/src/cli.rs`, 구현 내용: 같은 Coordinator 함수와 JSON 출력을 사용하고 독자 쓰기 경로를 두지 않는다.
- [ ] 수정 파일: `xtask/src/architecture.rs`, 구현 내용: domain→IO/게임/rmcp/vendor 의존 금지와 JVM 셸 책임을 검사한다.
- [ ] 수정 파일: `.github/workflows/ci.yml`, 구현 내용: schema·Rust·JVM·fixture·license·경계·선택 game 테스트와 evidence를 분리한다.
- [ ] 수정 파일: `README.md`, 구현 내용: 실제 검증 범위·필수 runtime·v0 temporary vendor·미지원 기능만 사실대로 표시한다.

완료: tests/ACCEPTANCE의 MVP 항목 모두 실제 산출물을 가지며 release.evaluate가 통과한다. 게임 실행 권리/환경이 없는 CI에서는 not_run을 표시하고 자동 MVP 승인하지 않는다.

## G5 — v1 준비: v0 기준선 고정과 Rust 인수

- [ ] 수정 파일: `policies/vendor-registry.json`, 구현 내용: 채택 함수별 behavior spec·replacement module·target evidence를 연결한다.
- [ ] 수정 파일: `tests/migration/`, 구현 내용: 0.1→0.2와 vendor-native 자료의 copy-on-write migration·loss·충돌을 시험한다.
- [ ] 수정 파일: `tests/workflow/`, 구현 내용: vendor와 Rust를 다른 staging/복사 월드에서 비교하고 upstream 결함은 독립 oracle로 판정한다.
- [ ] 수정 파일: `tests/performance/`, 구현 내용: 고정 workload의 CPU/RSS/왕복/게임 스레드 비용/출력량과 정확도를 기록한다.
- [ ] 수정 파일: `crates/mmmm-compiler-minecraft/src/`, 구현 내용: 임시 parse/build/transform port를 자체 Rust로 대체한다. 구버전 Rust upstream fork로 미룰 수 없다.
- [ ] 수정 파일: `crates/mmmm-runtime/src/router.rs`, 구현 내용: 새 plan부터 Rust binding으로 전환하고 기존 job은 구 digest로 reconcile한다.

완료: 원 계약의 기능을 보존하며 각 vendor를 순차적으로 retired한다. 원래 언어인 vendor를 전부 먼저 포팅하는 별도 대공사를 선행시키지 않는다.

## G6 — v1 출시 하드 게이트

- [ ] 수정 파일: `xtask/src/vendor_gate.rs`, 구현 내용: product/setup/fallback/build graph의 domain-vendor 잔존과 분류 우회를 검출한다.
- [ ] 수정 파일: `xtask/src/release_evidence.rs`, 구현 내용: 필수 시험·권리·migration·clean build·platform shim review를 하나의 release report로 묶는다.
- [ ] 수정 파일: `vendor/`, 구현 내용: retired 도메인 snapshot을 제품 필수 경로에서 제거하고 필요한 역사 자료만 별도 archive에 보관한다.
- [ ] 수정 파일: `integrations/legacy-workers/`, 구현 내용: v1 기본/선택 product 기능의 retired worker·hidden fallback을 제거한다.
- [ ] 수정 파일: `third_party/NOTICES.md`, 구현 내용: 남는 infrastructure·platform·output template 조건과 SBOM을 최종 artifact와 일치시킨다.
- [ ] 수정 파일: `.github/workflows/release.yml`, 구현 내용: 구 vendor/Node/Python domain runtime 미설치 환경에서 clean execution을 검증한다. 필요한 Java host는 명시적 플랫폼 예외로 남긴다.

완료: 도메인 기능의 Rust 소유가 100%이고 채택 기능 삭제로 숫자를 맞추지 않았다. 사용자 external tool·범용 crate까지 직접 재작성했다는 잘못된 광고를 하지 않는다.

## 병렬 작업의 경계

A: contracts/domain, B: runtime/store/policy, C: JVM, D: adapters/legacy-worker, E: reference/exchange/compiler, F: CLI/MCP/test/evidence. A가 정본 변경을 취합한다. API 변경 PR에는 schema, function-index, 예제, migration, 구현 stub 변경을 함께 포함한다. 각 트랙은 다른 트랙의 원장을 직접 수정하지 않는다.
