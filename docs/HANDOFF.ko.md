# MMMM — Minecraft Map-Making MCP
# 통합 구현 지시서: Rust 코어 · 객체와 함수 계약 · 범용 어댑터 · MVP/v0/v1

문서 판: **2026-10-13 통합본 2** · 계약 초안: **0.2.0** · 자체 코드/계약: **MIT**

이 문서는 새 구현의 기준이다. 이전 TS 핸드오프(0.1.0-draft.1), Blender 자료 대조 추가편, Rust/Reference/Exchange 검토편을 대체한다. 제품 릴리스 번호와 계약 번호는 별개다. 아래의 MUST/금지는 구현 요구이며 이미 구현했다는 표기가 아니다. 동봉 검증 결과는 명세 파일 검사 범위이며 Minecraft·Blender 통합 검증 결과가 아니다.

## 읽는 순서와 정본

1. 이 문서: 목표·책임·객체·실행·출시의 의미.
2. `docs/FUNCTION_CONTRACTS.ko.md`: 함수별 입력·출력·전후조건·부작용·오류·취소·재시도 계약.
3. `contracts/mmmm.schema.json`: 저장/wire 자료형 정본. `contracts/function-index.json`은 함수 계약의 기계 판독 목록.
4. `docs/ADAPTERS.ko.md`: 제작자 지원형과 비지원형, 호스트 및 외부 작업 연결.
5. `docs/VENDOR_AND_V1.ko.md`: 벤더링 도입·언어 유지·버전 격리·Rust 교체 및 v1 차단 조건.
6. `docs/IMPLEMENTATION_PLAN.ko.md`, `tests/ACCEPTANCE.ko.md`: 파일별 작업과 결과 기반 인수 기준.

최신 사용자 결정 → 이 통합본의 의미 계약 → 스키마의 형식 제약 → 예제 순으로 판단한다. 문서와 스키마가 충돌하면 구현자가 편한 쪽을 고르지 말고 계약 변경으로 함께 수정한다. 이전 부록에서 새 필드였던 Reference Catalog와 Scene/Physics/Bake 계약은 이번 정본의 범위다. 배포된 0.1 프로젝트가 실제 있다면 무조건 읽지 말고 §24의 마이그레이션 경로를 사용한다.

---

## 1. 변경하지 않을 제품 요구

MMMM은 플레이 봇이 아니라 **맵 제작 데이터와 변경 작업을 관리하는 로컬 중심 시스템**이다. 에이전트·CLI·편집 도구가 같은 제작 서비스를 호출한다.

| 요구 ID | 확정 요구 |
|---|---|
| U01 | Minecraft Java 26.3부터 생성/실행을 목표로 한다. 미래 버전과 1.xx를 자동 지원으로 표시하지 않는다. |
| U02 | 직접 작성한 MMMM 코어·계약·SDK·fixture는 MIT다. 제3자 코드와 자산의 권리는 별도다. |
| U03 | 새 도메인·Coordinator·CLI·MCP·정보·변환 코드는 Rust로 작성한다. |
| U04 | MVP와 v0에서 채택한 벤더링 코드는 구현 언어를 이유로 재작성하지 않고 원래 언어로 사용한다. |
| U05 | v1 공개 전, 임시 벤더링에 맡긴 MMMM 도메인 기능 전량을 자체 소유 Rust 구현으로 대체한다. |
| U06 | 이미 Rust인 upstream도 버전·의미·유지보수가 맞지 않으면 사용하지 않는다. Rust라는 이유만으로 호환성 예외를 주지 않는다. |
| U07 | scoreboard는 정수 상태, 26.3 native compute는 연속 수치 계산의 기본이다. LUT/고정소수점 벡터 엔진을 새 기본 의존성으로 만들지 않는다. |
| U08 | 설치된 제작 도구 재사용은 기본 켜짐. 새 모드·브리지·실행 코드 설치는 별도 정책이다. |
| U09 | NBT Autocomplete·Command Block IDE·WorldEdit·BDEngine·Blender 등을 특별 취급하는 제품 분기를 만들지 않는다. |
| U10 | Provider Adapter와 Compatibility Adapter를 분리하고 공통 작업 계약으로 정규화한다. |
| U11 | 구조물·파트·본·포트·명령·클립·상태·참조의 의미는 MMMM이 소유한다. |
| U12 | Minecraft 정보는 버전 자료·로컬 자원·실행 환경·월드 관찰을 구분하고 출처와 모름을 반환한다. |
| U13 | 모델링/물리는 도구 중립 교환 계약을 제공한다. 특정 편집기 전용 연결은 필수 MVP가 아니다. |
| U14 | 매 틱 애니메이션·물리는 생성물/게임/선택 런타임이 실행한다. LLM/MCP 호출 주기에 의존하지 않는다. |
| U15 | 미지원·손실·부분 완료·결과 불명·복구 한계를 숨기지 않는다. |
| U16 | 원본 맵·스크립트·게임 자산을 권리 확인 없이 공개 fixture나 MIT 코드에 포함하지 않는다. |

### 1.1 ‘v1 전면 Rust’의 정확한 적용 범위

**전면 교체 대상은 MMMM 제품 기능을 대신 구현하는 임시 벤더링/도메인 의존층이다.** 도메인 처리·팩 생성·기하 변환·색인·라우팅·복구를 Python/TS/Java subprocess나 이름만 바꾼 플러그인에 남기지 않는다. 원래 Rust였던 도메인 vendor도 같은 기능 인수/철수 대상이다. upstream 제품의 사용하지 않는 기능까지 복제하는 목표는 아니다.

앞서 선택한 **Java 게임 호스트/Provider SDK는 JVM API를 연결하는 최소 셸로 유지**한다[F02]. 이는 벤더링 철수의 우회로가 아니다. 허용 책임은 로더 등록, 실제 게임 문맥/권한, 스레드 전달, registry/command/shape 조회, 지정된 변경의 적용/readback, DTO 전달이다. 프리팹 설계·참조 재연결·수학 IR·애니메이션 생성·영구 작업 원장은 Rust가 맡는다. 호스트의 얇은 request dedup 캐시는 허용하되 제품 원장을 대체하지 않는다.

사용자가 소유한 Blender/모드/외부 solver는 Rust 재작성 대상이 아니다. 생성 데이터팩의 `.mcfunction`/JSON, Gradle 빌드 파일, 필수 JVM SDK도 ‘남은 벤더 도메인 로직’으로 세지 않는다. Tokio/serde/rmcp/SQLite 같은 범용 의존성은 별도 infrastructure 분류로 감사한다. 외부 C 기반 저장 엔진까지 모두 자체 Rust로 다시 쓴다는 목표는 아니다. 이 경계를 넓히는 변경은 소유자가 승인한 ADR이 필요하며, **도메인 vendor 잔존에는 v1 자동 예외를 허용하지 않는다.**

---

## 2. 릴리스 단계: MVP는 v0 안의 첫 인수 지점

| 단계 | 요구 결과 | 벤더링 |
|---|---|---|
| MVP (`0.1.x` 제품 후보) | 한 26.3 호스트, 프리팹 두 인스턴스, 명령/display/짧은 클립, 기본 정보, 중립 교환, 두 어댑터, plan/apply/readback/복구 | 언어 무관 원형 유지 가능. 필요한 기능·버전·출처·철수 계획이 등록되어야 함 |
| v0 (`0.x`) | MVP 안정화, 추가 읽기 형식·호환 프로필·제약 진단·성능 계측·v1 인수 명세 축적 | 원래 언어 유지 허용. 대규모 vendor fork 대신 새 기능은 Rust 포트 뒤에 구현 |
| v1 준비 | 각 도메인 vendor의 자체 Rust 대체, 사용자 데이터/계약 호환, 실제 게임 차등 시험 | 기존 vendor는 비교용 격리 환경만. 제품 빌드/기본 실행/배포에서는 사용 금지 |
| v1 공개 | 정의한 핵심 기능 전량 통과, 미해결 migration/unknown 작업 없음, 라이선스·의존성·성능·문서 증거 | 도메인 vendor 0, opaque language-port 0, 호스트 예외는 얇은 플랫폼 경계만 |

‘Rust 비율 95%’ 같은 줄 수 지표는 출시 기준이 아니다. 파서/출력기 1개가 vendor에 남으면 그 계약을 사용하는 모든 기능이 vendor-dependent다. **함수 계약별 구현 소유권**으로 판정한다. 기능 삭제로 교체율을 맞추지 않는다. 기존에 제공한 기능을 폐기하려면 별도 사용자 승인·사용자 데이터 대책·릴리스 고지가 필요하다.

### 2.1 MVP에서 직접 지원할 범위

- 읽기: 프로젝트/팩/NBT/함수/자원/선택 영역. 구형 자료는 읽은 범위와 미해석 부분을 구분.
- 쓰기: 승인된 프로젝트 workspace와 실제 게임 호스트. 모든 Anvil/POI/조명 파일의 범용 오프라인 쓰기는 제외.
- 객체: 프리팹, 인스턴스, 파트, 포트, 상태, 참조, command module, clip, asset/source map.
- 기본 형상: block/item/text display, 강체 파트 계층, raw affine 보존.
- 수학: 정수 상태·단위 있는 식 IR·목표 버전 native 계산·명시적 변환.
- 정보: 버전·자원·환경 스냅샷 검색, 현재 선택 영역의 문맥적 충돌 조회.
- 교환: 중립 장면 bundle 내보내기/가져오기, 강체/affine 트랙 검사, 물리 입력 정의와 결과 manifest.
- 연결: 지원형 등록, 명령·파일·제한된 public Java·등록된 최소 JSON-RPC 호출. RPC 서버나 코드가 없으면 수동 파일 교환만 제공.
- 비범위: 봇 플레이, 자동 설치 관리자, 전용 BDE/Blender connector, 전체 UI 복제, 임의 Java reflection, 범용 실시간 solver·가중치 스키닝·천 렌더러.

---

## 3. 코드 소유권과 벤더링 입구

각 외부 구성 요소에 `DependencyDisposition`을 부여한다.

| 분류 | 예 | Rust 철수 의무 |
|---|---|---|
| `owned_domain` | MMMM 객체·계획·정보·컴파일러 | 항상 Rust |
| `temporary_domain_vendor` | 기존 MCP의 파서/팩 작업/변환 기능 일부 | v1 전에 자체 Rust 구현으로 대체 |
| `infrastructure_dependency` | MCP SDK, 직렬화, DB, 압축, 표준 해시 | 개별 버전/feature/라이선스 감사 후 유지 가능 |
| `platform_shim` | Java 호스트·SDK | 게임 플랫폼 접점만 예외. 도메인 책임 금지 |
| `user_external_tool` | 설치된 모드·모델러·solver | 재배포/재작성하지 않음. 공통 계약으로 사용 |
| `test_only_reference` | 제거한 vendor와 격리된 비교 runner | v1 배포/필수 CI 경로에 포함 금지 |

동일 저장소에서도 부분별 분류가 다를 수 있다. 한 파서를 쓴다고 서버 전체·자동 업데이터·모드 설치 기능까지 가져오지 않는다.

### 3.1 도입 승인 필수 조건

출처 commit/archive hash, 실제 LICENSE, 전이 의존성, 구현 언어, 사용할 함수 계약, target version, 입출력 형식, 기존 결함, 허용된 작업 범위, build/run 명령, 소유 담당자, Rust replacement 모듈, 대체 인수 시험을 등록한다. **이 패키지는 실제 vendor를 새로 채택/다운로드하지 않는다. 후보 목록과 등록 양식은 채택 증거가 아니다.**

upstream은 `vendor/<component>/<commit>/`에 불변 복사한다. wrapper는 `integrations/legacy-workers/<component>/`에 별도로 둔다. wrapper는 타입·파일·프로세스·오류 번역과 최소 작업 제어만 담당한다. vendor 내부에 MMMM DTO를 심거나 MMMM 도메인이 vendor 클래스/함수명에 의존하게 하지 않는다.

버전 불일치 분류:

- **형식 차이만 있고 의미 보존 가능**: 검증된 codec으로 연결. 원본/변환본/손실을 기록.
- **게임 의미·registry·명령·저장 형식 차이**: 해당 기능을 Rust에서 직접 구현. 구버전 호스트·world writer를 manifest 숫자만 바꿔 사용 금지.
- **필요한 일부가 독립적인 순수 연산**: 그 부분만 contract 뒤에서 활용 가능. 게임 버전 호환 주장을 확대하지 않음.
- **권리/버전/완료 의미 미확인**: 채택 보류 또는 명시적 실험 경로. 기본 기능을 이 구성 요소에 의존시키지 않음.

원형 유지 정책은 알려진 안전성/정확성 결함을 그대로 실행하라는 뜻이 아니다. wrapper로 검증/제한할 수 없으면 해당 기능 비활성화 또는 Rust 선구현을 선택한다. 불가피한 소규모 patch는 원본 고지·diff·테스트를 남긴다. **대규모 호환 fork와 언어 직역을 v0의 지름길로 삼지 않는다.**

---

## 4. 프로세스·crate·호스트 경계

### 4.1 실행 구조

`CLI/MCP facade → Coordinator/application → domain + catalog + compiler/exchange → registry/router → Provider 또는 Compatibility → 실행기/Java host/사용자 도구`

Coordinator 한 개가 같은 로컬 데이터 루트의 project revision·policy·작업 원장·binding inventory·쓰기 락을 소유한다. 여러 MCP stdio facade와 CLI는 같은 Coordinator에 연결한다. facade별로 다른 원장/캐시를 만들지 않는다. domain/reference 순수 질의는 불변 스냅샷으로 병렬 처리한다.

외부 MCP는 `rmcp`를 사용하는 stdio를 첫 배포 경로로 고정한다[S01,S02]. 인터넷 원격 접속은 필수 MVP가 아니다. Coordinator 로컬 IPC는 인증된 loopback JSON-RPC 2.0으로 통일한다. endpoint는 사용자별 런타임 디렉터리 파일에 기록하고 OS ACL을 적용한다. 임의 포트 탐색은 하지 않는다. Java 호스트도 pairing된 loopback endpoint를 사용한다. 각 transport는 동일 내부 함수 계약을 호출한다.

### 4.2 crate 책임

| crate/영역 | 소유 책임 | 금지 |
|---|---|---|
| `mmmm-contracts` | DTO·ID·버전·wire codec | 게임/DB/MCP 실행 |
| `mmmm-domain` | 객체 의미·참조·변환·시간·상태 | filesystem/network, 특정 vendor |
| `mmmm-application` | use case와 port, plan 구성 | 구현체 직접 생성 |
| `mmmm-reference` | 자료 정규화·출처·검색·형상 질의 의미 | 자동 월드 로드/설치 |
| `mmmm-exchange` | 장면/물리/bake 교환·손실·patch 해석 | 도구별 Python/JS 주입 |
| `mmmm-compiler-minecraft` | target-specific 명령/팩/display/클립 출력 | 게임 실행·임의 라이브러리 설치 |
| `mmmm-adapters` | Provider/Compatibility 정규화·binding 해석 | 프로젝트 직접 변경 |
| `mmmm-runtime` | Coordinator·원장·락·정책·호스트 transport·외부 runner | domain 의미를 별도 재정의 |
| `mmmm-mcp` | MCP 도구·resources 노출 | 자체 plan/apply 알고리즘 |
| `mmmm-testkit` | 독립 fixture·fault injection·관찰 oracle | 실제 제품 성공 증거 위조 |
| `apps/mmmm` | CLI/daemon/mcp 진입점·구성 주입 | 별도 도메인 상태 |
| `jvm/*` | 로더·스레드·게임 API·public API 실행 | 프리팹/애니메이션/정보 제품 알고리즘 |

초기에는 모듈로 합쳐도 이 의존 방향은 유지한다. 모듈 분리만을 이유로 microservice를 늘리지 않는다. `vendor` 의존은 전용 wrapper/runner에서만 허용한다. `domain`이 vendor 타입을 import하는 것은 CI 위반이다.

### 4.3 고정할 저장 선택

첫 구현은 **SQLite 한 DB + content-addressed blob 디렉터리**다. DB는 로컬 디스크, foreign keys 켜짐, WAL, durable dispatch를 위한 synchronous 정책을 실제 디스크 시험 후 고정한다. 초기 dispatch/원장은 synchronous=FULL로 시작하며, 더 약한 durability는 crash 시험과 명시적 정책 승인 없이는 허용하지 않는다. 동시에 다른 journal 구현을 개발하지 않는다. SQLite transaction의 보장은 DB 내부이며 게임/외부 파일/worker 효과까지 포함하지 않는다[S06,S07]. 네트워크 공유 폴더에 WAL DB를 두지 않는다.

blob은 임시 파일에 작성→flush→hash 확인→같은 볼륨의 최종 digest 경로로 교체한다. 그 후 DB에 참조를 commit한다. 중간 실패의 orphan blob은 GC 가능하며, 반대로 존재하지 않는 blob 참조를 committed 상태로 만들면 안 된다. 외부 배포 파일 교체는 별도 적용 단계다. GC는 미해결 작업·복구 snapshot이 참조하는 blob을 삭제하지 않는다.

---

## 5. 공통 자료·버전·해시 계약

### 5.1 단일 스키마

`contracts/mmmm.schema.json` Draft 2020-12가 형식 정본이다. Rust serde DTO/Java DTO는 이 스키마에서 생성하거나 bidirectional fixture로 일치시킨다. DTO에서 다시 만든 별도 schema를 제2 정본으로 두지 않는다. Rust ABI/shared library를 공개 확장 계약으로 사용하지 않는다.

공통 필드는 `additionalProperties:false`. 실험 확장은 `extensions`의 namespaced key에 두고 모르는 값은 보존하되 실행하지 않는다. action의 입력/출력 스키마는 독립 meta-validation 후 사용하며 네트워크 `$ref` 자동 fetch를 끈다. JSON의 중복 key, lone surrogate, NaN/Infinity를 거절한다. 인증 principal을 요청 본문의 문자열만 보고 만들지 않는다.

### 5.2 독립 버전

제품 버전, 계약 버전, 호스트 프로토콜, 기능 계약 버전, 호환 프로필 버전, 도구 버전, 게임 target profile, project revision은 서로 다르다. 초기 `0.2.0`은 exact match가 기본이다. `26.3 이상`은 최소 제품 목표이지 모든 미래 빌드의 지원 선언이 아니다. 버전 문자열을 소수로 파싱하거나 사전식으로 비교하지 않는다.

`VersionProfile`에는 정확한 게임 build/artifact digest·기능·팩 형식·호스트/로더 빌드 증거를 담는다. reference_only와 build_verified, runtime_verified, read/write 지원을 구별한다. 외부 자료의 main/latest는 dependency lock이 아니다. 실제 Rust toolchain/crate/JDK/Fabric/Gradle을 G0에서 빌드 검증 후 정확한 버전으로 잠근다. 본문에 검증되지 않은 patch 버전을 만들어 적지 않는다.

### 5.3 JSON 수치·좌표·시간

int32는 JSON integer 범위로 제한한다. 64비트 revision/event sequence/길게 누적한 시간의 정수값은 canonical decimal string을 사용한다. 시간 `RationalTime`은 numerator/denominator 문자열이며 양의 denominator와 최대공약수 약분을 요구한다. 클립 시각은 0 이상, TPS는 0보다 큼, source frame offset은 별도 signed 값이다.

도메인의 기하 계산은 유한 f64를 사용하되 target float32 변환은 명시적이다. float32 결과가 실제 게임과 동일하다는 주장은 target readback 증거가 필요하다. JSON 숫자로 64비트 정수를 조용히 반올림하지 않는다.

### 5.4 digest

- raw file/resource digest: 원본 bytes의 SHA-256.
- DTO/action/profile/plan digest: RFC 8785 JCS 후 SHA-256[S05]. 일반 sort_keys는 대체 구현이 아니다.
- 자기 참조 필드 제외: `revision`, `planHash`, `schemaDigest` 등 해당 객체의 self-digest 필드만 type별 고정 projection으로 제외한다. 제외 목록은 계약 파일에 기록한다.
- planHash는 본문/고정 step/context pins/dependency pins/허용 손실/만료를 포함하며 runtime 진행 로그는 포함하지 않는다.
- 동일 digest는 동일 권한을 뜻하지 않는다. blob은 ACL/프로젝트 membership 검사 후 읽는다.

---

## 6. 정체성·소유권·리비전

| ID | 수명 | 사용 원칙 |
|---|---|---|
| projectId/prefabId/instanceId | 영속 제작 객체 | 파일명/엔티티 UUID와 독립 |
| nodeId/portId/stateId | 정의 내 안정 ID | 이름 변경에도 유지 |
| bodyId/colliderId/jointId | 물리 정의 내 안정 ID | 표시 node와 별도 |
| providerId | 논리 제공자 | 서로 다른 환경에 중복 가능 |
| bindingId | 등록된 제공자 인스턴스 | 재등록/epoch 변경 시 새로 발급 |
| contextId | 권한과 실행 위치를 묶은 서버 핸들 | 인증 수단으로 자체 사용하지 않음 |
| environment snapshot/epoch | 실행 환경·월드 수명 | 재연결·reload 변화 범위를 구별 |
| runtime UUID/handle | 현재 게임·도구 구현 대상 | 외부 binding의 불투명 참조 |
| planId/operationId/invocationId | 계획·작업·각 dispatch | 재시도·중복 여부를 별도로 추적 |

Project는 리소스 그래프의 루트이며 전체 월드를 한 JSON에 넣지 않는다. PrefabDefinition, Instance, CommandModule, AnimationClip, PhysicsDefinition, Asset은 독립 revision을 갖는다. project commit은 그 리소스 revision 목록을 가리킨다. live gameplay state/RuntimeBinding은 authoring revision과 분리한다. 매 틱 score가 바뀐다고 편집 프로젝트 전체가 새 revision이 되어서는 안 된다.

원본 변경은 불변 snapshot→typed ChangeIntent→plan→승인된 commit으로만 수행한다. 어댑터·codec·외부 vendor가 live Project 객체를 가변 참조로 보유하지 않는다. domain 함수는 새 값/patch/diagnostics를 반환한다.

---

## 7. 세 그래프와 타입 기반 구성요소

### 7.1 공간 그래프

하나의 root, 나머지는 존재하는 단일 parent를 갖는다. 순환 금지. transform은 부모 공간의 로컬 값이다. pivot은 노드/port의 명시적 변환으로 표현한다. UI 이름/태그가 비슷하다고 parent를 추정 확정하지 않는다. 가져오기 결과는 candidate/confirmed/opaque로 표시한다.

### 7.2 행동 그래프

이벤트·버튼·조건·함수·상태 전이를 담는다. 순환은 허용할 수 있지만 같은 tick의 무한 재귀와 타이머를 통한 반복을 구분한다. function execute context, score/storage scope, 입출력 상태, 정리 이벤트를 관리한다.

### 7.3 자원/참조 그래프

model→texture, item→model, command→function, node→asset, external port→instance 등 타입 있는 edge다. parent model 순환과 게임 상태 기계 순환에 같은 규칙을 적용하지 않는다. namespaced ID를 `.split(':')[-1]`로 줄이지 않는다. `minecraft` 외 namespace는 보존한다.

### 7.4 구성요소

Node에 필요한 typed component만 부착한다: BlockGeometry, Display, RigPart, PortAttachment, InteractionRegion, DamageRegion, PhysicsBinding. ‘한 객체 클래스가 모든 필드를 가진 거대 객체’나 깊은 모드별 상속은 금지한다. 알려지지 않은 mod component는 opaque payload와 출처로 보존할 수 있지만 동작을 추정 실행하지 않는다.

`text_display`의 label/hud/background_geometry 역할을 구분한다. 공백 한 칸과 배경색은 의도된 도형일 수 있다[F03]. item/display/model 경계도 엔티티 이름만으로 결정하지 않는다. 실제 payload는 target codec을 거친다.

---

## 8. 프리팹·인스턴스·상태와 참조

### 8.1 PrefabDefinition

BlockSet 자원, node/port/state 정의, module/clip/physics 참조, 기본값·외부 연결 포트를 가진다. definition은 live 플레이 진행값을 담지 않는다. 수많은 cells는 palette 자원으로 분리한다. BlockSet에는 positions/palette뿐 아니라 명시적인 block entity data와 상태 보존 범위를 추가한다. entity/POI/조명은 하나의 blockset에 조용히 생략하지 않고 별도 자원 또는 limitation이다.

### 8.2 Instance

특정 prefabRevision과 world/dimension/placement를 고정한다. override는 node transform뿐 아니라 display/state default/참조의 typed override를 갖는다. prefab이 갱신되어도 기존 인스턴스를 자동 덮어쓰지 않는다. update plan에서 3-way 비교(base definition, 새 definition, instance override)를 제시한다. unresolved 충돌은 부분 갱신 후보로 남긴다.

### 8.3 복제·이동·삭제

- 복제: 새 instance ID와 runtime identity, 내부 state symbols 생성. local 참조만 재연결하고 project/external은 선언에 따라 유지. 기본은 default state, live state 복제는 별도 snapshot 요청.
- 이동: 해당 placement/ports/block states/관련 command references를 갱신. 외부 목적지 좌표는 유지. opaque command가 위치 의존적이면 그 부분의 relocate를 미지원으로 표시.
- 삭제: instance 소유 runtime/entity/state와 알려진 schedule을 정리하는 계획. 공유 자원은 참조 카운트/정책 없이 삭제하지 않음. 아직 실행 중인 외부 job은 별도로 관리.
- 변경 감지: 사람이 간판/블록을 바꾸면 drift 보고. 자동 ‘정상화’로 사람 수정을 덮지 않음.

### 8.4 상태 계약

scope = project/instance/player/invocation. 상태형 = int32/float32/bool. 의미 단위와 target storage를 분리한다. bool→score 0/1, float32→storage NBT 기본. scratch는 재진입 안전한 호출 공간 또는 명시적인 non-reentrant 함수를 사용한다. 함수가 순차 실행된다는 이유만으로 전역 tmp 공유를 허용하지 않는다.

이름 생성기는 object ID·scope·target profile 기반으로 충돌 없는 symbol table을 만들고 SourceMap에 저장한다. 리소스명/objective/tag 길이 제한은 target profile에 둔다. 이름 줄임의 hash 충돌은 검출하고 재할당한다. `#timer timer` 같은 외부 기본값을 모든 instance 공용 상태로 그대로 편입하지 않는다.

---

## 9. 좌표·행렬·블록 배치

제작 좌표: Minecraft XYZ, Y-up, 블록 단위. cell은 최소 모서리 기준 정수. Quaternion은 `[x,y,z,w]`, 정규화 요구. 내부 행렬은 row-major 배열·열벡터 곱, `M_world = M_parent × M_local`, translation 인덱스 3/7/11이다. 외부 포맷의 배열을 그대로 복사하지 않는다.

MVP block 변환은 정수 이동/Y축 90도 회전. door hinge/stairs/rail 등의 상태 회전은 registry/state별 시험을 통과한 범위만 지원한다. mirror/비균일 scale/임의 회전은 후속. display는 affine를 보존할 수 있지만 실제 블록으로 변환하면 loss가 생길 수 있다.

shear·반사·초박형 scale을 TRS로 분해하면서 잃지 않는다. 필요한 경우 원시 matrix를 유지한다. `0.00005`와 같은 축을 silent clamp하지 않는다. 특이 행렬은 렌더 보존 가능 여부와 역행렬이 필요한 reparent 가능 여부를 구분한다. zero scale을 이유 없이 모든 읽기에서 제거하지 않되 inverse가 필요한 연산은 `NONINVERTIBLE_TRANSFORM`이다.

`reparent(keep_world)`는 새 부모 역행렬이 존재할 때만 수행한다. 블록 구조 회전과 명령문 내 절대좌표 재작성은 별도 단계다. 명령은 원문·토큰 span·AST·symbol ref를 유지하며 문자열 전체 replace로 회전하지 않는다. 수학 각도 radians, yaw/pitch wire 필드는 degrees를 이름에 명시한다.

---

## 10. 커맨드 모듈·커맨드실·맵 디자인

CommandNode는 종류(impulse/repeating/chain), conditional, auto, facing, localPosition, nextId, conditionSourceId, command source, execution context, symbol refs를 갖는다. **실행 next와 물리적으로 뒤쪽의 조건 원본을 별도로 보존**한다. 굽은 chain 이동 시 조건 원본 관계를 검사한다.

배치 형태:

- `rack`: 기능별 직렬 줄, 설정 가능한 줄 간격, service 통로, 표식, 확장 공간, chunk 범위.
- `embedded`: 버튼 뒤의 단일 TP/함수 진입점. 지역 원점과 선택 문맥을 유지.

모든 명령을 중앙실로 옮기지 않는다. `@p`는 실제 버튼 사용자라는 보장이 없으므로 멀티플레이에서는 입력 소유권을 별도 연결한다. 물리적 떨어짐은 selector/global score 간섭을 막지 않는다. block power/observer/레드스톤 검사와 state/ref scope 검사를 나눈다. 공유가 의도된 경우 shared declaration으로 허용한다.

청크 작동 조건은 renderer가 아니라 host가 보고한 상태와 승인된 ticket 정책이다. 구버전 spawn chunk 가정을 가져오지 않는다. 정보 조회는 자동 청크 생성/유지를 하지 않는다. rack 적용은 비활성 staging→state/ref readback→명시 활성화 순서다. 간접 tick 효과·예약 함수·플레이어 상태는 기록하지 않았다면 undo 범위가 아니다.

맵 디자인 use case는 지역 요약(높이·경사·빈 공간·구조물), 프리팹 배치 후보, 통로/출입구 연결, 시각 전후비교, 비용 보고를 제공한다. 미감·난도·서사 결정은 사용자/에이전트가 한다. 코어가 ‘보기 좋은 맵’을 자동으로 증명하지 않는다. large NBT를 대화에 dump하지 않고 지역·객체·함수 색인과 page/cursor로 전달한다.

---

## 11. Minecraft Reference Catalog

### 11.1 네 데이터 층

| 계층 | 자료 | 갱신/권위 |
|---|---|---|
| VersionReference | 특정 build의 registry·명령·규칙/추출 보고서 | 고정 버전, source digest |
| LocalArtifactData | 승인된 설치본·팩의 모델/텍스처/언어/자원 | 파일 digest와 순서 |
| EnvironmentSnapshot | 실제 로드된 registry·명령·mods·packs | 호스트 epoch/reload generation |
| WorldObservation | 차원·좌표·엔티티·이웃 문맥의 관찰 | 관찰 tick·범위·일관성 수준 |

현재 환경과 다른 버전 자료를 덮어씌우지 않는다. ‘최신이므로 live 우선’이 아니라 scope/version/side/fingerprint가 맞는 자료인지 확인한다. 리소스팩과 데이터팩의 순서는 별도 배열. 모든 자원은 일반 deep merge가 아니다. 언어 별칭은 canonical resource ID를 바꾸지 않는다.

### 11.2 제공 대상

블록/아이템/엔티티/바이옴/소리/태그/component ID, blockstate 속성/허용값, 실제 명령 tree와 인자, 수학 규칙, blockstate→model→texture/item→model/font, 호스트 기능과 현재 차원, 충돌/outline/support/fluid 자료를 제공한다. 레지스트리 ID가 존재한다고 모든 NBT 필드를 안다고 표시하지 않는다.

`DataRecord.status = known | absent | unknown | unsupported | requires_runtime`. known은 값과 source/scope/type/unit가 필요하다. absent는 조회 coverage에서 없음이 확인된 경우만. unknown collision을 empty shape로, 모르는 밀도를 0으로 반환하지 않는다. 값의 provenance는 observed/extracted/documented/user_declared/estimated를 구분한다.

### 11.3 스냅샷과 조회 계약

스냅샷은 immutable. cache key에 target artifact, logical side, ordered pack stack, mod set, registry generation, locale, 질의 문맥을 넣는다. 동일 환경이라도 player permission이 다른 명령 제안은 같은 public cache로 공유하지 않는다. snapshot cursor는 query hash/snapshot/principal scope에 묶는다.

live 다중 chunk 조회가 여러 tick에 걸리면 전역 한 순간 snapshot이라고 부르지 않는다. `consistency = per_item_observed | bounded_window | provider_atomic`과 관찰 구간을 반환한다. 대상 dependency invalidation 범위를 확정할 수 없으면 conservative invalidation을 사용한다. 읽기 권한과 cache hit의 권한 검사는 동일하다.

기본 검색은 exact ID→prefix→타입/태그/KO·EN 이름 필터다. 임베딩 DB/추가 LLM은 필요 없다. 결과는 짧은 요약 + record/snapshot/source refs + continuation. 모델에게 공식 사실과 제작 관행 설명을 같은 등급으로 주지 않는다.

### 11.4 자산 권리

자체 코드 MIT가 게임 텍스처·소리·폰트의 재배포를 허가하지 않는다. 기본 배포는 추출기/스키마와 사용자 로컬 자료의 참조이며 원본 자산을 저장소에 넣지 않는다. `misode/mcmeta` 같은 외부 자료는 선택 source provider다[S12]. build/digest/조건을 확인하기 전 runtime truth로 쓰지 않는다.

---

## 12. 충돌·기본 물리·모델링 의도

VisualGeometry, outline, 실제 collision shape, interaction, DamageRegion은 별개다. 실제 shape query에는 block ID뿐 아니라 전체 blockstate·이웃·차원/위치·관련 엔티티 문맥이 들어간다. 렌더 JSON의 큐브가 충돌체라는 가정은 금지한다[S09].

NativeBehaviorFact(실제 관찰) / PhysicsMaterialAssignment(사용자 물성) / RuntimeMapping(검증된 대응)을 분리한다. 파괴 경도로 kg/밀도를 추론하지 않는다. 게임 friction 값을 외부 solver 계수로 이름만 바꿔 전달하지 않는다. metersPerBlock와 질량/각속도/중력 단위를 입력에서 고정한다.

정적 바닥은 실제 블록을 우선 활용한다. 동적 기본 몸체는 target version과 entity 종류별로 속성/충돌/행동이 검증된 carrier profile에서 선택한다. display가 몸체를 따라가게 하되 게임 물리가 위치를 갱신할 때 매 틱 TP로 덮어쓰지 않는다. `^` 좌표는 yaw/pitch 기준 변환 편의이지 경로 충돌 처리나 임의 본 행렬 변환이 아니다.

v0에서 실시간 solver를 추가해도 MMMM은 물리 정의/작업/출력 계약을 소유할 뿐 매 tick MCP로 적분하지 않는다. 움직이는 발판의 플레이어 지지·운동 전달·동기화는 별도 capability다. 설치된 모드가 있다고 그 모드의 모든 효과를 서버 판정으로 간주하지 않는다.

---

## 13. 수학·함수·애니메이션 compiler

### 13.1 게임 수학

26.3 native compute와 실수 NBT 저장의 차이를 target profile/codec에서 확인한다[S03]. scoreboard 상태는 int32다. `/compute float scale` 명령 결과의 floor와 float provider의 `from_float` truncation, 정수 `div`와 `floor_div`를 구별한다. 기존 `/scoreboard operation /=`와 새 provider `div`의 음수 의미를 같다고 가정하지 않는다.

Expr IR은 const/state/context component/add/sub/mul/div/min/max/clamp/sin/cos/sqrt와 명시적 convert를 지원한다. type/unit/op overflow/NaN/0 나눗셈을 검사한다. f64 host constant fold를 target f32 계산과 임의 교환하지 않는다. 동등성 입증된 fold만 사용한다. 없는 native opcode를 임의 문법으로 만들어 출력하지 않는다.

명령 파서는 로컬에서 원문/알려진 AST를 보존하고 실제 호스트 parse/complete를 우선 검증원으로 사용한다. upstream parser가 1.xx에 멈췄으면 새 26.3 AST/출력 구현을 Rust에서 맡기고 parse capability를 부분 범위로 줄인다. opaque source는 그대로 보존 가능하지만 의미를 모르는 relocation/optimisation은 수행하지 않는다.

### 13.2 함수 계약

명령 함수에도 `inputs`, `outputs`, `stateReads`, `stateWrites`, `executionContext`, `reentrancy`, `scheduledCallbacks`, `cleanup`을 작성한다. 모든 `.mcfunction`에 원본 schema 파일을 강제하지는 않지만 MMMM 생성 함수의 계약은 SourceMap/ExportManifest에서 추적 가능해야 한다. 매크로 인수는 typed이고 escaping을 거친다. 사용자 함수를 substring 치환하여 생성기 내부 함수에 합치지 않는다.

### 13.3 클립과 리깅

클립 키는 node 부모 공간의 **절대 로컬 포즈**다. rest pose delta가 아니다. 본은 강체 파트 계층을 기본으로 하며 skinned vertex weights는 별도 자원/미지원 능력이다. 소켓/locator를 port로 보존한다. 하나의 physics body가 여러 display parts를 움직일 수 있다.

source sampling, key reduction, target tick quantization, game interpolation을 네 단계로 분리한다. 중복 pose 제거는 duration/event를 없애지 않는다. initial/final hold 구간과 loop seam을 유지한다. event 실행은 `(timestamp, authoredSequence)` 순서로 고정하고 구간 crossing에서 누락/중복하지 않는다. pose scrub은 event를 기본 억제한다.

matrix 16개 성분 lerp를 일반 보간으로 제공하지 않는다. step 또는 검증된 decomposition/target 변환 보간만 사용한다. negative scale·shear·삼각형 베이크는 중간 포즈 오차까지 확인한 경우에만 부드러운 보간을 허용한다. disable interpolation이 ‘필드 생략’인지 ‘0으로 재설정’인지 target codec에서 구분한다.

### 13.4 시간·실행

`game_seconds`와 `wall_seconds`를 구분한다. 직접 compiler MVP는 game_seconds. wall clock 음악 동기화는 해당 runtime capability가 없으면 미지원이다. TPS는 기본 제안 20이지만 import의 60 등 원래 값을 유지한다. 전역 `/tick rate` 변경은 clip 설치와 다른 권한/계획이다.

2초 클립을 20 TPS에서 40 ticks, 60 TPS에서 120 ticks로 양자화한 경계와 이벤트를 시험한다. 정수 tick에 놓이지 않는 시각은 rounding policy/오차를 보고한다. score가 점프하거나 재시작되었을 때 이벤트 정책과 loop iteration ID를 추적한다. 기기 FPS가 TPS와 같다고 표시하지 않는다.

---

## 14. 도구 중립 Scene/Physics/Bake 교환

공통 manifest와 content-addressed payload를 기본으로 한다. 루트는 `mmmm-exchange.json`, 경로는 `objects/`, `geometry/`, `tracks/`, `assets/` 등의 상대 경로다. 외부 도구의 원본 `.blend`/프로젝트는 opaque 원본 자원으로 보존할 수 있지만 이름만 바꾸어 중립 장면으로 읽지 않는다.

| 계약 | 필수 의미 |
|---|---|
| SceneExchangeManifest | 원본 project/selection revision, 객체 ID 맵, 좌표/단위, 관련 data snapshot, payload digest, 보존/손실 |
| SceneSelectionSnapshot | 선택 instance/node/port/state, parent 및 원점, 외부 참조를 유지할 boundary |
| CollisionSceneSnapshot | shape·coverage·관찰 문맥·시각·정확도 |
| PhysicsDefinition | body/collider/joint/재질/초기값/gravity 및 visual binding |
| BakeRequest | source pins, sample times, source FPS, time domain, 요구 solver 기능, 표현·예산·오차 |
| BakeArtifact | tool/solver 버전·입력 hash·실제 설정·samples·events·topology·손실·비용 |
| ScenePatch | base revision과 명시적 생성/변경/삭제·SourceMap 변경 |
| ExportManifest | 생성/참조 파일, 진입/초기화/정리, score/storage 및 외부 runtime 의존, 검증 결과 |

호출 주체(Provider/Compatibility), 통신(file/registered RPC/public API), 기능(scene edit/bake/export)는 서로 다른 축이다. MMMM은 등록된 도구의 기능을 검색하며 BD/Blender 이름을 기능 판단으로 사용하지 않는다. tool 고유 코덱은 별도 등록 확장 또는 사용자 도구 측 구현이다. 복잡한 평가 메시 생성은 JSON 프로필만으로 자동 구현할 수 없으며, 이를 핑계로 arbitrary Python/JS `eval`을 열지 않는다.

### 14.1 원본·평가 결과·게임 산출물

세 자원은 별도다. 본·제약·모디파이어의 원본, 평가된 부품/표면 트랙, 게임 display/functions를 서로 같은 형식으로 표시하지 않는다. source object names가 바뀌어도 안정 ID로 대응한다. imported 결과에 필드가 없다는 것은 삭제 명령이 아니다. 삭제는 `ScenePatch.entries[].kind = delete_node`에 명시한다.

교환 파일만 제공하면 수동 편집/재가져오기를 지원한다고 표시한다. 제공자 없이 자동 베이크가 가능하다고 하지 않는다. 등록된 `.py`를 발견/설명하려고 import하면 그 스크립트의 top-level 부작용이 실행될 수 있으므로 해시/정적 메타데이터 확인만 한다[F03,F04].

### 14.2 표현과 위상

BakeArtifact 표현 = rigid_part_tracks / affine_part_tracks / triangulated_surface_samples. 실시간 물리 의존은 BakeArtifact로 가장하지 않고 PhysicsDefinition.runtimeIntent=runtime_required 및 runtime capability로 남긴다. 삼각형 수만 같다고 동일 topology라고 판정하지 않는다. 안정된 vertex/triangle ID와 topology digest 또는 검증된 대응이 필요하다. topology 변화는 명시적 spawn/delete 전략이 없으면 미지원이다. 퇴화 면/비정상 법선/양면/색공간/UV 손실 정책을 보고한다.

첨부 사례의 3 displays/triangle은 특정 표현의 비용 공식이지 모든 exporter의 비용이 아니다[F03]. 임의 per-vertex deformation을 본 전송으로 위장하지 않는다. 베이크된 변환은 새 외력에 반응하지 않는다는 limitation을 유지한다.

### 14.3 단위와 코덱

metersPerBlock, massUnit, seconds, source FPS, target TPS, basis/handedness, quaternion order, matrix layout, local/world space, COM space를 고정한다. 외부 입력을 정규화하는 한 단계에서만 basis를 적용한다. 재수입 때 두 번 회전/스케일하지 않는다.

glTF는 기하·스킨·애니메이션 payload의 선택 코덱이다. arbitrary shear/full game refs를 전부 보존하는 정본은 아니다[S10]. USD Physics는 후속 포맷 후보다[S11]. 핵심 meta를 `extras`에 넣었다고 모든 editor가 보존한다고 가정하지 않는다.

### 14.4 결과 가져오기

staging artifact의 hash→schema→graph/ID→unit/time→topology→resource refs→loss/예산→base revision을 검사한다. 먼저 임시 variant와 ScenePatch를 만들고 원본은 변경하지 않는다. apply는 일반 plan 경로다. bake request는 external workspace write 권한, 결과 game install은 별도의 world write 권한이다. 한쪽 승인이 다른 쪽을 자동 승인하지 않는다.

---

## 15. Provider Adapter와 Compatibility Adapter

두 어댑터는 같은 ActionDescriptor/ExecutionContext/Invocation/ProviderResult/OperationReport를 사용한다. 실행 위치 server/client/external과 지원 방식은 별개다. `ProviderDescriptor`의 출처/검증 수준은 호스트가 기록한다. 제작자 등록이라는 이유로 trusted/sandboxed라고 간주하지 않는다.

Provider Adapter는 registrar에 등록된 schema·handler를 bindingId로 정규화한다. 제작자는 최소 describe/execute만 제공하면 되고 plan/status/cancel/undo는 optional이다. 등록은 metadata를 읽는 단계이고 실제 쓰기 시험은 별도다. SDK는 게임 런타임과 분리된 wire DTO를 쓰며 compileOnly로 제공한다.

Compatibility Adapter는 승인된 profile(match + action + binding)을 검증한다. profile은 순수 데이터. 이름별 코드를 코어에 만들지 않고 typed literal/argument pointer/context/handle 매핑만 사용한다. 명세 작성자는 제작자·사용자·커뮤니티가 될 수 있다. 에이전트 생성 초안은 승인된 출처와 같은 신뢰 등급이 아니다.

공통 실행기:

- **command**: target Brigadier parse/complete, 실제 principal source. quoted text/resource ID/float 등 typed token codec. shell 문자열 호출 금지.
- **file**: 승인된 ResourceRef와 root, immutable read/staging write/export. save와 reload는 별도 action.
- **public_java**: 정확한 public signature, 등록 receiver resolver/handle만. 비공개 필드/setAccessible/임의 constructor/탐지 중 클래스 초기화 금지.
- **registered_rpc**: targetId에서 호스트 정책의 endpoint/credential을 해석. profile이 임의 URL/token을 입력하지 않음. 외부 MCP 중계는 같은 원칙의 선택 executor.

receiver를 공통 경로로 얻을 수 없거나 unsupported complex Java type이 필요하면 미지원이다. 모든 모드의 모든 public 메서드를 자동 이해하지 않는다. GUI 전용 도구는 설치됨만 표시할 수 있다. 별도 hook이 필요하면 신규 설치 정책 적용. private reflection/Mixin 주입/화면 자동화는 필수 MVP 밖이다.

기능의 adapter path와 implementation origin(vendor/owned/external)은 별도 필드다. **vendor runner를 세 번째 공개 adapter로 만들지 않는다.** replacement는 같은 port 뒤의 implementation 교체이며 사용자 프로젝트 형식이나 의미를 바꾸지 않는다.

---

## 16. 기능·함수 계약의 강제 규칙

자세한 서명과 함수별 조건은 `docs/FUNCTION_CONTRACTS.ko.md`와 기계 목록을 따른다. 모든 공개 서비스/port 함수는 다음을 명시한다.

1. 입력과 출력의 named DTO, ID의 수명, 단위·좌표계·빈 값 의미.
2. 선행조건: auth/context/snapshot/revision/capability/자원 존재.
3. 후행조건: 어떤 값이 생성/변경되며 무엇은 바뀌지 않는지.
4. 부작용 위치: none/private_cache/staging/project/world/client/external, 그리고 commit 주체.
5. 오류: 입력 거절과 dispatch 후 실패를 구분. 오류 문자열만 반환하지 않음.
6. 멱등성·재진입·순서·취소·타임아웃·복구 보장.
7. 반환 상태의 검증 근거와 미확인 범위.

Rust 구현은 domain pure function과 IO port를 분리한다. domain에는 Tokio/serde_json::Value 대입을 통한 임의 변형·vendor class가 들어오지 않는다. wire parsing 후 ValidatedDomain type으로 이동한다. 외부 extensible payload만 제한적으로 opaque JSON을 허용한다.

async trait의 실구현 방식은 pinned toolchain과 object safety에 맞춰 고정하되, 표준화되는 것은 wire/의미 계약이지 Rust 내부 ABI가 아니다. Mutex/RwLock guard를 await 경계 너머에 들고 있지 않는다. CPU 변환은 bounded pool, Tokio I/O는 별도. 작업 취소는 cooperative token과 실제 확인 상태로 구현한다[S04].

---

## 17. 계획: 변경 의도를 실행 내용에 고정

ChangeIntent는 자연어가 아니라 discriminated DTO다. 지원 MVP intent: prefab.instantiate, instance.clone/relocate, display.patch, command_module.patch, clip.retime, resource.patch, pack.build, scene.import_patch, external.action, recovery.plan. 입력 prompt를 곧바로 실행 코드를 만드는 우회로로 쓰지 않는다.

Plan = source snapshots + typed intent + contexts + route pins + version/dependency/codec pins + resource read/write footprint + 단계 DAG + 진단/손실/예산 + 승인 요구 + 만료. 읽기는 병렬 가능하지만 write 충돌의 순서를 명시한다.

서로 다른 external/server 단계가 있을 수 있으므로 **각 step에 contextId를 지정**하고 plan에 그 모든 context digest를 고정한다. root context가 game이라는 이유로 external 도구에 게임 권한을 복사하지 않는다.

### 17.1 단계 간 데이터 흐름

완성되지 않은 bake 결과의 실제 bytes를 계획 때 알 수는 없다. plan은 `from_step(stepId, outputPointer, expectedSchemaDigest, transformCodecDigest)` 슬롯을 고정하고, 완료 후 결과 검증→footprint 확인→Invocation arguments hash 기록을 수행한다. 권한·최종 대상·비싼 런타임 설정을 untrusted upstream 결과가 새로 선택하게 하지 않는다. 예상 scope를 넘으면 재계획한다.

파일 내보내기→외부 bake→게임 설치는 기본 두 계획이다. 외부 결과에 따라 실제 엔티티 수/파일이 정해진다면 결과를 가져온 후 게임 적용 plan을 새로 만든다. v0의 복합 workflow도 단계별 승인을 생략하지 않는다.

### 17.2 plan은 승인 증거가 아니다

내부 cache/staging은 생성할 수 있지만 월드/사용자 원본을 변경한 뒤 되돌려 pure plan으로 보고하지 않는다. vendor가 preview 과정에서 쓰기를 한다면 별도 sandbox 작업으로 계획한다. raw command는 opaque plan이며 exact undo/정밀 footprint를 보장하지 않는다. 지원되지 않는 객체 연산을 opaque action으로 자동 우회하지 않는다.

---

## 18. 적용·상태·취소·재조회·복구

ApplyRequest는 planId/planHash/contextId/idempotencyKey만 받는다. 위치·차원·arguments를 추가하면 거절한다. 정상 순서:

1. auth/principal/context pins/epoch/policy/expiry/digest 확인.
2. `(principal, projectId, idempotencyKey)`에 planHash를 bind. 동일 키·동일 hash는 기존 operation, 다른 hash는 conflict.
3. 정해진 순서로 write fence/lock 취득. 다른 프로세스·mod가 이를 따를 것이라고 가정하지 않음.
4. 실제 target/리소스/version/implementation precondition 재확인.
5. `dispatch_intent`를 durable journal에 commit.
6. 고정된 Invocation을 host/worker에 전달.
7. provider ack, 변화, output validation, independent readback을 각 증거로 기록.
8. required verification과 현재 side effect 상태에 맞춰 확정.

상태는 queued/running/cancel_requested/succeeded/failed_before_effects/partial/outcome_unknown/cancelled. 실행 여부 불명과 몇 개 변경됨을 동시에 표시할 수 있도록 step별 dispatch/effect 증거를 함께 둔다. `succeeded`는 요구 검증 수준 완료이지 전체 맵·미술 품질 보증이 아니다.

### 18.1 모르는 결과 처리

네트워크·worker timeout, schema가 잘못된 write 응답, 프로세스 중단은 부작용이 없었다는 증거가 아니다. 알려진 effect가 있으면 partial, 더 진행했는지 모르면 outcome_unknown 증거를 함께 남긴다. 불명 상태에서 다른 vendor/owned/provider로 같은 write를 자동 실행하지 않는다. poll/readback/reconcile만 허용한다.

읽기 재시도는 권한·snapshot가 동일한 경우 제한된 backoff로 가능하다. write 재시도는 실제 provider keyed contract와 durable dedup의 범위에서만. Coordinator key만으로 외부 side effect exactly-once를 보장하지 않는다.

### 18.2 취소와 재시작

queued 취소와 running 취소 요청을 구별한다. Future drop/spawn_blocking abort/프로세스 kill은 게임의 변경 취소 완료가 아니다[S04]. OS kill은 관리 정책에 따른 별도 수단이며 기존 변경은 partial/unknown으로 기록한다.

재시작 시 dispatch 기록 후 final evidence가 없는 step은 재전송하지 않는다. host job ID·readback으로 reconcile한다. host도 session-bound invocation dedup를 제공하되 JVM 재시작 후 잃을 수 있는 범위를 선언한다. 게임 재연결 후 옛 handle은 STALE_CONTEXT로 처리한다.

### 18.3 복구

복구도 새 plan/operation이다. 현재 target가 이전 operation의 after snapshot과 맞을 때만 그 direct before 값을 적용한다. 다른 사람 변경이 끼면 recovery conflict. provider undo token은 binding/epoch에 묶인다. old token을 새 provider history에 적용하지 않는다.

다중 파일 교체, game block mutation, DB commit, fluid/schedule/player state는 서로 다른 보장이다. recorded direct changes 이외를 ‘전체 undo’라고 표시하지 않는다. rollback된 상태도 관찰 전까지 완료라고 하지 않는다. 광범위 작업은 사용자가 승인한 복사 월드/백업 경로를 우선 제안한다.

---

## 19. 정책·보안·자원 한도

기본: modUseEnabled=true, reuseInstalledTools=true, providerDiscovery=true, compatibilityProfiles=true, newInstallPolicy=manual_only, publicJavaMode=registered_signatures_only, privateReflection=false, guiAutomation=false, runtimeMods=forbid. 마지막 값은 **완성 맵의 필수 모드 정책**이다. 제작 호스트 사용 금지가 아니다. 사용자는 server_only/client_server_allowed로 변경할 수 있다.

권한 = 사용자 정책 ∩ 작업 grant ∩ 실제 game principal ∩ host capability. tool/profile manifest의 trusted flag를 믿지 않는다. 정책 수정은 모델이 편집하는 project JSON이 아니라 사용자 제어 채널에서 수행한다. revocation 후 queued 변경과 새 dispatch는 멈추고 기존 job 상태 조회·recovery는 별도 권한으로 유지한다.

설정 OFF는 MMMM의 외부 호출만 끈다. 실제 mod uninstall/unload 하지 않는다. 한 기능 실패가 무관한 기능의 읽기/분석까지 막지 않도록 capability별 가용성을 반환한다. unknown write footprint는 그 scope의 후속 쓰기에 fence를 걸되 관계없는 프로젝트는 계속 사용할 수 있다.

프로필과 도구 응답·명령 feedback·파일 텍스트는 untrusted data다. 그 안의 지시를 사용자 정책으로 해석하지 않는다. 비밀은 credentialRef로 유지하고 plan/log에 token·로컬 사용자 경로를 불필요하게 남기지 않는다. localhost만으로 인증하지 않는다.

기본 한도(운영 기본값 제안): control JSON 1 MiB, summary 64 KiB, 스키마 깊이 64/노드 4096, paging 필수. bulk asset/region/mesh는 별도 ResourceRef로 전달. ZIP symlink/../absolute/duplicate/압축 폭탄/대소문자 충돌을 거절하고 길이·파일 수·확장 해제 bytes budget을 설정한다. path check와 실제 open 사이 symlink 변경을 막는 플랫폼 안전 열기를 사용한다. HTTP redirect가 승인 origin을 벗어나면 중지한다.

같은 JVM의 모드는 충분한 권한으로 임의 일을 할 수 있다. metadata의 read 표시는 sandbox가 아니다[S08]. MMMM은 노출된 호출 경계를 제어하는 도구이지 설치된 악성 mod를 완전 격리하는 제품이 아니다. subprocess도 제한 권한/작업 복사본 정책 없이는 sandbox라고 하지 않는다.

---

## 20. 호스트 프로토콜과 외부 실행

Host protocol은 MMMM 내부 JSON-RPC 2.0. 버전 `0.2.0` exact handshake. hello는 environment kind/side/epoch, artifact/loader/registry generation, 실행기 능력과 제한을 반환한다. 요청은 invocationId·operation/step·context·deadline·idempotency·action/implementation digest를 고정한다.

메서드: hello, inventory, describe, inspect, prepare, dispatch, operation.get, operation.cancel, events.since. events는 sequence와 gap을 반환한다. gap이 발생하면 snapshot을 다시 읽고 누락 event를 허위 생성하지 않는다. heartbeat는 가용성 정보일 뿐 job 취소가 아니다.

Java transport thread에서 월드 수정 금지. host task queue에서 짧은 target precondition+apply를 같은 실행 구간으로 처리한다. 큰 작업은 batch/chunk별 재확인·budget·partial 변경 기록. client와 server는 같은 JVM에서도 다른 logical side/권한이다[S13]. server 권한을 client read에 자동 복사하거나 반대로 하지 않는다.

외부 tool 실행은 등록된 target/worker만. vendor sidecar는 고정 executable digest·argv template·작업 root·환경 변수 allowlist로 실행하고 shell을 거치지 않는다. vendor의 debug stdout은 protocol 채널과 분리한다. worker가 Project DB를 열거나 승인되지 않은 live world root에 쓰지 못하도록 경로/프로세스 권한을 제한한다. 직접 live 기능을 요구하는 vendor는 같은 host dispatch/observation 계약을 구현하지 못하면 채택하지 않는다.

---

## 21. MCP·CLI의 표면

MCP tool 이름은 고정·결정적인 목록으로 제공하고 실제 제공자 기능은 search/describe로 조회한다. 기능별 하위 schema를 다시 검증한다. 도구 목록의 변경/권한/구조화된 결과 의미는 선택한 공식 SDK에 맡기고 MMMM state를 프로토콜 숨은 세션에 의존시키지 않는다[S08].

고정 도구군: environment/capability inspect, data search/describe, world shape query, project/object inspect, command complete, plan create/inspect/apply, operation get/cancel/reconcile/recovery plan, artifact read, action read/plan, exchange prepare/inspect/import plan. 쓰기와 설치는 generic ‘read’로 우회하지 않는다.

MCP resource URI는 `mmmm://catalog/<snapshot>/<kind>/<encoded-resource-id>`와 승인된 artifact resource로 한다. Resource를 제공했다고 클라이언트가 항상 모델 문맥에 넣는 것은 아니다[S14]. 고정 read tool을 함께 둔다. URI는 locator이며 bearer secret이 아니다.

CLI는 같은 함수 DTO로 `--json`과 사람용 요약을 제공한다. CLI가 validation/권한/plan을 생략해 직접 live 파일을 쓰지 않는다. `mcp` 모드 stdout은 프로토콜만, 로그는 stderr/승인된 로컬 파일. 새 명령은 function-index와 인수 시험에 같이 등록한다.

---

## 22. 성능·관찰·비용

성능은 제작 CPU/RSS/기동·plan 시간, blob bytes, game tick p50/p95, main thread 적용 시간, display/entity 수, network payload, agent 왕복을 분리한다. 동일 생성물을 실행하는 경우 Rust 전환이 게임 TPS를 자동 향상시키지 않는다.

vendor vs owned 차등 비교는 동일 frozen snapshot·입력·target artifact·설정·하드웨어/예산을 사용한다. 읽기/순수 compile은 shadow 가능하나 **live write를 두 번 실행해 비교하지 않는다.** 서로 분리된 복사 월드에서 각 backend를 실행하고 독립 readback으로 비교한다.

카탈로그 lookup은 page/ID index, bulk transformations는 bounded worker pool, NBT/world read는 선택 영역 우선. 명령 수가 줄었다는 이유로 전체 성능이 좋아졌다고 하지 않는다. warm cache/cold cache와 벤치 입력 digest를 기록한다. baseline 측정 뒤 예산을 채택하며 임의 성능 목표를 성공 증거로 쓰지 않는다.

---

## 23. 저장소 레이아웃

```text
MMMM/
  Cargo.toml, Cargo.lock, rust-toolchain.toml, LICENSE, README.md, AGENTS.md
  contracts/mmmm.schema.json
  contracts/function-index.json
  contracts/fixtures/
  crates/mmmm-contracts/src/{dto,ids,canonical}.rs
  crates/mmmm-domain/src/{prefab,instance,graph,transform,state,commands,time}.rs
  crates/mmmm-application/src/{ports,objects,planning,execution,recovery}.rs
  crates/mmmm-reference/src/{catalog,snapshot,source,shape,query}.rs
  crates/mmmm-exchange/src/{manifest,physics,bake,normalize,patch}.rs
  crates/mmmm-compiler-minecraft/src/{target,math,commands,animation,packs}.rs
  crates/mmmm-adapters/src/{provider,compatibility,binding,codecs}.rs
  crates/mmmm-runtime/src/{coordinator,registry,router,policy,journal,resources,host,workers}.rs
  crates/mmmm-mcp/src/{server,tools,resources}.rs
  crates/mmmm-testkit/src/{host,provider,legacy,editor,solver,faults}.rs
  apps/mmmm/src/{main,cli,daemon,mcp}.rs
  jvm/{provider-api,host-common,host-fabric,fixture-provider,fixture-legacy}/
  profiles/{minecraft,compatibility}/
  integrations/legacy-workers/<component>/
  vendor/<component>/<commit>/
  policies/{default-policy.json,vendor-registry.json}
  third_party/{infrastructure-lock.json,NOTICES.md}
  docs/{contracts,adapters,reference,exchange,version-support}/
  docs/adr/
  tests/{contracts,domain,workflow,game,migration,performance}/
  xtask/src/{main,schema,architecture,vendor_gate,release_evidence}.rs
  .github/workflows/
```

`vendor/` 디렉터리는 이번 패키지에 실제 코드로 채워져 있지 않다. v1 제품 checkout에는 해당 domain snapshot을 필수 build input으로 남기지 않는다. v0 비교 자료는 권리를 유지한 별도 tag/archive에서 보관할 수 있다. `Cargo vendor`로 offline 공급망을 고정한 범용 crate는 temporary_domain_vendor와 혼동하지 않고 SBOM에 분류한다.

---

## 24. v0 → v1 기능 인수와 사용자 데이터 마이그레이션

각 vendor component마다 계약 ID 집합을 기록하고 그 전체를 replacement plan에 연결한다. 단계를 `admitted → wrapped → characterised → rust_implemented → equivalence_verified → switched → retired`로 고정한다. 제3자 코드의 버그를 규범으로 복사하지 않고 독립 동작 명세와 실제 target 동작으로 옳고 그름을 판정한다.

Rust 인수 절차:

1. 현재 정상/경계/실패 동작과 upstream 결함을 구분한 BehaviorSpec을 고정한다.
2. 수정에 선호되는 원본 데이터/계약/출처를 확보한다. 실제 vendor 내부 구조를 영속 정본으로 만들지 않는다.
3. 자체 Rust port 구현과 oracle 시험을 만든다. language translation만으로 라이선스가 새로 MIT가 되지 않는다[S15].
4. frozen fixture 비교, 별도 복사 월드 readback, 타임아웃/취소/오류 의미, 성능 budget, migration을 검증한다.
5. 새 plan부터 implementation digest를 바꾼다. 실행 중/결과 불명 작업은 구 backend로 reconcile하거나 수동 복구한다. pending job을 새 구현에서 자동 재실행하지 않는다.
6. 구 vendor 없이 clean build/기본 CLI/MCP/use case가 동작하는지 검증한다. fallback도 제거해야 retired다.
7. 릴리스 SBOM·notices·인수 증거를 갱신한다. 빌드 feature를 껐다는 이유만으로 숨은 production 경로가 없다고 가정하지 않는다.

0.1 계약 파일의 v0.2 migration은 copy-on-write, 원본 hash 보존, 명시적 field 매핑으로 수행한다. 새 runtime context/authority, 실제 버전 검증, 출처 unknown을 자동 ‘verified’로 채우지 않는다. 예전 타입에 없던 정보는 pending/unknown/manual resolution이며 그 기능의 실행만 제한한다. runtime UUID와 미해결 plan은 포맷 변환만으로 새 세션의 유효 핸들이 되지 않는다.

v1도 wire/project 계약을 유지하거나 migration report를 제공한다. 구현 언어 변경 때문에 사용자에게 모델·모드·클립을 재작성하라고 요구하지 않는다.

---

## 25. 구현 단계와 작업 배분

파일별 지시와 세부 인수는 별도 `docs/IMPLEMENTATION_PLAN.ko.md`에서 수행한다. 순서는 다음으로 고정한다.

- G0: Rust workspace/계약/ID/저장/버전 프로필/소유권 registry.
- G1: pure domain+Catalog+두 fake adapter+첫 write 원장 경로.
- G2: 실제 26.3 host·공개 SDK·명령/public API·readback.
- G3: 프리팹/command/display/짧은 clip+중립 exchange+기본 collision.
- G4: MVP 복구/정책/CLI/MCP/버전 증거·선택 vendor 격리.
- G5: v0 기준선을 고정한 뒤 v1 준비 트랙에서 vendor contract별 Rust 대체.
- G6: v1 zero domain-vendor, migration/release gates.

계약 정본 담당자는 한 명이다. 병렬 트랙은 A 계약/domain, B runtime/store/policy, C JVM, D adapters/vendor wrapper, E catalog/exchange/compiler, F CLI/MCP/integration로 나눈다. 다른 트랙이 DTO를 독자 추가하지 않는다. DTO 변경은 schema/문서/예제/마이그레이션/함수 계약을 함께 변경한다.

첫 세 구현 변경: (1) 계약과 pure objects, (2) SDK 없는 legacy fixture와 supported fixture의 같은 read 계약, (3) 작은 블록 영역 plan/apply/readback/recovery. 처음부터 GUI·모든 모드 자동 연결·전체 기존 맵 복원으로 범위를 넓히지 않는다.

---

## 26. 인수 기준과 출시 차단 조건

각 기준의 expected result는 독립적으로 정한 좌표/상태/파일/호스트 관찰이다. validator 출력만 다른 validator에 넣어 통과시키는 시험을 제품 증거로 쓰지 않는다. 자체 fixture는 실제 모드 이름/사용자 맵 없이 같은 경계 문제를 재현한다.

MVP 필수: 두 adapter 동일 계약, 독립된 두 편의점 인스턴스, internal/external refs 보존, client/server 권한 분리, 20/60TPS 클립·event, known/unknown catalog, shape 문맥, exchange identity/time/loss, stale target 차단, timeout 중복 방지, after-state recovery conflict, installed reuse/new install 분리.

v1 추가 필수: 모든 채택 도메인 vendor 계약의 Rust 소유, non-Rust 제품 domain runtime 없음, 구 vendor 미설치 clean execution, Rust upstream 불일치 기능 직접 소유, 비교·실제 target readback·migration 성공, license/SBOM/NOTICE 보존, 출하 아카이브 검사. JVM/범용 lib/사용자 외부 도구의 예외 목록과 책임은 공개 문서에도 일치해야 한다.

`tests/ACCEPTANCE.ko.md`의 모든 필수 항목에 test ID·target digest·runner·timestamp·결과·artifact를 남긴다. 게임 시험을 실행하지 않은 CI는 runtime_verified를 만들지 않는다. static contract pass와 game pass는 다른 gate다.

---

## 27. 라이선스·출처·공개 문서

MIT는 우리가 소유한 코드에만 적용한다. MIT/Apache source를 복사하면 원 고지·수정 표시·필요 NOTICE를 유지한다[S02,S16]. LGPL을 설치본으로 연결할 때에도 실제 연결 방식 조건을 확인한다. GPL/AGPL domain code를 언어만 바꿔 MIT로 재표기하지 않는다. 승인되지 않은 제한/무허가 코드는 vendor 채택 불가이며 외부 사용자 실행과 코드 복사를 구별한다.

이미 사용자가 가진 BDE/Blender/모드는 MMMM 배포물이 아니다. 도구마다 전용 통합 코드나 배포 정책을 코어에 넣지 않는다. 다만 MMMM에 복사하는 코드, 생성물에 복사되는 runtime/template, source 데이터/텍스처는 별도 권리 manifest에 남긴다. 외부 프로그램을 실행한 결과라는 이유만으로 모든 출력의 권리가 같아지지 않는다.

README는 공개 사용 기능/지원 상태/설치 경계/제약을 설명한다. 상세 구현 지시서는 docs에 둔다. ‘Rust-based’와 ‘Rust-only domain before v1’, 필수 Java 호스트/선택 legacy runtime을 숨기지 않는다. 아직 실행하지 않은 게임 버전/모드는 지원 완료로 표시하지 않는다.

---

## 28. 이 핸드오프의 확인 범위

기존 구현 지시서와 두 추가 검토서를 읽어 최신 사용자 결정으로 재작성했다[F01–F03]. 본문/스키마/예제/함수 목록의 정적 일치를 검사한 결과는 `validation/REPORT.json`에 있다. Rust toolchain이 이 작업 환경에 없어 Rust/Java 제품 빌드·게임 통합·실제 외부 도구 동작·성능·제3자 vendor 인수 시험은 수행하지 않았다. 이를 코드 완료로 표시하지 않는다.

`contractVersion 0.2.0`은 새 설계 정본이며 실제 제품 v0.2 공개를 뜻하지 않는다. v1은 위 gate의 증거가 모일 때만 배포한다. 출처의 구현 사실과 MMMM의 새 설계는 `SOURCES.md`에서 구분했다.

### 보조 계약의 확정 의미

Scope.regions는 contextId와 worldId를 포함해 다중 game/external 계획에서 어느 세계의 영역인지 모호하지 않게 한다. InstanceOverride는 transform/display/state_default/reference의 닫힌 union이며 live state 변경과 definition default 변경을 구분한다. PhysicsBody의 명시적 inertiaDiagonal은 kg·m² 단위의 주축 관성 모멘트이고 inertiaOrientationXyzw로 body-local 주축 방향을 함께 준다. 동적 body는 양의 질량·양의 주관성·정규화 방향이 필요하고, 질량중심과 collider의 위치 단위는 CoordinateSystem을 따른다.

### 좌표 교환의 수식과 표면 샘플

CoordinateSystem.basisToMinecraftRowMajor는 축/handedness만 나타내는 무차원 직교 기저 B다. translation=0, 마지막 행=(0,0,0,1), determinant=±1을 검사하며 단위 scale을 이 행렬에 중복 포함하지 않는다. distanceUnit=blocks이면 k=1, meters이면 k=1/metersPerBlock이다. C=B·diag(k,k,k,1)로 두고 위치는 p_M=C·p_E, 양쪽 공간을 같은 basis로 변경하는 변환은 M_M=C·M_E·C⁻¹로 바꾼다. 이미 변환한 geometry를 다시 같은 C로 변환하지 않는다. 외부 world pose를 부모 local pose로 바꾸는 단계는 L=parentWorld⁻¹·world이며 특이 parent는 거절한다. 원본 origin 보정은 명시적 node/root transform으로 한다.

선속도·중력의 필드명에 meters/second가 명시되면 SI 크기는 유지하고 기저만 변환하며, 블록/초가 필요한 출력 경계에서만 metersPerBlock을 적용한다. 반사 기저에서 각속도 같은 축벡터는 det(B)·B로 변환한다. quaternion에 반사를 직접 넣지 않고 회전행렬의 basis change와 shape 반사를 구분한다. normal은 inverse-transpose, winding은 handedness 반전 여부를 반영한다.

SurfaceSample은 at·mesh ResourceRef·topologyDigest·vertex/triangle 수·선택적 identityMap을 가진다. sample 배열 순서만으로 시간을 추정하지 않는다. 위상이 불변이면 동일 vertex/triangle 순서의 payload codec을 고정하고, 순서가 달라지면 identityMap 또는 미지원으로 처리한다. mesh bytes codec의 실제 지원은 capability로 선언하며 ResourceRef만 있음을 파싱 지원으로 취급하지 않는다.

물리 선택은 여러 인스턴스를 포함할 수 있으므로 visualBindings의 대상은 `(instanceId,nodeId)`인 ObjectNodeRef로 지정한다. `door` 같은 nodeId 하나로 선택 전체를 조회하지 않는다. bodyToNode는 body-local에서 해당 visual node의 기하 원점까지의 오프셋이며 WorldNode=WorldBody·bodyToNode이다. parent-local clip으로 내보낼 때에는 부모 world pose를 역변환한다. 동일 node에 여러 body가 최종 쓰기를 하면 pose writer 충돌이다.

### 교체 작업의 시점

MVP/v0 출시를 위해 언어 포팅을 선행하지 않는다. v0 기본 브랜치는 승인된 vendor를 원래 언어로 유지하며, 기능/버전 결함 때문에 독립 구현이 필요한 부분만 새 Rust로 작성한다. 전면 교체는 v0의 행동 기준선을 고정한 후 v1 준비 트랙(G5)에서 진행한다. 검증된 대체 구현의 조기 도입은 별도 일정 결정이며, 언어 통일만을 이유로 v0 출시를 지연하지 않는다.
