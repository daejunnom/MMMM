# 범용 어댑터와 실행기 계약

이 문서는 HANDOFF.ko.md의 규범 부속서다. 아래는 구현할 MMMM 계약이지 기존 모드가 이미 지원하는 API 목록이 아니다.

## 1. 세 축을 교차시키되 합치지 않는다

| 축 | 값 | 판단 주체 |
|---|---|---|
| 지원 방식 | Provider / Compatibility | 등록 경로와 계약 출처 |
| 호출 방식 | game command / file / public Java / registered RPC | 실행기와 호스트 |
| 구현 소유권 | owned / temporary vendor / infrastructure / platform shim / user external | 의존성 원장과 출시 게이트 |

벤더링 worker를 세 번째 모드 어댑터로 만들지 않는다. worker는 MMMM 소유 application port의 임시 구현이며, 외부 도구 발견과는 다른 수명·배포·철수 정책을 가진다. 지원형 모드도 private Java API를 공용 통로로 임의 노출할 수 없고, 호환형도 충분한 계약과 검증을 갖추면 고수준 기능을 제공할 수 있다.

## 2. 최소 Provider SDK

Java SDK는 game Entity/Level을 wire DTO에 넣지 않는다. 공개 SPI는 다음 책임만 갖는다.

| 함수 | 입력 | 반환/효과 | 사전·사후조건 |
|---|---|---|---|
| `register` | Registrar | 등록 후보 핸들 | 기능·스키마 선언만. 월드 변경 금지 |
| `execute` | Invocation, LocalContext | CompletionStage<ProviderResult> | binding/action/context digest 확인 후 host 실행 문맥에서 수행 |
| `prepare` (선택) | 고정 입력·읽기 스냅샷 | 준비 정보 | pure인 경우 실제 쓰기 후 rollback하는 구현 금지 |
| `poll` (선택) | scoped job handle | progress/completion/evidence | 동일 작업에 대한 조회. 새 작업 생성 금지 |
| `cancel` (선택) | scoped job handle | 취소 접수/확인 상태 | 취소 요청과 완료를 구분 |
| `recover` (선택) | recovery plan·scoped token | ProviderResult | 현재 상태 사전조건 확인, 새 operation으로 기록 |

SDK가 호출하는 game thread executor는 플랫폼 셸이다. 자체 스케줄러·영구 project store·기하 변환기를 Java에 추가하지 않는다. SDK API version과 host wire version을 독립적으로 협상한다. API 클래스를 각 모드에 shading해 같은 클래스를 여러 번 정의하지 않도록 compile-only 사용 지침을 제공한다.

ProviderResult의 `complete`는 제공자의 보고다. Coordinator는 output schema, 실제 effect 기록, 필요한 독립 readback을 확인한 후에만 요구 수준의 성공을 확정한다. `job_accepted`는 jobHandle이 필수다. 비동기 exporter가 작업 예약만 하고 반환한 경우 complete로 반환해서는 안 된다.

### 등록 생명주기

호스트 준비 → 등록 지점 조회 → 출처 확인 → 스키마·API 검증 → bindingId 발급 → 기능별 readiness 게시 순서다. 이름이 같은 제공자가 서로 다른 게임/도구 인스턴스에 있을 수 있다. 모든 핸들은 binding·epoch·principal·type에 귀속한다.

Fabric entrypoint를 첫 호스트 포트로 사용하되 실제 26.3 컴파일/실행은 G2에서 확인한다[S17]. NeoForge는 같은 Registrar의 다른 플랫폼 구현이며 최소 MVP 출시 조건에 두 로더를 동시에 넣지 않는다. 무해한 조회로 확인할 수 없는 준비 조건은 `requires_runtime` 또는 별도 승인된 시험으로 남긴다.

## 3. CompatibilityProfile은 제한된 데이터 선언

프로필에는 applicability, action contract, input mapping, binding, output mapping, completion/verification policy를 기록한다. **임의 JS/Python/Rust 코드, shell 문자열, 무제한 루프, 조건 없는 reflection을 넣지 않는다.** 기본 MVP에서는 한 action당 하나의 binding이다. 복합 작업은 Coordinator의 단계 DAG로 표현한다.

### 매칭

- 모드/도구 ID, 확인된 버전, 로더, side, API signature 또는 endpoint contract가 모두 일치해야 한다.
- `supportedGameVersions`는 읽기 목록이 아니라 해당 binding의 실행 대상 조건이다. 외부 파일 도구도 생성물 타깃 프로필을 별도 요구한다.
- 코드가 Rust인지와 버전 검사는 무관하다. 버전 불일치를 범위 문자열 확대나 라이브러리 이름 변경으로 우회하지 않는다.
- profile digest와 출처 승인은 정책 저장소가 관리한다. profile 스스로 `trusted` 또는 관리자 권한을 선언해도 신뢰 상승이 없다.
- 설정상 재사용이 켜져 있고 승인된 profile이 환경과 일치하면 반복 설치 절차 없이 활성화한다. 새 hook 설치는 별도다.

### 값 매핑

BindingValue는 literal, 인자의 JSON Pointer, 승인된 context 필드, scoped handle 중 하나다. 문자열 enum→외부 enum 변환은 닫힌 mapping table로 가능하다. `frame`→`seconds`처럼 의미가 바뀌는 변환은 unit codec ID와 버전을 고정한다. 일반 산술 코드나 복잡한 mesh 변환은 profile이 아니라 등록된 codec/provider의 책임이다.

입력 필드가 사라졌다고 delete를 만들어내지 않는다. 출력 표면이 정보 일부만 보존한다면 loss를 반드시 반환한다. 필수 output schema를 만족하지 않는 실제 반환은 `OUTPUT_INVALID`이지만, 이미 수행된 쓰기는 실패 전 효과 없음으로 되돌려 표시할 수 없다.

## 4. 공통 실행기

### 4.1 Command executor

실제 호스트의 Brigadier와 paired principal의 command source를 사용한다. raw 명령은 원문을 유지하되 별도 action으로 계획한다. 고수준 명령 mapping은 typed token을 조립한 뒤 실제 parser로 확인한다. 문자열 인자, SNBT, resource location, selector는 각각 별도 codec이다. 공백 join/regex SNBT 변환을 사용하지 않는다.

자동완성 cursor는 **UTF-16 code unit offset**이다. Rust UTF-8 byte offset 또는 Unicode scalar index와 혼용하지 않는다. surrogate pair 중간 위치는 명시적으로 거절한다. 답변에 parser source revision과 replacement range를 포함한다.

명령 반환 정수·피드백·실제 완료는 다르다. 명령 트리만 보고 undo·범위 보존·제공 모드를 추정하지 않는다. 중앙 command room으로 이동한 뒤 `@p`, `~`, `^` 의미가 바뀌는 경우 context를 새로 생성해 계획한다.

### 4.2 File executor

ResourceRef → 승인된 workspace 경로 해석을 통해서만 접근한다. 절대 사용자 경로를 profile에서 직접 받지 않는다. 비교할 원본 hash와 출력 staging root를 고정한다. symlink/경로 순회/Windows device name/대소문자 및 정규화 충돌/ZIP 중복 경로/압축 해제 한도를 검사한다.

호환 도구가 자기 기본 디렉터리에 파일을 쓰려는 경우 그 경로도 plan footprint에 있어야 한다. 출력 폴더가 비어 있다는 사실을 성공으로 보지 않는다. manifest, 예상 자원, 참조 함수, stale output 잔존까지 확인한다. 전체 디렉터리 교체가 승인되지 않았으면 누락 파일을 삭제하지 않는다.

읽기·write staging·install·reload는 별개다. 실행 중 월드 region/level 파일에 직접 쓰지 않는다. live 적용은 host port를 이용한다. subprocess를 중단했다고 이미 저장한 파일이 원상복구됐다고 보고하지 않는다.

### 4.3 Public Java executor

정확한 승인 서명과 public lookup만 지원한다. MVP 값은 string/bool/int32/finite float·double/JSON list·map/scoped handle이다. 메서드가 요구하는 임의 사용자 클래스를 reflection으로 생성하지 않는다. static/registered receiver를 구분하고, receiver를 가져올 공통 resolver가 없으면 `UNSUPPORTED_RECEIVER`다.

탐지 시에는 클래스 초기화를 강제하지 않는다. 실제 호출에서 일어나는 static initialization은 호출의 효과일 수 있다. 접근 가능한 public 메서드라는 사실만으로 안전한 메서드라는 보장은 없으므로 명세 승인과 작업 권한 검사는 그대로 필요하다.

Thread affinity는 side만으로 충분하지 않다. client/server main queue 또는 외부 실행 문맥을 명세에 부여하고 호스트가 맞는 큐로 전달한다. API가 반환한 CompletionStage를 기다리는 동안 게임 메인 스레드를 block하지 않는다. Future의 예외에도 side effect evidence를 별도로 기록한다.

### 4.4 Registered RPC executor

초기 구현은 사용자가 등록한 로컬 `targetId`의 JSON-RPC 2.0 request/response와 bounded poll을 지원한다. endpoint/credential은 프로필이 아니라 설정 저장소에 있다. TCP 포트 스캔·인터넷 endpoint 자동 탐색·token forwarding은 하지 않는다.

외부 tool host의 `sessionEpoch`와 구현 digest를 pin한다. request accepted와 bake completed를 구분한다. jobHandle은 제공자가 반환한 원격 ID를 감싼 scoped handle이다. 원격 자원은 다운로드 승인과 hash 확인 후 로컬 CAS로 들인다. 외부 MCP tool을 중계하는 기능은 별도 transport 구현으로 확장할 수 있지만 로컬 JSON-RPC 지원을 곧 모든 MCP 연동 지원으로 부르지 않는다.

## 5. Scene → Bake → Import의 다중 문맥 계획

한 기능은 한 execution side를 갖는다. 여러 side를 이용하는 작업은 각각의 context pin을 가진 step으로 분해한다.

| 단계 | 문맥 | 읽기/쓰기 | 완료 근거 |
|---|---|---|---|
| 선택/충돌 스냅샷 | game server | 읽기 | coverage·영역 hash·관찰 tick |
| bundle 준비 | offline project | private staging | manifest·payload hash |
| 외부 편집/베이크 | external tool | 승인된 복사 장면·출력 | 제공자 완료 + output manifest |
| 결과 가져오기 계획 | offline project | 읽기/새 계획 | identity·time·loss·revision 검사 |
| 프로젝트 변경·팩 생성 | project workspace | 명시적 commit/staging | changeset·source map |
| 게임 적용 | game server/client 필요 시 분리 | 승인된 변경 | target readback |

외부 bake 결과는 사전에 bytes hash를 알 수 없으므로 result slot으로 연결한다. 이 slot의 **출처 step, JSON Pointer, 허용 schema, 최대 크기, 권한 footprint**를 계획에 고정한다. 응답이 이 범위를 넘으면 후속 작업을 진행하지 않고 replan한다. 반환된 문자열을 다음 단계의 임의 명령이나 endpoint로 해석하지 않는다. 사용자 장면에 반영하는 최종 patch는 bake 완료 뒤 구체적 diff를 보여주는 새 plan을 권장 기본으로 한다.

## 6. 발견·비활성화·실패

- loaded/connected/ready/verified를 각각 기록한다. 배포 파일 존재만으로 loaded라고 하지 않는다.
- 제공자 새 등록은 기존 plan의 binding을 바꾸지 않는다.
- read 실패는 snapshot 조건을 지키며 다른 제공자로 재계획할 수 있다. **전달된 쓰기 실패/타임아웃은 자동 fallback하지 않는다.**
- 결과 불명 scope만 예약 상태로 두고 다른 프로젝트/관계없는 읽기는 계속 허용한다.
- 도구 사용 토글을 끄면 신규 호출을 중지하지만 로그·상태 조회·reconcile은 계속 가능하다. 복구도 새 effect라면 필요한 별도 권한을 확인한다.
- 같은 JVM이나 unrestricted external process를 악성 코드 sandbox라고 부르지 않는다.

## 7. 외부 제작 도구에 요구할 최소 교환

도구는 모든 원본 기능을 보존할 필요는 없지만 다음은 정확히 보고해야 한다: stable object map, source revision, 좌표/단위, 시간, 표현 방식, 생성 artifact, 누락 정보와 알려진 손실, 실제 수행 버전. `physics.bake` 기능이 없으면 scene editor라는 이유로 라우팅하지 않는다.

.blend/.bdengine 파일을 저장·전송할 수 있는 능력, 그 구조를 해석하는 능력, 해당 프로그램에서 평가하는 능력은 별개다. 원래 앱이 필요한 경우 runtime requirement를 표시한다. bnmmvf 자료의 평가 mesh·초박형 면·키프레임 경계 문제는 중립 합성 fixture로 재현하고 원본 코드를 번들하지 않는다[F03,F04].

## 8. 필수 통합 시험

자체 지원형 fixture, SDK 없는 legacy fixture, 외부 편집기 fixture A, 외부 solver fixture B를 별도로 둔다. A는 좌표축과 이름을 바꾸고 stable ID를 유지한다. B는 job accepted→부분 artifact→완료→단절을 제어 가능하게 제공한다. 이들은 결과 기대값을 생산 구현과 공유하지 않는다. fixture 성공은 실제 Blender/BDE/사용자 모드 검증이 아니다.
