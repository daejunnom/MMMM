# MMMM Java 호스트와 Provider SDK

제품 버전은 `0.1.0`, 정본 저장·wire 계약과 호스트 프로토콜은 `0.2.0`이다.
`provider-sdk`는 원본 `contracts/mmmm.schema.json`을 바이트 변경 없이 리소스로
포함하며 원본 SHA-256을 확인한다. 원본 예제와 digest 기대값은 checkout의
`examples/`, `tests/`와 `contracts/digest-projections.json`에서 읽는다.
별도 DTO 스키마나 예제 사본은 만들지 않는다.

`provider-sdk`는 불변 Invocation과 ProviderResult, 선언된 ActionDescriptor,
게임 스레드·권한·취소·핸들 접근 인터페이스를 제공한다. `host-core`는 짧은 수명의
세션, dispatch 중복 방지, callback, 이벤트와 인증 loopback을 담당한다.
`fabric-host`는 실제 서버 수명과 native registry, block state, Brigadier에 접속한다.
프로젝트 변경 준비, 객체 변환, 컴파일, 애니메이션 생성, CAS, 영구 operation
journal과 독립적인 완료 판정은 Rust가 담당한다.

## 확인한 target과 빌드 선택

2026-10-14에 다음 공식 배포 자료를 확인했다. 이 표는 의존성 선택 근거다.
실제 host jar 빌드나 서버 인수 성공을 나타내지 않는다.

| 항목 | 고정 값 | 공식 근거 |
| --- | --- | --- |
| Minecraft Java | `26.3` | [Minecraft 26.3 release](https://www.minecraft.net/en-us/article/minecraft-java-edition-26-3), [Mojang version metadata](https://piston-meta.mojang.com/v1/packages/11f1aefe473eefba0af62e3286c33b692807b2eb/26.3.json) |
| Java | major `25` | 같은 Mojang metadata의 `javaVersion.majorVersion` |
| Fabric Loader | `0.19.5` | [26.3 loader metadata](https://meta.fabricmc.net/v2/versions/loader/26.3), [Fabric 26.3 release](https://fabricmc.net/2026/09/15/263.html) |
| Fabric API | `0.162.0+26.3` | [Fabric Maven metadata](https://maven.fabricmc.net/net/fabricmc/fabric-api/fabric-api/maven-metadata.xml) |
| Loom | `1.17.21` | [Loom metadata](https://maven.fabricmc.net/net/fabricmc/fabric-loom/maven-metadata.xml), [exact module metadata](https://maven.fabricmc.net/net/fabricmc/fabric-loom/1.17.21/fabric-loom-1.17.21.module) |
| Gradle | `9.6.0` | [Fabric 26.3 release](https://fabricmc.net/2026/09/15/263.html) |

Loom/Gradle은 26.3 배포 안내의 1.17 계열·9.6.0 조합을 선택했다. 현재 최신 조합을
뜻하지 않는다. 1.17의 고정 patch가 1.17.21이며 module metadata는 JVM 21 및
Gradle plugin API 9.5.0을 선언한다. game compilation은 Java 25를 사용한다.
26.3은 이름이 공개된 game artifact를 쓰므로 mappings 의존성을 추가하지 않는다.
Loom plugin id는 `net.fabricmc.fabric-loom`이며 Fabric 공식 26.3 예제처럼
loader와 API를 `implementation`으로 선언한다.

Jackson `2.18.3`, networknt JSON Schema Validator `1.5.9`와 Java JSON
Canonicalization `1.1`은 JSON·정본 검증을 위한 infrastructure 의존성이다.
[networknt exact POM](https://repo.maven.apache.org/maven2/com/networknt/json-schema-validator/1.5.9/json-schema-validator-1.5.9.pom)은
Jackson, itu `1.14.0`, SLF4J `2.0.17` 및 YAML 의존성을 선언한다.
호스트 nested jar에는 Jackson, validator, itu, YAML/SnakeYAML과 JCS를 포함한다.
SLF4J는 game platform이 제공하는 버전을 실제 dependency graph와 jar 실행에서
검사해야 한다. 조립된 jar의 전이 의존성과 라이선스 인수는 아직 완료하지 않았다.

## 실행과 생성물

실행은 저장소 밖의 소유 build slot에서 관리한다. 실행기에서 `GRADLE_USER_HOME`,
`TMP` 또는 `TMPDIR`과 `--project-cache-dir`를 모두 checkout 밖으로 지정해야 한다.
설정 파일은 Gradle 9.6.0 및 외부 cache 경로를 강제한다. project cache를 CLI에서
지정하지 않으면 settings 실행보다 먼저 기본 `.gradle`이 만들어질 수 있으므로
설정 파일의 검사만으로 생성물 수명주기를 보장한다고 보고하지 않는다.
Gradle output은 소유 cache 부모의 `gradle-build/`, Loom run directory는 지정한
임시 루트로 간다. daemon, 병렬 Gradle 작업, 공유 build cache와 자동 JDK 내려받기는
사용하지 않는다. 호스트의 SQLite·CAS·journal은 이 빌드 cache의 소유 대상이 아니다.

빌드 실행기는 정확한 Java 25와 Gradle 9.6.0을 공급한 뒤 SDK/host-core 검사를
먼저 실행하고 Fabric compile 및 실제 jar 실행을 검사한다. 이 작업에서는 wrapper
binary를 다운로드하거나 저장소에 넣지 않았다.

## 인증과 게임 경계

호스트를 로드하는 것만으로 RPC listener나 write 권한이 생기지 않는다. 신뢰된
pairing 설치자가 실제 플레이어 UUID, 권한, 불변 ExecutionContext, source/action
승인 digest 및 write profile 검증 상태를 설치해야 한다. 이 API는 local composition
경계다. `config/mmmm-host.json`의 공개 설정 loader와 `/mmmm connect` 관리자 명령이
승인된 MMMM Rust binary의 `host-bridge --stdio-bootstrap`을 호출한다. 정확한 실행
파일 SHA, 실제 플레이어·host facts와 요청 scope를 확인한 뒤 Rust가 발급한 권한과
불변 context를 설치한다. 공개 설정 필드는 `executable`, `executableSha256`,
`dataRoot`, `projectId`, `scope`, `hostArtifactDigest`이며 권한·policyRevision·token은
설정에서 읽지 않는다. 이 연결 경로의 실제 실행은 아직 검증하지 않았다.

원본 프로토콜에 HMAC을 덧붙이지 않는다. 인증된 loopback은 `127.0.0.1` 임의 포트의
`POST /rpc`, memory-only bearer와 `X-MMMM-Epoch`를 사용한다. host method는
`mmmm.host`, params는 원본 HostRequest이며 JSON-RPC string id는 requestId와 같다.
배치·chunked transfer·browser Origin은 거절한다. 토큰은 HostHello·DTO·event·log로
반환하지 않는다. private bootstrap은 `MMMMHST1`, big-endian u32 length와 최대
1 MiB 공개 JSON frame, 별도의 32-byte capability를 사용한다. HTTP bearer는 이
raw capability의 lowercase hex 64자다. bridge handshake 전체는 wall clock 30초,
stderr drain은 64 KiB로 제한하고 stdout EOF와 child exit 0을 확인한다.
epoch는 paired **host** session의 값이다.

`/mmmm approve <planId> <planHash>`는 같은 승인된 실행 파일의
`host-bridge --stdio-approval`을 사용한다. Rust가 보유한 동결 plan, 현재 정책과
source/profile 근거를 확인한 뒤 별도의 불변 승인 session을 설치한다. 공개 설정이나
HostRequest의 임의 JSON은 승인 권한을 만들지 않는다. 승인 회전은 기존 runtime,
binding, generation과 작업 기록을 다시 만들지 않으며, 최대 8개의 원래 session
route를 보존한다. 원래 호출의 poll/readback은 원래 route를 사용한다. 같은 실행
identity에서 현재 승인으로 policyRevision과 그에 따른 contextDigest만 바뀔 수 있고,
contextId·환경·executor·선택 범위·anchor·좌표를 다른 대상으로 다시 묶지 않는다.

server 시작·종료와 datapack reload는 generation을 바꾼다. 이전 세션·context·핸들은
새 generation에 재사용하지 않는다. 등록은 최초 invocation 이전에 끝나며 실제
provider artifact hash와 신뢰된 Rust 계약 승인에 맞는 action만 허용한다.
Java가 action schema를 compile했다는 사실은 Rust의 full schema meta-validation이나
실제 game compatibility 인수를 대신하지 않는다. 같은 JVM의 Provider는 신뢰된
확장 코드이며 SDK가 악성 Java 코드를 sandbox하는 것은 아니다.

## 현재 native action과 inspect

| 경계 | 입력·출력과 효과 |
| --- | --- |
| `mmmm:block_read` / `mmmm:block_state_read` | 실제 dimension·int32 position, 실제 complete block state 및 관측 tick. loaded chunk만 읽는다. |
| `mmmm:block_patch` / `mmmm:block_state_patch` | expectedState·desiredState, 실제 native before/after 및 setBlock 반환값. block entity가 있는 source/destination은 거절한다. 간접 엔진 효과와 NBT는 증명하지 않는다. |
| `mmmm:command_execute` / `mmmm:raw_command` | 원문 command를 Brigadier로 parse하고 게임의 실제 제한된 ExecutionContext에서 실행한다. 호출별 native callback의 int32 반환만 기록하며 effects는 unknown이다. 명령 반환을 대상 완료나 독립 readback으로 승격하지 않는다. |
| `mmmm:authored/instantiate`, `/clone`, `/relocate`, `/display_patch`, `/command_patch`, `/scene_patch` | 입력은 닫힌 `{preparedChange: ResourceRef}`다. Java는 CAS를 읽지 않고 별도 trusted 승인에 결합된 Rust의 sealed native instruction 및 정확한 원문 명령을 실행한다. Java host artifact는 native 실행의 출처이며, Rust의 authored commit·컴파일 출처를 대신하지 않는다. |
| inspect `command_complete` | 실제 paired player의 source와 UTF-16 span으로 원본 CommandSuggestions를 반환한다. |
| inspect `execution_context`, `dependency` | 설치된 불변 context와 등록된 action·implementation digest만 반환·비교한다. |
| inspect `block_read`, `precondition` | 별도의 승인된 observation context에서 실제 target을 읽는다. `block:<dimension>:<x>:<y>:<z>` point subject의 `region_snapshot`을 지원한다. `full_target`은 block entity가 없는 직접 block-state point 전체에만 적용하며, region·NBT·entity·간접 효과 전체로 확대하지 않는다. |
| inspect `world.shape_probe`, `world.shape_query` | 실제 state·neighbor·fluid context와 로드된 dependency를 관측한다. collision/outline은 native voxel AABB 원시 바이트를 전달한다. entity handle와 support/fluid geometry는 명시적인 unsupported다. |
| inspect `native_registry` | 실제 live block/item/entity registry 원시 바이트·digest·generation과 관측 시각을 전달한다. raw 256 KiB를 넘으면 INPUT_LIMIT이며 잘라낸 결과를 complete로 보고하지 않는다. |
| inspect `registered_read` | 원본 RegisteredActionRequest와 실제 등록된 read callback을 사용한다. fake Invocation이나 작업 원장을 만들지 않으며 변이·job 보고를 거절한다. |
| inspect `runtime_sources` | 실제 game/mod archive의 입력 컨테이너 SHA, 현재 ordered server pack view와 generation을 관측한다. 동적·불명확한 pack과 client pack은 unknown/null이다. |
| inspect `native_targets` | 닫힌 block-state·block-entity·entity·storage·score·objective selector와 실제 native codec으로 bounded raw before/readback을 반환한다. 대상마다 membership·presence·coverage를 보존하며 tick window나 같은 호스트 결과를 독립 완료로 승격하지 않는다. |
| inspect `undo_registration` | 선등록된 source→undo 관계와 실제 descriptor/source digest를 반환한다. 원래 operation report의 undoTokenRecord는 host가 동결한 영수증이며 비공개 provider token을 포함하지 않는다. |
| inspect `undo_role` | 정확한 binding/action의 전체 descriptor와 `ordinary`·`source`·`recovery_only` 역할, 실제 등록 관계 및 세대 digest를 반환한다. 성공한 전체 조회는 등록 세대를 닫으며 불완전한 등록을 ordinary로 처리하지 않는다. |
| inspect `undo_job` | 원래 복구 호출의 실제 SDK 실행 사실과 소비한 원래 source 호출·공개 영수증 연결을 조회한다. 다섯 영수증 참조 인수를 block/entity selector로 해석하지 않는다. |

`rotationDegrees`의 array 순서는 원본 자료에 명시되지 않았다. MMMM 구현 결정은
`[pitchDegrees, yawDegrees]`이며 native Vec2도 같은 순서를 사용한다. 0이 아닌 두
축의 실제 명령·completion 검증은 아직 수행하지 않았다.

shape dependency는 승인된 scope와 이미 loaded된 chunk를 읽는 getter에서 수집한다.
실제 empty VoxelShape만 빈 boxes로 반환한다. 알 수 없는 pack/mod/game artifact
fingerprint는 null이며 arbitrary mod getter의 전체 의존성을 입증하지 못하므로
dependencyScope는 unknown이다. Rust는 이 결과를 좁은 캐시나 검증된 target
geometry로 승격하지 않는다. Java는 mesh나 geometry CAS payload를 만들지 않는다.

Provider 완료, cancel 요청 또는 callback의 acknowledgement는 독립 완료나 종료
확인이 아니다. 알 수 없는 쓰기 효과는 자동 재시도·성공·rollback 완료로 바꾸지 않는다.
dispatch cache는 유한하며 기존 invocation evidence를 임의 퇴거시키지 않는다.
socket 수명과 callback deadline은 game tick과 별개의 wall clock으로 제한된다.
객체와 job handle은 session·binding·원래 contextId/contextDigest·type·Java class에
묶인다. 같은 session의 다른 context에서도 재사용할 수 없으며, 새 승인 session으로
자동 이전되지 않는다. chunk event에서 얻은 객체도 현재 FULL 이상으로 접근 가능한
상태인지 매번 확인하며, INACCESSIBLE chunk를 읽거나 다시 로드하지 않는다.

native batch는 승인된 하나의 `stage`·`activate`·`cleanup` 부분집합을 실행한다.
원래 sealed step의 객체·node·instance·prefab provenance, command array의 JCS SHA,
compiler·codec·target pins와 실제 before target을 결합한다. 전체 export의 cleanup을
즉시 실행하거나 Java에서 원하는 NBT·display matrix를 재생성하지 않는다.
자동 command block 활성화는 실제 auto·power·예약 tick의 quiescence와 정확한 원문
source의 승인된 간접 효과 범위까지 요구한다. 미관측 범위는 unknown·unsupported를
보존하며 자동 rollback이나 격리 완료를 주장하지 않는다.

native target 관측은 실제 게임 codec으로 entity·block entity·score·objective를
직렬화한다. objective의 모든 현재 holder와 표시 슬롯은 readonly native map view에서
개수 상한을 확인한 뒤 읽는다. storage는 이미 캐시된 namespace만 읽으며 처음 접근하는
namespace를 로드하지 않는다. UUID 조회 실패는 전역 부재가 아니다. 정확한 원래
호출에 결합된 native kill 뒤 객체가 실제 destroyed/not-save 상태이고 로드된 replacement가
없을 때만 원래 관측 객체의 부재를 보존한다. 그 history를 읽는 `sourceInvocationId`는
원래 session·context·epoch와 일치해야 한다.

두 readonly Mixin accessor는 Commands의 현재 실행 context와 Scoreboard의 map을
읽는다. native 명령은 기존 실행 context가 있으면 queue와 효과를 만들기 전에 거절한다.
전역 Brigadier result consumer를 바꾸거나 새 native execution context를 흉내내지 않는다.
accessor 방식은 [Fabric 공식 문서](https://docs.fabricmc.net/develop/mixins/accessors)를 따른다.
`runtime_sources.platformReadAccess`는 실제 설치 여부, own class/config 입력 resource
SHA와 host container를 별도로 기록한다. `compiled_input_resource_bytes`와
`loadedDefinitionBytes: not_observed`를 구분하며 게임의 transformed class bytes를
관측했다고 해석하지 않는다. source facts의 안정 digest 내부 recipe는
`mmmm.runtime-source-facts-digest/1`이고, 정확한 source facts 객체에서 최상위
`observedAt`만 제외해 RFC 8785 JCS SHA를 계산한다. nested time·generation·pack order·
unknown source 필드는 제외하지 않는다.

`target_admission`은 원래 sealed native step과 현재 source facts·generation을 받는
읽기 전용 parser 경계다. 실제 loaded definition의 parser·predicate·handler 전체
출처 승인 port가 없는 현재 연결에서는 parser와 handler를 호출하지 않고
`LOADED_DEFINITION_UNAVAILABLE`을 보존한다. class resource나 원본 JAR의 SHA를
loaded definition 증명으로 바꾸지 않는다. `calibration_run_source`도 이미 실제
dispatch에서 발급한 불변 CalibrationRun 영수증을 조회하는 typed port이며,
요청에 적힌 program·command·source SHA로 새 증명을 만들지 않는다. 현재 실제
발급기가 없으면 `CALIBRATION_RUN_ISSUER_UNAVAILABLE`로 거절한다. 숫자 calibration의
정확한 normative program 실행·출처·독립 output 증명은 후속 실제 연결과 게임 인수가
필요한 이번 MVP의 미완료 조건이다.

`undo_material`은 원래 source 호출의 열린 세션과 전체 context에서만 원본 Invocation,
등록된 source→undo 관계, nullable 공개 token receipt 및 실제 paired player UUID를
반환한다. private provider token은 반환하지 않는다. 새 승인 세션은 원래 job의
조회 권한을 자동으로 받지 않으며, source receipt는 원래 세션을 닫기 전에 Rust의
단일 원장에 보존해야 한다. 복구 callback은 현재의 별도 승인과 실제 after target을
mutation 직전에 다시 확인한다. 원래 receipt의 source policy와 context는 그대로
보존하며, 새 복구 context에서 바뀔 수 있는 authority 필드는 policyRevision과 그에
따른 contextDigest뿐이다.

`undo_role`의 요청은 닫힌 `{kind, bindingId, actionId}`이며 실제 등록된 binding과
action을 함께 선택한다. source의 `provider_undo` 선언에는 선등록된 source→undo 관계가,
실제 Recover callback에는 역관계가 있어야 한다. 전체 등록 세대에서 이 검사를 마친
첫 성공 조회는 추가 provider/action/undo 등록을 거절한다. 실패한 조회는 세대를
성공으로 닫지 않으며 기존 setup 오류를 자동으로 새 세대로 대체하지 않는다.
선택한 action에 직접 연결된 관계만 최대 64개, 최종 응답은 256 KiB로 제한한다.
한도를 넘으면 `INPUT_LIMIT`이며 생략한 관계를 완전한 조회로 반환하지 않는다.
등록 세대 digest는 실제 원본 ProviderInventory의 inventoryRevision과 정렬된 전체
undo 관계의 binding/action 및 정본 descriptor SHA를 포함한 JCS 객체의 SHA다.
Fabric 응답에는 이 역할 조회와 현재 context/environment, 실제 runtime source facts
digest, host artifact SHA, registry generation 및 관측 tick/시각을 결합한다.
이 관측은 Apply 권한이나 runtime profile 검증을 발급하지 않는다.

`undo_job`은 닫힌 `{kind, invocationId}` 요청으로 원래 복구 HostSession과 전체
설치 문맥을 확인한다. claim 때 원자적으로 얻은 source Invocation과 공개 영수증은
원래 source의 실제 session route에 묶이며, 같은 scalar ID의 최신 session으로
이동하지 않는다. 비공개 제공자 토큰은 조회에 포함하지 않는다. 실제 callback 진입,
변이 경계, 취소, polling, 원래 future의 완료/실패, context 폐기 및 대기 중인
게임 스레드 callback 수를 각각 기록한다. timeout으로 만든 ProviderResult나 늦게
완료된 future는 이미 닫힌 보고를 성공으로 바꾸지 않는다.
`synchronous_quiescent`는 실제 synchronous 등록 callback이 끝나고 SDK context가
닫혔으며 추적된 게임 스레드 작업과 접수된 비동기 job이 없다는 SDK 실행 사실이다.
비동기 job의 실제 종료 producer가 없으면 접수 이력을 계속 outstanding으로 보존한다.
이는 원래 세계 대상의 복원, 간접 효과의 종료나 rollback 완료 증명이 아니다.
Rust는 단일 원장에 보존한 실제 source 대상과 before/after 관측을 새 권한으로 다시
읽어 효과를 `None`·`Some`·`Complete`·`Unknown`으로 판정한다. 미관측 target codec,
간접 효과 또는 비동기 종료는 unknown으로 남기며 token 재사용이나 claim 해제를
허용하는 근거로 바꾸지 않는다. 새 역할/job 회귀 소스는 별도 실제 검사 전까지
이 문서의 이전 Java 성공 근거에 포함하지 않는다.

현재 native batch·승인 회전·관측기·readonly accessor는 작성한 후속 source이며 실제
컴파일과 게임 인수를 계속해야 한다. 전형적인 prefab/display/entity/module/scene 전체
적용, command source의 간접 효과 폐쇄, 정확한 target profile의 numeric/runtime 근거와
독립 readback은 각자의 실제 인수 대상이다. 공개 release와 write profile 승인은 이
문서만으로 달성되지 않는다.

## 검증 상태

원본 전체 schema example, digest fixture 10개, strict JSON/JCS 및 불변 DTO의 테스트
소스를 작성했다. host-core는 permission drift, 미검증 write profile, queued cancellation,
invocation dedup, session/binding/context/type handle 격리 및 terminal job context 폐기를 검사한다.
이 테스트들은 runtime 안전 경계의 검증이고 실제 Minecraft 인수와 별도다.
관리된 `sdk-core004` 실행에서 Java 25 및 Gradle 9.6.0으로 SDK production/core compile과
SDK 92개·host-core 4개 검사가 통과했다(failures/errors/skipped 모두 0).
후속 registered read, canonical contract URI의 offline resolution과 provider undo token
검사는 `jvm006`에서 SDK 107개·host-core 29개가 통과했고 `jvm007`에서도 같은 성공 근거가
재사용됐다. `jvm007`의 첫 Fabric compile은 ChunkPos와 chunk-load callback의 실제 API
차이 네 곳에서 실패했다. 정확한 게임 JAR의 유한한 `javap008`/`javap009` 관측에 맞춰
그 차이와 접근 가능 상태 검사를 수정했다. `jvm010`은 SDK 107개 성공 근거를 재사용했고
host-core 32개와 public-java-adapter 17개 검사 및 Fabric `compileJava`가 실제 통과했다.
각 test의 failures/errors/skipped는 모두 0이다. 이 결과는 이후에 작성한 native batch,
readonly Mixin, plan approval/profile 및 실제 mutable-target undo 회귀를 포함하지 않는다.
`jvm018`에서는 후속 production Java 전체와 SDK 107개·host-core 56개·public-java-adapter
17개 검사가 통과했다. Fabric 경계 검사 30개 중 17개는 command text의 JCS digest를
계산할 때 pinned canonicalizer가 primitive root를 받지 못해 실패했다. scalar를 같은
JCS engine의 singleton array에서 직렬화한 뒤 외부 괄호만 제거하는 좁은 수정을 했고,
독립적인 primitive byte 기대값 검사를 추가했다. 수학적으로 같은 javaMajor의
`25`·`25.0`·`2.5e1` 비교도 정확한 Int32 변환으로 맞췄다. 이 두 수정은 후속 관리된
실행에서 확인했다. `jvm019`에서는 Java 전체 컴파일과 SDK 108개·host-core
56개·public-java-adapter 17개·Fabric 경계 33개 검사가 모두 통과했으며,
failures/errors/skipped는 모두 0이었다. 이 결과는 loaded definition 출처의 실제
발급, CalibrationRun 실행 및 실제 게임에서의 profile 인수를 대신하지 않는다.
jar 조립·실제 서버 native readback,
private bridge pairing/approval과 공개 배포는 아직 `not_run`이다.
