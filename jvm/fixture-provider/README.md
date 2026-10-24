# SDK counter 인수 fixture

이 module은 직접 작성한 MIT Provider fixture다. [fixture-legacy](../fixture-legacy/README.md)의
동일한 actual `LegacyCounterApi`를 호출하므로 SDK, public Java와 command가
별도 counter 상태를 만들지 않는다. 게임 자산, 외부 맵과 스크립트를 포함하지 않는다.
제품 버전 `0.1.0`, MMMM 정본 wire 계약 `0.2.0`을 따른다.

빌드는 기존 JVM 경계의 Minecraft `26.3`, Fabric Loader `0.19.5`, Fabric API
`0.162.0+26.3`, Java `25`, Loom `1.17.21`, Gradle `9.6.0`을 재사용한다.
내부 source 의존성은 `provider-sdk`와 `fixture-legacy`다. 배포 시 SDK class는
명시적 `mmmm_host` runtime dependency가 공급하며 legacy mod는 별도 승인한
JAR를 사용한다. 이 fixture JAR에 SDK나 legacy JAR를 중복 포함하지 않는다.

`FixtureProvider`는 `counter_read`, `counter_set`, `counter_job` 세 action을
선언한다. 실제 LocalContext의 server side, principal, epoch, permission,
게임 thread를 확인하며 기존 SDK의 guarded queue와 `job`/`String` scoped handle을
사용한다. 등록당 최대 16개 원래 job을 보존하며 poll은 원래 stage만 관측한다.
다른 provider로의 재전송이나 job 재시작은 수행하지 않는다.

실제 ticket 취득 뒤 관측이나 effect 기록이 실패해도 원래 stage, handle과 failure
diagnostic을 유지한다. stage가 실제 terminal이 되기 전에는 pending으로 보고하고,
취소가 counter 변경을 rollback했다고 표시하지 않는다. caller의 원래 context와
invocation digest가 바뀌면 기존 job을 사용하지 않는다.

`FixtureProfiles`는 legacy의 정확한 static `read/set/job` Java signature 및
`read/set` command profile을 선언한다. executor와 dimension은 context에서 공급한다.
profile JSON, JAR digest와 `versionEvidence=declared`는 source pin 선언이다.
actual loaded class·loader·signature·no-init 검증과 현재 ProfileApproval을 발급하지
않는다. public Java 설치에는 명시적 mapping-only prepare policy가 필요하며
임의 constructor, receiver나 JobTicket을 profile에서 생성하지 않는다.

2026-10-14의 관리된 JVM fixture 실행 `003`에서 `FixtureProviderTest` 11개와
legacy engine 18개, 합계 29개 검사가 통과했다. 실패·error·skip은 모두 0이며
Java 25, Gradle 9.6.0, Loom 1.17.21 조합에서 JAR와 source JAR 생성까지
17개 task가 실제 실행됐다. Gradle 종료 0, 소유 자식 drain, 증거 export,
scratch 회수와 lease 해제를 확인한 로컬 결과다. 최종 배포 SHA의 결과는 아니다.
SDK 검사는 source/schema/queue/permission/handle, 늦은 완료 및 관측 실패를
authored port로 재현한다. 실제 Fabric SDK entrypoint discovery, source/signature
승인, typed footprint와 공통 plan/apply 연결의 게임 AD 인수는 아직 미실행이다.
같은 helper 성공을 독립적인 actual counter readback이나 실제 게임 인수로 승격하지 않는다.

관리 실행기의 `jvm` 슬롯에서 상위 문서의 외부 cache, Java 및 유한 자원 설정을
제공한 뒤 아래 task를 실행한다. 두 module의 전체 authored 검사 수는 29개다.

```text
:fixture-legacy:compileJava :fixture-legacy:processResources :fixture-legacy:test
:fixture-provider:compileJava :fixture-provider:processResources :fixture-provider:test
```

별도 JAR 및 source JAR 생성 task는 다음과 같다.

```text
:fixture-provider:jar :fixture-provider:sourcesJar
```

실제 제품 연결은 같은 보호 Store에 승인한 두 runtime JAR digest와 source provenance,
실제 loaded callback closure,
정확한 compatibility binding, typed counter footprint와 독립 readback을 설치해야 한다.
FN33 read와 FN34 plan은 그 뒤 기존 plan/apply/operation journal을 사용해야 한다.
이 Gradle 등록은 host의 자동 설치·게임 실행·EULA 동의·plan 승인과 공개 배포를
수행하지 않는다. [함수 계약](../../docs/FUNCTION_CONTRACTS.ko.md)과
[AD01–03·AD10 인수](../../tests/ACCEPTANCE.ko.md)의 실제 서버 검증은 별도다.
