# SDK 없는 counter 인수 fixture

이 module은 직접 작성한 MIT fixture다. 게임 자산, 외부 맵과 스크립트를 포함하지
않으며 MMMM SDK나 host를 설치하지 않아도 command와 public Java API를 제공한다.
제품 버전은 `0.1.0`이고 실제 게임 실행 환경은 기존 JVM 경계와 같은 Minecraft
`26.3`, Fabric Loader `0.19.5`, Fabric API `0.162.0+26.3`, Java `25`를 사용한다.
Loom `1.17.21`과 Gradle `9.6.0`은 상위 설정의 고정 값을 따른다.

`LegacyCounterMod`는 서버 시작·종료와 tick에 연결한다. `LegacyCounterApi`의
정확한 static 공개 signature와 `/mmmm_fixture read`, `set`, `job`, `cancel`은
같은 counter cell을 사용한다. cell은 현재 서버 session, 연결된 player UUID와
dimension에 묶이고 write/job/cancel은 실제 관리자 권한을 확인한다. 별도 원장,
MMMM Project 데이터나 게임 월드 rollback은 소유하지 않는다.

상한은 64 cells, 16 pending jobs, 200 tick 지연과 counter `0..10000`이다.
job의 counter 변경은 최초 호출에서 동기로 한 번 수행한다. 이후 tick은 결과
전달만 수행하며 취소가 이미 적용한 변경을 복원하지 않는다. `before_mutation`,
`lost_response`, `late_completion`은 변경 전 거절, 변경 뒤 응답 실패와 취소를
확인하지 못한 원래 결과의 늦은 전달을 각각 재현한다. JobTicket은 실제 호출에서
발급한 private 생성 객체이며 immutable before/after와 상태를 보존한다.

2026-10-14의 관리된 JVM fixture 실행 `003`에서 `CounterEngineTest` 18개와
SDK wrapper 11개, 합계 29개 검사가 통과했다. 실패·error·skip은 모두 0이며
Java 25, Gradle 9.6.0, Loom 1.17.21 조합에서 JAR와 source JAR 생성까지
17개 task가 실제 실행됐다. Gradle 종료 0, 소유 자식 drain, 증거 export,
scratch 회수와 lease 해제를 확인한 로컬 결과다. 최종 배포 SHA의 결과는 아니다.
이 module의 검사는 순수 engine 및 fault 경계이며 실제 Fabric 서버 lifecycle,
게임 권한, SDK discovery와 command/public Java 연결의 AD 인수는 아직 미실행이다.

관리 실행기의 `jvm` 슬롯에서 상위 문서의 외부 cache, Java 및 유한 자원 설정을
제공한 뒤 다음 task를 실행한다. game classpath도 같이 typecheck해야 한다.

```text
:fixture-legacy:compileJava :fixture-legacy:processResources :fixture-legacy:test
```

시험 결과와 별도로 JAR 및 source JAR를 만들 때는 다음 task를 사용한다.

```text
:fixture-legacy:jar :fixture-legacy:sourcesJar
```

Loom run configuration은 관리된 외부 임시 경로를 사용한다. 이 task 목록은 게임
실행, EULA 동의, mod 설치나 원본 월드 사용을 수행하지 않는다. 실제 게임 검증은
고정 source와 배포할 같은 JAR bytes를 별도로 승인한 최소 복사 월드에서 진행한다.
정확한 source digest와 loaded class·loader·signature·초기화 정책 승인은
Compatibility 연결의 별도 책임이다. JAR의 hash나 이 문서는 write grant가 아니다.

필수 연결 기준은 [함수 계약 FN19/FN33/FN34](../../docs/FUNCTION_CONTRACTS.ko.md)와
[AD01–03·AD10 인수](../../tests/ACCEPTANCE.ko.md)를 따른다. SDK facade는
[fixture-provider](../fixture-provider/README.md)에서 같은 actual API를 호출한다.
로컬 검사 통과는 실제 게임 인수나 공개 배포 완료를 대신하지 않는다.
