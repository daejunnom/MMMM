# MMMM 구현 착수 조건

저장소 규약은 제품 구현 전에 적용한다. 실제 기능 구현과 인수는 원본 계약,
검증된 도구와 결과 근거를 연결해 진행한다. 현재 범위는 G0부터 G4와 공개
`v0.1.0` 배포까지이며 G5와 G6은 후속이다.

## 현재 기준

현재 구성은 작업 규약, 구현 및 수명 기준, PR 템플릿, 선언 구조 정책, 원본 계약과
Rust 구현 기반이다. 원격 `main`, `develop`과 기능 브랜치에 기준선을 반영했고,
제품 구현은 Draft PR #1에서 진행한다. 원격 `main`과 `develop` 보호는 2026-10-15에
적용하고 실제 API readback을 확인했다. Windows의 빌드 관리 도구 bootstrap은
실제로 통과했으며, 제품 인수와 현재 통합 검증은 미완료다.

## G0 선행 조건

- [x] 원본 `contracts/mmmm.schema.json`, `contracts/function-index.json`과 예제 패키지를 확보한다.
- [ ] 원본의 버전, provenance, digest와 문서 의미를 확인하고 저장 및 wire 계약 `0.2.0`을 도입한다.
- [x] 현재 배정에 Git 구성이 포함되면 빈 원격 상태를 확인하고 bootstrap을 수행한다.
- [ ] 첫 Rust와 JVM 빌드로 실제 toolchain, feature, JDK, Gradle 및 의존성을 고정한다.
- [ ] 관리 도구 bootstrap부터 모든 대형 빌드 및 테스트 출력을 외부 소유 슬롯에 둔다.
- [ ] Windows, Linux와 macOS에서 성공, 실패, timeout, 취소 및 자식 종료 확인을 검증한다.
- [ ] lease, 한도, 경로 이탈, cache 회수와 증거 내보내기 실패를 검증한다.
- [ ] Rust 구조 검사기를 도입하고 metadata만 읽는 범위와 거절 경로를 검증한다.
- [x] 원격 구성이 배정되면 실제 검사 등록과 `main` 및 `develop` 보호 설정을 확인한다.
- [ ] 담당자와 리뷰 구성을 확인하고 필요한 CODEOWNERS를 등록한다.

원본 70개 파일의 SHA-256 무결성을 확인했고 선택 도입한 61개 파일은
`contracts/handoff-input.json`에 기록했다. 계약의 의미, DTO와 공식 JCS 검증은
별도로 진행한다. 관리 도구와 구조 검사를 검증하기 전 실행 명령 또는 자동 정리의
완료를 보고하지 않는다.

D058의 원격 보호는 실제 성공 이력이 있는 `foundation-result`와 `jvm-result`를
GitHub Actions app `15368`에 고정하고, 최신 대상 기준과 관리자 적용·PR·대화 해결을
요구한다. force push와 삭제는 금지하며 bypass는 없다. 초기 단독 유지보수이므로
필수 외부 승인 수는 0이고 code-owner 및 마지막 push의 타인 승인은 요구하지 않는다.
이를 타인의 리뷰를 받은 것으로 보고하지 않는다. 관리 실행 `368`의 첫 API 요청은
`contexts`와 `checks` 동시 사용으로 HTTP 422를 받아 적용되지 않았다. 원 요청·오류와
정리 기록을 보존했고, 구형 `contexts`를 제외한 `369`는 두 branch의 적용 및 독립 GET
대조 후 exit 0·drain·출력·export·scratch 정리·lease 해제를 완료했다. readback SHA는
main `47c47a6e538bc144aa8ce9f4b99ae37872a015598293ac2e0af8d958274b3a12`,
develop `93b0597475b808a096ebb6d443d05b9fca0eabb11fc6c784fe1f8a92809e635c`다.

## 2026-10-14~15 로컬 구현 검증

| 검증 | 실제 결과 | 적용 범위와 남은 조건 |
|---|---|---|
| 원본 패키지 | SHA-256 목록 70개 일치 | 선택 도입 61개 파일의 원본 바이트 보존 |
| Windows PowerShell/C# 관측 callback | 실제 자식 6.2초, callback 1회, 종료 0, Job drain, 오류 없음 | 빈 문자열 상호 운용 오류의 재현 및 수정 검증 |
| Windows 관리 도구 bootstrap | Cargo 종료 0, Job drain, export, scratch 정리와 lease 해제 | 짧은 외부 출력 루트 사용; 다른 OS는 미실행 |
| Windows 관리 도구 첫 Rust 검사 | 40 통과, 5 실패, 자식 fixture 1개 직접 실행 제외 | 실제 프로세스 시작과 로그 export 경로 수정 후 재검사 필요 |
| 프로세스 경로 비교 | 일반 경로의 내부 normal 검사는 통과; 같은 경로의 VerbatimDisk 형식은 timeout | 작업 디렉터리 전달 형식의 원인 조사 근거이며 수정 인수는 별도 |
| Windows 관리 도구 최종 관측 경계 재검사 | 55 통과, 실패 없음, 자식 fixture 1개는 감독 검사가 직접 호출 | 파일·디렉터리 삭제 경합, 소유 기록·고정 루트 누락과 중첩 링크 거절 포함; 출력 보존, 정리와 lease 해제 통과 |
| Windows native bridge | callback, 자연 종료, 엄격한 잔여 자식 거절, 명시적 소유 자식 정리의 4개 실행 통과 | 엄격한 실패를 성공으로 바꾸지 않고 원래 명령 code와 실제 drain을 보존 |
| Git 구조 검사 | stage 0 파일 130개 검사, 위반 없음 | 정책 JSON 하나만 내용 조회; 이후 stage 변경은 재검사 |
| Windows 제품 모듈 첫 통합 검사 | 6개 crate 컴파일 성공; Provider 15, 계약 26, 도메인 43, 정보 카탈로그 16 검사 통과 | 저장 원장 13개는 Windows 경로 검사에서 실패하여 원인 수정 중; 빌드 도구 검사는 해당 실행에서 시작되지 않음 |
| 활성 임시 파일 관측 보완 bootstrap | Cargo 종료 0, drain, export와 lease 해제 통과 | 소유 활성 임시 하위 항목의 삭제 경합만 허용; 누락 허용 전 상위 경로와 오류 항목 자체의 링크 경계 검사 포함 |
| 의존성 및 출시 순수 판정 | 30개 검사 통과, Cargo 종료 0, export 및 lease 해제 | 인증 모사 fixture의 판정기 검증이며 실제 vendor 채택, 실제 게임 또는 출시 근거가 아님 |
| Windows 저장 원장 경로 수정 재검사 | 15개 검사 통과, Cargo 종료 0, export 및 lease 해제 | 실제 임시 SQLite/CAS, canonical 경로, 재시작·중복 방지·관측 효과 보존과 후속 dispatch 차단; 전원 손실 검증은 별도 |
| 공통 application 경로 | 16개 검사 통과, Cargo 종료 0, export 및 lease 해제 | 실제 임시 SQLite/CAS와 stateful 독립 target fixture; actual host·게임 및 인증 transport는 통합 중 |
| Windows 전체 workspace 검사 | 8개 crate의 216개 검사 통과, 실패 없음 | 자식 fixture 1개는 감독 검사가 직접 호출; 인수 ID 82개 및 실제 게임의 통과 수와 구분 |
| Windows 코드 검사 | workspace 전체 formatting 및 all-targets Clippy `-D warnings` 통과 | 수학 반복문 정리 후 도메인 43개 재검사 통과; 다른 OS는 CI에서 실제 검증 |
| 첫 3개 OS 기반 CI | 세 OS 모두 Rust 제품 검사 전 실패 | macOS의 rustup 및 Linux의 Python 복수 탐색 경로, Windows의 native 시작 실패; 동일 SHA의 성공으로 재해석하지 않음 |
| Windows Cargo 사전 검사 실패 복구 | native 실행 전 거절, 정확한 소유 기록 대조와 빈 scratch 확인 후 수동 lease 해제 | 정상 rustup proxy 처리와 lease 획득 전 사전 검사로 수정; 수동 복구는 자동 완료 근거가 아님 |
| Windows 수정 launcher 첫 Cargo 실행 | 실제 Cargo 종료 101, drain 및 실패 로그 export, 정확한 소유 slot 완료와 lease 해제 | 병행한 승인 의존성 변경으로 locked resolution 거절; 제품 또는 bootstrap 성공으로 표시하지 않음 |
| Windows 수정 launcher 재검사 | Cargo 종료 0, Job drain, export, 소유 자식 정리와 lease 해제 통과 | 승인 의존성 변경의 명시적 lock 갱신을 선택; 원격 Windows 시작 실패의 후속 CI 확인은 별도 |
| 두 번째 3개 OS 기반 CI | Linux 구조 검사·formatting·tests·Clippy 통과; 집계 실패 | Windows native bootstrap은 통과했으나 미설정 PowerShell native exit 변수를 실패로 판정; macOS 최초 컴파일 준비 중 EPERM, 원인 확인 중 |
| Windows PowerShell 종료 판정 회귀 | caller native exit 7을 유지하면서 bootstrap 종료 0, 실제 완료 receipt와 lease 해제 확인 | PowerShell script의 예외 및 native receipt를 사용하며 과거 native exit를 bootstrap 결과로 사용하지 않음 |
| Coordinator와 CLI 첫 통합 컴파일 | Windows lib 및 bin 컴파일 통과 | 인증 transport·부분 자료 조회와 공통 application 연결; 실제 native peer 검사 및 game pairing은 별도 |
| 부분 자료 조회·형상·큰 결과 집중 검사 | application 19, reference 30, runtime 26 검사 통과 | 실제 임시 SQLite/CAS·재시작·범위/ACL·무결성·큰 결과의 자료 참조; native shape와 실제 게임의 인수는 별도 |
| JVM 도구 준비 | 공식 JDK 및 Gradle ZIP SHA-256 일치, 유한 extraction 및 외부 소유 cache 보존 | Temurin `25.0.4.1+1`, Gradle `9.6.0`; JVM 제품 컴파일 및 테스트 결과와 구분 |
| 첫 JVM 실행 | Java 시작의 jimage 경로 오류로 실패, 종료 및 로그 보존 | Windows native 경로 형식 경계 확인 후 재검사 중; 오류 파일은 내용 출력 없이 외부 증거 위치로 이동 |
| 정본 소유 문서 저장 집중 검사 | runtime 35 검사 통과, 실패 및 warning 없음 | historical Project membership, exact revision/CAS, ACL·취소·재시작·source pin 손상; authored compound commit은 다음 통합 대상 |
| JVM SDK 실제 제품 컴파일 | Java 25, Gradle 9.6.0 및 Loom 1.17.21 구성, SDK compileJava/resources/jar 통과 | deprecated API 수정 후 제품 소스 컴파일; 테스트 소스 반환형 오류 수정 및 host-core/Fabric 검증은 별도 |
| 세 번째 3개 OS 기반 CI | Windows와 Linux의 전체 기반 job 통과; 집계 실패 | macOS prepare/supervise 단계 EPERM 유지; 공개 소스 함수와 줄 번호를 한정해 다음 실행에서 원인 확인 |
| 변경 전 상태 보존과 Coordinator 집중 검사 | application 23 검사 통과; Coordinator 22 통과, 8 실패, 1 ignored | 원래 상태의 독립 capture 및 원장 연결은 통과; Windows endpoint publish의 실제 native 오류와 시작 실패 진단을 수정 중 |
| JVM SDK 및 호스트 코어 검사 | SDK 92, host-core 4 검사 통과; 실패·오류·skip 없음 | Java 25와 실제 Gradle 실행 및 XML 결과 확인; Fabric 게임 호스트와 실제 게임 인수는 별도 |
| 교환 모듈 첫 실제 검사 | 57 통과, 2 실패 | 좌표 숫자의 JSON 표현 비교와 수정·삭제 충돌 검사 순서를 수정; 수정 후 결과는 재검사 대상 |
| 네 번째 3개 OS 기반 CI | Windows와 Linux의 전체 기반 job 통과; 집계 실패 | macOS reserved launcher의 ValueError가 먼저 발생; 종료 경로의 EPERM과 구분하며 원본 supervision proof와 빈 Cargo 로그를 보존 |
| 컴파일러 집중 검사 | 70 검사 통과, 실패 및 ignored 없음 | 수학·scene·animation·pack의 순수 출력 및 거절 경로; strict Clippy 수정 후 재검증과 실제 native parser·game 인수는 별도 |
| Reference capture 집중 검사 | 39 검사 통과, 실패 및 ignored 없음 | 기존 30개 및 실제 원문·CAS·rights·ordered identity 조합 9개; 실제 paired game source 및 자산 resolver 연결은 별도 |
| JVM 새 읽기·schema·undo 경계 검사 | SDK 107, host-core 29 검사 통과 | 원본 계약에 맞게 fixture 수정 후 실제 검사; 다음 JVM 실행에서 해당 입력의 성공 재사용을 확인. 실제 게임 인수는 별도 |
| Fabric 호스트 첫 실제 컴파일 | Minecraft 26.3 API 오류 4개로 실패 | 실제 의존성 JAR의 API를 검사해 ChunkPos 및 청크 이벤트 차이를 확인; 수정 후 재검사 대상 |
| 다섯 번째 3개 OS 기반 CI | Windows와 Linux의 전체 기반 job 통과; 집계 실패 | macOS `set address space limit`의 native EINVAL을 확정; Darwin 전용 VM 및 관측 memory 정책을 구현 중 |
| Darwin 자원 정책의 Windows 검사 | 관리 도구 64 통과, 1 ignored | 순수 Darwin 정책·API 분류 9개 포함; 실제 macOS native 동작은 미검증 |
| 여섯 번째 3개 OS 기반 CI | Windows와 Linux의 전체 기반 job 통과; 집계 실패 | macOS VM 설정과 확인은 성공했으나 동기 파일 크기 검사 중 성공 표본 간격이 2817 ms로 늘어 1초 제한을 초과; 원본 실패를 보존 |
| 파일 순회 중 자원 관측과 입력 파싱 제어 | Windows 관리 도구 69, 계약 28 검사 통과; 두 crate의 all-targets Clippy 통과 | fallible 순회 체크포인트와 최초 native 오류 보존, JSON 원래 취소 오류 보존; 실제 macOS 관측 간격은 후속 CI 대상 |
| 교환·계획·실행·저장 집중 검사 | application 38, exchange 59, planner 37, runtime 63 검사 통과 | 실제 임시 SQLite/CAS와 순수 도메인 및 실패 경로; 이후 raw bytes 읽기와 호스트 연결 변경은 별도 재검사 |
| JVM 호스트와 공개 Java 어댑터 | host-core 32, public-java-adapter 17 검사 통과; SDK 107개의 유효 성공을 재사용; Fabric compileJava 통과 | 실제 Gradle 및 XML 결과 확인; 이후 native 실행·승인 변경과 실제 서버·클라이언트 인수는 별도 |
| Coordinator와 CLI의 확장 검사 | CLI 12 통과; Coordinator 73 통과, 11 실패, 1 ignored | 정책 이름 fixture 10개와 native 종료 증거 경로 fixture 1개를 수정 중; 실제 stdio 통합 검사 실행은 lib 성공 이후 별도 |
| Coordinator 인증·범위 재검사 | CLI 12, Coordinator 86 통과; 1 실패, 1 ignored | 잘못된 정책 이름 fixture 10개 및 per-Project scope 검사는 통과; native 종료 증거의 `child_parent_identity` 경계는 미해결. 이후 retained authentication hook은 미실행 |
| 일곱 번째 3개 OS 기반 CI | Linux와 macOS 전체 기반 job 통과; Windows와 집계 실패 | source `3f022c91e32324ae0a16fe7abbfe00fd4ce98ce4`; Windows 저장 크기 관측의 native 접근 거부를 그대로 보존. 실제 Darwin 성공과 새 제품 인수를 구분 |
| 일반 자원 정책과 저장 관측 진단 | Windows 관리 도구 81 통과, 1 ignored | 실제 소유 자식의 Job 설정·readback과 bounded 진단 검사 포함. 이 실행의 부모는 이전 감독 도구이며 새 정책을 모든 제품 실행에 적용했다고 표시하지 않음 |
| 여덟 번째 3개 OS 기반 CI | 3개 OS bootstrap·구조·formatting 통과; 제품 검사와 집계 실패 | source `8d2ac7f49132eea55ba527f53232958f966abdc1`; Windows·Linux의 테스트 취소 호출 컴파일 오류와 Darwin의 variadic `mode_t` 승격 오류를 보존·수정. 제품 테스트 성공으로 표시하지 않음 |
| 격리 stdio worker 실제 검사 | Windows worker 시작 실패, native `10106`, drain 확인 | bootstrap과 실행 파일 확인 이후 `worker_connect`에서 실패. OS에서 도출한 최소 환경 수정은 재검사 대상이며 메모리 또는 process 상한을 변경하지 않음 |
| 격리 stdio worker 수정 후 실제 검사 | Windows native 시나리오 8개 통과, 명령 종료 0 | OS에서 도출한 최소 Windows 환경과 유한한 쓰기 chunk, 최종 flush 이후 ACK를 사용. 256 MiB·process 1의 worker 한도와 blocked stdout의 원래 deadline을 유지; macOS 높은 FD 회귀는 미실행 |
| 정본 calibration 프로그램 및 교환 root | compiler 78, exchange 61 검사 통과 | 47개 고정 수치 프로그램과 세 entry의 pack 구성, 별도 필수 ZIP root 검증. 실제 게임 calibration 또는 target profile 승인이 아님 |
| 초기 Project 정책과 undo 첫 집중 검사 | runtime 67 통과, undo 10 실패 | 정책의 생성·재시작·정확한 version pin·공통 reader 검사는 통과. undo route의 CAS blob 등록 전 외래 키 참조 오류를 수정했으며 수정 후 재검사는 별도 |
| Coordinator 보존·workspace 및 host checkpoint | CLI 12 통과; Coordinator 124 통과, 1 실패, 1 ignored | 실제 native owner와 같은 Store의 정책 보존 경로 및 외부 I/O 없는 host checkpoint 통과. Windows native peer의 후속 연결에서 오류 2가 발생하여 원래 실패와 종료·drain을 보존 |
| 일반 자원 정책 아래 JVM 전체 재실행 | SDK 107, host-core 56, public-java-adapter 17 통과; Fabric 13 통과, 17 실패 | 모든 Java 소스 컴파일과 16개 Gradle task의 실제 재실행 확인. Fabric 두 fixture가 공통 JCS scalar 정본화에서 실패해 수정 중; Job commit peak 1,525,178,368 bytes, process 6, drain·export·scratch 정리·lease 해제 확인 |
| JVM scalar 정본화 및 profile 숫자 수정 후 | SDK 108, host-core 56, public-java-adapter 17, Fabric 33 검사 통과 | 같은 고정 Java·Gradle 도구와 2 GiB Job 한도 아래 전체 16개 task 실제 재실행, 실패·오류·skip 없음. primitive JCS와 mathematical integer 계약 검사 포함; 실제 loaded-definition 발급, calibration producer와 게임 인수는 별도 |
| undo 보존 및 application 경계 수정 후 | runtime 77, application 52 검사 통과 | 실제 SQLite/CAS·GC·재시작, 원래 receipt 보존, 정확한 source association, atomic claim, 새 epoch·drift·권한 거절과 독립 복원 fixture 확인. application undo는 테스트에서만 연결한 상태이며 실제 Service·호스트·게임 통합은 미완료 |
| 확장된 Rust 소스의 엄격 검사 | 등록된 workspace 전체 all-targets Clippy `-D warnings` 통과 | compiler calibration, runtime undo·bootstrap, Coordinator source·context·target profile과 CLI 포함. 아직 등록하지 않은 production composition, observer agent와 실제 게임 경로의 검증으로 확대하지 않음 |
| 실제 peer와 target profile의 집중 검사 | CLI 12 통과; Coordinator 140 통과, 1 실패, 1 ignored 후 target profile 12개 재검사 통과 | 실제 Windows native peer의 잘못된 PID 거절과 정상 연결 세 번 반복 통과. reference-only profile의 nullable artifact를 suite fixture로 잘못 역직렬화한 테스트만 수정했으며, 전체 최초 실패와 집중 재검사 성공을 구분. 실제 게임 calibration 또는 profile 승인 결과가 아님 |
| 첫 JVM 3개 OS CI | 세 OS와 집계 실패, 각 artifact의 bytes·SHA-256 확인 | source `1498ea14f253b03bf97a72323feddad934118b03`; macOS의 읽기 전용 PowerShell 변수 대입, Windows bootstrap의 활성 cache 경합과 Linux helper 시작 전 signal 6을 보존. Linux ICU 메시지를 패키지 부재로 단정하지 않으며 수정 후 성공은 별도 검증 |
| bootstrap 활성 항목 관측 회귀 | Windows 실제 harness 17개 사례 통과, 명령 종료 0 | 원래 열거된 authored leaf를 삭제한 뒤 실제 누락 예외를 보존하고 활성 descendant만 허용. PowerShell child tuple의 깊이 증가 괄호를 수정하여 실제 깊이 5/5/1 및 root 선택을 확인. 완료 cache·owner record·링크·알 수 없는 wrapper 거절, fixture와 외부 sentinel 보존. 첫 두 harness 실패 및 원격 Windows bootstrap 재검증은 별도 |
| JVM 공유 runtime probe | Windows 관리 한도 안의 실제 PowerShell 7.6.5·.NET 10.0.11에서 `en-US` 정렬 통과 | 정해진 GC 숫자와 유한 record만 확인. helper와 workflow의 정적 파싱은 통과했으나 Linux·macOS probe 및 수정 후 3개 OS JVM CI 성공은 미검증 |
| 열한 번째 Rust 3개 OS CI | Windows 전체 기반 job 통과; Linux·macOS 및 집계 실패 | source `ef9d9281e1dd16aa467a9a880ead2851c0a4df2c`; 세 artifact의 bytes·SHA-256을 대조. macOS stdio의 `posix_spawnattr_setflags` 인자형 컴파일 오류와 Linux의 platform 조건부 린트 두 건을 확인해 수정. 원래 실패를 유지하며 수정 후 해당 OS 성공은 별도 검증 |
| 저장 계획과 undo claim의 추가 경계 | runtime 78 검사 통과, 실패 및 warning 없음 | 실제 PlanId와 hash를 source material의 claim에 묶고 mutable retained target 관측을 transaction 전에 수행. 같은 Store의 원장·CAS·GC·재시작 및 거절 경로이며 실제 게임 복원 인수와 구분 |
| production Application과 calibration recipe 연결 | application 56, compiler 85 검사 통과 | 기존 공개 경로와 lazy undo 경로가 같은 알고리즘을 사용. 처음 실패한 ordinary context fixture는 정본의 external side와 descriptor·digest에 맞춰 수정했고 원래 55 통과·1 실패 기록을 보존. sealed 47개 calibration 프로그램과 metadata 출력의 순수 recipe 검사이며 실제 게임 실행·profile 발급은 별도 |
| Linux JVM 자원 정책의 Windows 검사와 실행기 빌드 | 관리 도구 96 통과·1 ignored, all-targets Clippy 및 실행기 빌드 통과 | 새 Linux 정책의 parser·identity·tracker 순수 검사를 Windows에서 수행. 새 실행기도 Windows 2 GiB Job 정책 안에서 빌드했다. Linux의 실제 VM 설정·RSS 관측·PowerShell 및 Gradle 실행은 아직 미검증 |
| 열두 번째 Rust 3개 OS CI | Windows와 Linux 전체 기반 job 통과; macOS 및 집계 실패 | source `8b9dda10a02aa188fcd731b9dcd28c3b67b49dd3`; macOS artifact bytes·SHA-256을 대조. 제품 컴파일은 통과했고 Coordinator는 135 통과·2 실패. native peer Protocol 거절과 stdio 시작 실패의 제한된 assertion을 보완 중이며 supervisor drain·export·정리 및 lease 해제는 완료 |
| Java undo production 경계 | SDK 108, host-core 81, public-java-adapter 17, Fabric 49 검사 통과 | 255개 검사와 16개 Gradle task를 고정 Java·Gradle 및 Windows 2 GiB Job 안에서 실제 재실행. 원래 source session·receipt, 등록 역할·세대와 raw future·timeout·queue를 구분. SDK의 정지 관측을 실제 게임 효과·복원으로 승인하지 않음 |
| 관측기 첫 등록 검사 | Rust 순수 검사 41개와 Java codec 검사 11개 통과 | 기존 private nested test의 중복 crate-root 등록 때문에 실패한 첫 컴파일을 보존하고 제거 후 재검사. lib test의 미사용 및 FFI visibility warning 15개는 actual optional query 연결과 API 경계 정리 대상. 실제 JVMTI startup, SAM·참조 closure, calibration 또는 profile 발급 결과가 아님 |
| JVM XML 결과 export 함수 회귀 | 실제 함수 추출 harness 3개 사례 통과 | PowerShell XML adapter가 Gradle의 `name` 속성을 요소 이름으로 읽은 원인을 확인. 실제 XML element의 Name·LocalName·빈 namespace를 검사하며 이름 없는 정상, 속성 충돌 정상과 namespace 거절을 확인. fixture 보존; Gradle 또는 CI 성공을 대신하지 않음 |
| 특수 생성물 진단 | Windows 관리 도구 97 통과·1 ignored 및 all-targets Clippy 통과 | 기존 특수 파일 관측·정리 거절과 lease 보존을 유지하고 native metadata 종류 및 유한한 생성물 상대경로 진단만 추가. Unix socket·FIFO 회귀는 해당 OS에서 별도 실행하며 기존 원격 특수 파일의 실제 종류·주체는 아직 미관측 |
| production Coordinator·CLI 첫 타입 검사 | Windows 등록된 두 패키지의 all-targets check 통과, warning 없음 | private request 권한 객체와 실제 host 오류의 immutable causal snapshot을 분리하고 daemon packet slice 및 새 native fixture helper를 수정. 원래 두 번의 컴파일 실패를 보존. 등록된 composition과 stdio 검사 실행 및 실제 제품·게임 인수는 별도 |
| 새 Linux JVM 정책 첫 실제 관측 | 고정 512 GiB VM soft/hard readback과 RSS 관측 및 inside runtime probe 성공; 전체 job 실패 | source `b43f8650ea32697ad1798fc5ec465ff170a8eb24`, 정확한 Linux artifact bytes·SHA-256 대조. 실제 PowerShell 7.6.6·.NET 10.0.12의 en-US 및 ICU 로드를 확인. 특수 생성물 관측·export가 거절되어 종료·drain 후 slot과 lease를 보존했으며 Gradle과 JVM CI 성공은 미확인 |
| production Coordinator·CLI 실행 검사 | CLI 14, Coordinator 210 통과·1 ignored; 실제 native stdio harness 통과 | 처음 실행의 Coordinator 207 통과·2 실패 기록을 보존. escaped JSON 한도 fixture와 per-enter witness 오류 기대값을 실제 경계에 맞게 수정. 원래 host 오류의 typed cause를 보존하며 공개 RPC code/message를 유지. raw stderr 왕복, EOF·잘린 capability, 막힌 stdout/stderr, 취소·원래 시간 제한과 실제 자식 drain을 확인. 최초 strict lint의 17개 실패는 별도 수정·재검사 대상 |
| 관측기 선택적 forwarder 묶음 | Rust 순수 41개, Java codec 14개와 JAR 빌드 통과 | 실제 Class identity와 현재 native generation을 통해 선택적 descriptive forwarder 조회를 연결. 처음 strict lint의 lib 13·lib-test 14개 실패를 보존하고 소스 경계를 정리 중. 실제 JVM startup과 긍정 hidden 관측, SAM·source closure 및 게임 target profile 발급은 아직 미검증 |
| 열네 번째 Rust·다섯 번째 JVM CI | Rust Windows와 JVM Windows job 통과; 각 Unix 및 집계 실패 | source `43fc99447942b83c3ad9b76d8a748cf7ee528d93`. XML export 수정 후 Windows JVM 판정 성공을 관측. 두 Unix JVM archive의 bytes·SHA-256을 대조해 scratch의 실제 `clr-debug-pipe` FIFO 거절을 확인하고 slot·lease를 보존. Linux Rust는 숫자 필드 관측 오류로 종료했으나 실패한 필드가 아직 구분되지 않음. macOS Rust는 종료 101이며 새 진단 소스가 포함된 후속 검사가 필요 |
| 원래 stdout capture와 Linux signed stat | 관리 도구 105 통과·1 ignored와 all-targets Clippy 통과 | private 원래 capture handle의 유한한 읽기·size·EOF·current 검사, Windows share-write/delete 거절 및 기존 outcome 보존을 확인. Linux pgrp/session의 signed decimal 문법을 정리하고 닫힌 필드별 진단을 추가했으며 PID 양수·원래 leader와 session/group 검증을 유지. Linux CI의 실패 필드가 미관측이므로 원격 오류 해결로 판정하지 않음 |
| 소유 JVM helper 진단 IPC 정책 | 시작 전 override·helper bool readback 소스 검토와 PowerShell AST 통과 | D025의 정확한 purpose=jvm 실행에만 .NET managed debugger/profiler/port를 비활성화. 원래 환경 문자열을 내보내거나 스크립트 시작 뒤 설정하지 않으며 특수 파일 검사·보존을 유지. 새 정책의 실제 3개 OS helper 시작·FIFO 예방·Gradle·export 결과는 후속 관측 대상 |
| 일곱 번째 JVM CI의 실제 3개 OS 성공 | 각 OS에서 SDK 108, host-core 81, public-java-adapter 17, Fabric 49 검사 통과 | source `b0cacc56577df8d7c73692d4d3e10f079320daa6`, [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38475236519). 세 archive의 정확한 크기·SHA-256, 필수 task 실행과 source SHA를 확인. inside probe의 diagnostics 비활성화가 모두 true이며 command 0·drain·완전한 출력·export·scratch 정리·lease 해제를 확인. 실제 게임 및 릴리스는 not_run |
| 열여섯 번째 Rust CI | Windows job 성공, Linux·macOS와 집계 실패 | 같은 source의 [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38475236467). 두 실패 archive의 bytes·SHA-256 대조. Linux는 컴파일 중 고정 native metadata 열기의 NotFound로 supervisor가 종료했고 어떤 파일 역할인지는 아직 미확인. macOS는 기존 Coordinator 135 통과·2 실패로 peer Protocol과 worker startup 기대값 실패를 보존. 두 실행의 drain·완전한 출력·export·lease 해제를 확인했으며 수정 후 Unix 성공을 주장하지 않음 |
| Coordinator readiness 수정 후 Windows 검사 | CLI 15, Coordinator 212 통과·1 ignored 및 실제 native stdio 시나리오 통과 | 정본 함수 인덱스 전체의 세션 정책 설치·인증, 원래 daemon I/O deadline과 sanitized CLI 오류 회귀 포함. startup 500 ms·전체 진단 3초 제한을 유지. native stdio의 line/raw/stderr/EOF/잘린 capability/held input/blocked output과 drain 확인. 실제 foreground daemon 재검증 및 Unix 결과는 별도 |
| 실제 CLI 초기화와 유한 foreground daemon | 새 개발용 Project 초기화 및 수정 후 lifetime 8초 daemon 실행 종료 0, strict lint 통과 | 초기화 receipt를 실제 stdout으로 전달하고 SQLite/CAS를 빌드 cache 밖에 보존. 첫 foreground 실행은 종료 3·stderr 0 bytes로 실패했으며 정본 밑줄 정책 결함 수정 후 실행에서 정상 readiness 전달과 종료를 확인. 두 결과를 각각 보존하고 새 실행의 drain·완전한 출력·scratch 정리·lease 해제를 확인. 최초 실패의 typed primary를 직접 관측했다고 보지 않으며 실제 게임 연결·대상 profile 인수와 구분 |
| Legacy 및 Provider fixture 첫 실제 JVM 검사 | legacy 18, provider 11 검사 통과·실패·오류·skip 0, JAR와 source JAR 생성 | 고정 Java 25·Gradle 9.6.0·Loom 1.17.21, 17개 task 실제 실행. 같은 legacy counter를 SDK와 SDK 없는 경계에서 사용하고 취소·lost response·late completion의 의미를 구분. source admission·실제 공통 plan/apply/readback 및 게임 AD 인수는 별도이며 이번 실행의 drain·export·scratch 정리·lease 해제를 확인 |
| 관측기 실행기 실제 Windows 검사 | 161 통과·1 ignored, all-targets Clippy 통과 및 실행기·DLL 빌드 | 원래 60초 absolute deadline, 생성 전 취소의 private capture receipt, same-handle stdout, secret 이름·named stream 거절과 엄격 ABI2 52개 회귀 포함. 최초 misplaced Win32 constant import 컴파일 실패를 보존하고 실제 수정 후 검사. 입력 archive는 확인한 원본 bytes를 선택할 수 있는 192 MiB 상한이며 native heap·Job·시간·합계 상한은 유지 |
| 개발용 observer 첫 native 시작 시도 | 입력 DLL의 실제 hardlink 2개를 INPUT_FILE로 거절, Java 생성 전 실패 | 원래 구현의 미확정 started·undrained·보존 lease를 그대로 기록. D026에 따라 정확한 소유 기록·비활성 PID·다른 active slot 없음·빈 scratch·native 호출 전 오류 분기를 확인한 별도 복구를 수행. 최초 보고서는 바꾸지 않았고 실제 DLL bytes의 single-link 복사·digest 대조를 다음 입력으로 사용 |
| 개발용 observer 두 번째 실제 native 시작 | Java 생성 확인·command 1·drain·완전한 출력·원본 pin 대조·export·lease 해제 | 고정 원본 JDK·DLL·JAR 등 12개 선택 파일의 digest를 보존. Java JarFile open 뒤 Instrumentation의 native bootstrap search append에서 IllegalArgumentException으로 premain 실패. 실제 ABI2 및 긍정 hidden 관측은 미완료이며 경로 표현과 native 재개방을 추적 중. 실패를 timeout·OOM 또는 관측 성공으로 바꾸지 않음 |
| 생성 전 거절의 수명 재검증 | 원래 hardlink DLL을 같은 정책으로 거절·started false·drain·export·scratch 정리·lease 해제 | 실제 세 번째 실행의 INPUT_FILE 거절은 정상 수명 처리로 완료. 최초 실행의 미확정 상태와 수동 복구 기록은 변경하지 않으며, 생성 이후 실패는 원래 capture 및 native drain 증거로만 처리 |
| observer bootstrap JAR 경로 검사 | Java 22개 검사 통과·실패·오류·skip 0, 새 JAR 생성 | 실제 파일의 같은 ASCII 상대 이름으로 bootstrap 등록하고 JDK native 경로 재개방을 확인하도록 변경. 고정 도구 아래 네 task 실제 실행·drain·export·lease 해제를 확인. 네 번째 native 실행은 command 0이었으나 stdout의 JVM 경고가 단일 프레임을 오염시켜 FRAME 거절; 원본 candidate 보존 |
| 개발용 observer 실제 JNI/JVMTI 관측 | 다섯 번째 native 실행 command 0, ABI2 5,886 bytes·엄격 decode 통과 | ordinary·SAM 없는 hidden·좁은 hidden forwarder를 actual Class identity·generation·issuer epoch에 연결하고 12개 입력의 실행 전후 digest를 확인. raw SHA `4e43bb003805482f138083fae1cec959d8ef1d22d2e35a2cad43ce8dad2c04dc`; JVM 경고는 stderr에 원문 보존. drain·완전한 출력·export·scratch 정리·lease 해제 확인. 게임 source admission·전체 SAM 참조 closure·profile 승인·인수 통과와 구분 |
| 열일곱 번째 Rust·여덟 번째 JVM CI | Rust Windows·JVM Windows/macOS 성공, 나머지 Unix 및 집계 실패 | source `3f2becc4cb0620675dcd9a0a4f69c4962ca51f4e`, 실패한 세 archive의 정확한 bytes·SHA 대조. Linux Rust의 Coordinator 208개와 macOS peer lifecycle 통과를 확인했으나 Linux native stdio fixture는 startup_deadline, macOS는 native_spawn 22·drained false로 실패. Linux JVM의 Gradle 0·255개 검사는 통과했지만 종료 자원 관측의 fixed metadata open ESRCH로 job 실패. command 성공과 전체 감독 성공을 분리하며 수정 후 결과는 미확인 |
| 열여덟 번째 Rust CI | Windows job 성공, Linux·macOS 및 집계 실패 | source `b573009e29562cefb6f2e05363f9255da6ec3bc7`, [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38536350640). Linux·macOS archive의 정확한 bytes·SHA-256 대조. Linux workspace 및 native stdio는 통과했으나 Unix Coordinator의 unused mut·collapsible if 세 strict lint로 실패. macOS Coordinator는 207 통과·native_spawn 22 한 실패이며 양성 native harness는 미실행. 각 원본 실패와 drain·완전한 출력·export·scratch 정리·lease 해제를 보존. 새 spawn 단계 진단·lint 수정의 실제 Unix 재검증은 별도 |
| 아홉 번째 JVM CI의 실제 3개 OS 성공 | 각 OS에서 7개 모듈의 306개 검사 및 필수 11 task 실제 실행 통과 | 같은 source의 [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38536350671). 세 archive의 정확한 bytes·SHA-256과 source SHA, 실패·오류·skip 0, D025 inside readback true를 확인. SDK 108·host-core 81·public-java-adapter 17·Fabric 49·observer 22·legacy fixture 18·provider fixture 11이며 command 0·drain·완전한 출력·export·scratch 정리·lease 해제 확인. 같은 helper의 로컬 7개 모듈 실행도 306개·11 task 통과. 실제 게임 및 릴리스는 not_run |
| 소유 자료 Factory 첫 통합 실행 | Coordinator 221 통과·1 실패·1 ignored | supplied data adapter는 같은 Store·원래 deadline·취소·request를 그대로 전달. owned data trait 검사는 새 Project head에 기존 policy의 exact revision provenance가 연결되지 않아 prepare_workspace에서 실패. reader 검증을 유지하고 원래 실패 로그·정상 drain·export·정리를 보존. native owned-source atomic commit과 Factory fixture의 정식 ingress 연결을 진행 중이며 실패 해결은 아직 미검증 |
| 세 target ABI 선택 코드의 Windows 검사 | Rust observer 48개·strict all-targets Clippy·exact target library build 통과 | 실제 `--target x86_64-pc-windows-msvc`를 사용. 새 DLL로 여섯 번째 actual JNI/JVMTI startup command 0·ABI2 5,886 bytes strict decode와 12개 입력의 전후 pin을 확인. raw SHA `7935d96d9f16eb18d1da402df28a44b48993684cd7e4c79edf7102b9653d7c10`; drain·완전한 출력·export·scratch 정리·lease 해제 확인. C header witness·Unix startup·game source 및 profile 권한은 아직 미검증 |
| Native 소유 저작 자료의 원자적 저장 | Runtime 93개 통과 및 strict all-targets Clippy 통과 | 새 15개는 실제 Store의 Prefab·Instance·Clip/raw resource 원문 및 canonical pin 분리·초기 policy carry·재시작·GC·현재 권리·원래 취소와 기한·최종 SQL 실패 rollback·OutcomeUnknown fence를 검사. 첫 strict 실행의 중첩 조건 5개 lint 실패는 보존하고 같은 조건 및 오류를 유지해 수정한 뒤 재검사 통과. 이 Store 검사와 게임 source 승인 및 실제 효과 검증을 구분 |
| Native source ingress와 Factory 재검증 | Coordinator 238개 통과·1 ignored, 실제 native stdio 시나리오와 strict all-targets Clippy 통과 | Prefab·Instance·Clip 및 retained/raw 자료를 원래 native owner·request budget·policy·같은 Store의 atomic commit에 연결. 새 ingress 16개에 Clip 양방향 참조·입력 순서·실제 raw/projected pin·취소·권한 철회·foreign Store 및 stale head 거절 포함. Factory의 기존 실패 seed를 실제 ingress로 바꾸고 commit 후 이전 Project grant를 명시적으로 revoke한 뒤 원래 budget으로 새 workspace를 구성해 통과. 첫 namespace import compile 실패·test helper의 err_expect lint 5개와 원본 Factory 실패는 별도 보존. 실제 state source association은 미구현이므로 unavailable을 유지하며 게임/인수 완료로 확대하지 않음 |
| 기존 Store 전용 native source entry | Runtime 96개·Coordinator 246개·CLI 15개 및 Windows native stdio 통과, 세 crate strict all-targets Clippy 통과 | `open_existing`은 누락된 root·lock·DB·CAS를 생성하지 않으며 초기화되지 않은 DB를 채택하지 않는다. 실제 단일 owner·기존 데이터·원문 및 canonical pin·history·stale head·원래 취소·커밋 후 출력 및 drain 실패의 확정 receipt 보존을 검사했다. cold argv seam은 새 wire 함수·source 승인·게임 권한을 추가하지 않으며 실제 CLI 명령 검증은 별도다. 관리 실행의 command 0·drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다. |
| 실제 Windows CLI source import | 새 개발용 Project 초기화와 cold `source-import` 모두 command 0 | 실제 438 bytes Prefab 원문을 가져왔고 receipt의 raw SHA `60f576ab08f730720f3f6a6a6debdc9401faa12c1f62fd1f6dffdb6f47d93949`와 canonical pin `e92d53cb4515880ad2f02d652d2db5680c0449368edc8b7fe39e9ab6942d96bf`를 각각 확인했다. 새 Project revision·Project blob과 단일 문서의 확정 receipt, native output worker의 정상 종료 및 전체 관리 drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다. 실제 실행 파일 41,641,984 bytes의 SHA는 `55afb3db75ea126acb585063b42441a83bf457486dc7d2f19827270633778b97`; 수정된 입력의 관리 빌드 근거를 보존하되 전체 source inventory pin을 검증했다고 주장하지 않는다. 제품 SQLite/CAS는 빌드 정리 밖에 보존했으며 실제 게임과 릴리스는 미실행이다. |
| Unix definition startup 및 Linux pidfd의 Windows 검사 | 관리 도구 171개 통과·1 ignored, strict all-targets Clippy 통과 | 명시적 환경 구성 실제 회귀와 platform argument·pidfd event의 순수 판정이 포함된다. Unix dirfd·native pidfd lifecycle 검사는 Windows cfg에서 실행되지 않았으며 실제 Linux·macOS 시작 및 syscall 검증의 근거로 쓰지 않는다. |
| 선택 JDK 헤더의 실제 Windows C ABI witness | 세 번째 실행 C compile/link·witness 및 전체 관리 실행 통과 | 실제 MSVC와 선택한 `jni.h`·`jvmti.h`·`jni_md.h`의 크기·정렬·36개 table/6개 callback/4개 entry 서명·capability 비트를 검사했다. witness 1,036 bytes SHA `0bc2647c3739771d33a7dd9a2841fe4aed6f1c9b3634724b47e8c7f63cef790f`, 8개 입력 전후 pin 일치. 첫 compiler profile 거절과 두 번째 command 0 뒤 잔여 소유 자식 때문에 발생한 전체 실패를 보존했다. 세 번째 실행은 D020의 명시적 빌드 자식 정리·실제 drain/export/scratch 정리/lease 해제를 확인했다. 전체 toolchain image·JVM 실행·ClassLoader native 서명·Unix ABI 또는 게임 인수를 검증했다고 확대하지 않는다. |
| 열아홉 번째 Rust CI의 실패 단계 관측 | Windows 성공, 두 Unix 및 집계 실패; 두 실패 archive의 실제 bytes·SHA·source 대조 | source `5beea11f1fa3048f49c7d63c0557da086c2662c5`, [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38546096382). 두 Unix의 Coordinator lib는 209개 통과했지만 양성 native stdio harness에서 macOS는 `native_spawn_memory_limit`·errno 22·drained false, Linux는 `startup_deadline`·drained true로 실패했다. outer 관리 실행은 두 경우 모두 실패 로그·drain/export·lease 해제를 보존했다. Linux의 실제 연결·partial/rejected HELLO와 해시 비용은 아직 미관측이며 원인을 단정하지 않는다. |
| 공개 source head의 CI metadata | Rust20 Windows 성공·두 Unix와 집계 실패, JVM11 workflow 성공 | source `4e8c58c7efa2addccbe55af1e13a2219fe1a7755`의 [Rust run](https://github.com/daejunnom/MMMM/actions/runs/38552259333) 및 [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38552259337). 이번 확인은 job/workflow metadata이며 새 archive의 개별 검사와 digest 대조로 확대하지 않는다. C ABI·controlled startup의 새 CI 단계는 아직 source 등록 및 실제 실행 검증 대상이다. |
| 공통 native 관측 및 런처 통합 후 Windows 재검증 | `mmmm-native-process` 5개·관리 도구 171개 통과·1 ignored, 두 crate strict all-targets Clippy와 실제 런처 빌드 통과 | 새 crate는 libproc의 순수 native 관측·정적 및 숫자 오류만 공유하며 정책·owner·신호·drain을 발급하지 않는다. tools의 기존 Darwin 정책은 유지하고 실제 macOS 관측은 후속 CI로 검증한다. 별도 bootstrap 실행기로 현재 실행 파일을 덮어쓰지 않게 빌드한 뒤 여덟 번째 Windows native startup이 command 0·strict ABI2 5,886 bytes·12개 입력 전후 pin·drain/export/scratch 정리/lease 해제를 통과했다. raw SHA `25fbf06104f59c55331acf323883a12d1cbccbe4e40659011c9068ad7950c4fd`. 일곱 번째 caller 인수 조립 오류는 JVM·lease 생성 전 거절로 별도 보존했다. 새 Unix 경로·native pidfd lifecycle·전체 source inventory와 실제 게임 인수는 여전히 미검증이다. |
| 열세 번째 JVM CI의 실제 Unix observer 성공 | Linux·macOS의 native build, 실제 C ABI witness, controlled startup 각각 command 0 | source `81245ee6fde6a4681a6388677b6d5163838e73bd`, [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38558687358). 세 archive의 bytes·SHA·source를 대조했다. 두 Unix는 8개 header pin과 세 managed step의 process/finish/finalization digest 연결·drain/export/scratch 정리/lease 해제를 확인했다. 실제 ABI2는 각각 5,886 bytes 및 12개 input pin이며 Linux raw SHA `4af3a6bbfc38ffb492432428d1c15456dd773a8d3f5358ff8e42236c28a6890b`, macOS raw SHA `c47209e940968d3ca55cdd266d0a2aa19228a53662c5abed1ec8e83ff86b9bac`다. Windows는 `compiler_selection`의 ItemNotFoundException으로 실패했고 ABI helper 및 startup은 미실행이다. 실제 runner는 `win25-vs2026`이며 원래 기록만으로 누락된 VS root·launcher·compiler 중 하나를 단정하지 않는다. 일곱 JVM 모듈의 306개 및 11 task 성공 기록과 새 Windows observer 실패·전체 job 실패를 구분하며 실제 게임과 release는 미실행이다. |
| 스물두 번째 Rust CI의 Linux 감독 실패 | 제품 test 결과 전 `enumerated_candidate` stat open의 native ESRCH로 supervisor 실패 | 같은 source의 [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38558687366). Linux 실패 archive의 13,910 bytes·SHA `19fa3814a96c8f5ea7995170e3f7b721f4d39be6ed86ff21141a3aa76435a65a`와 source를 대조했다. 실제 command code는 미관측·signal 9·elapsed 6,697 ms·stdout 0이며 원래 오류와 drain·완전한 출력·export·scratch 정리·lease 해제를 보존했다. 이 첫 stat 조회 오류는 이미 identified member의 RSS 실패에만 적용하는 pidfd witness로 해결됐다고 표시하지 않는다. Linux native lifecycle tests와 전체 제품 검사는 이 실행에서 통과한 근거가 없다. |
| Windows compiler 실제 설치 조회 수정 | 새 `vswhere` 경로의 네 번째 로컬 header 실행 전체 통과, PS AST 오류 0 | 기본 고정 설치 경로 대신 OS KnownFolder의 실제 installer 조회를 사용하며 명시적 VS root는 실패 시 fallback하지 않는다. 5초 작업·한 번의 2.5초 종료 확인·각 pipe 4 KiB의 조회는 실제 181 ms·exit 0·EOF·입력 전후 pin을 확인했고 raw 설치 경로를 출력하지 않았다. 이어 실제 C compile/link·ABI witness·8개 pin 재검사가 통과했다. 전체 관리 실행은 D020의 소유 빌드 자식 종료·drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다. 원래 CI의 coarse 실패는 보존하며 새 compiler 역할 phase·조회 및 선택 digest를 별도 기록한다. 이 로컬 결과는 수정 후 Windows CI 성공을 의미하지 않는다. |
| 완료된 pairing·파일 입력·stdio 통합의 Windows 검사 | Coordinator 270개·CLI 15개 통과·1 ignored, 두 crate strict all-targets Clippy 및 실행 파일 빌드 통과 | 현재 request와 활성 grant·정확한 route generation으로 완료 receipt를 재검사하고 첫 완료 및 publication/rollback 원인을 유한하게 보존한다. 새 pairing 8개는 실제 TCP/context·entered request fixture와 private completion seam을 사용하며 실제 게임 ACK/EOF 근거가 아니다. 파일 reader의 Windows 9개와 entry 통합 3개는 실제 보호 Store·선택 원문·atomic commit·missing file 미발행·취소·hardlink·공유 경계를 검사했다. Linux 인증의 원래 5초·80 bytes·full-image hash와 error/drain은 유지한 채 닫힌 진행 관측을 추가했다. D029의 실제 macOS worker·Unix 파일 reader·pidfd lifecycle은 이 Windows 결과로 통과 처리하지 않는다. native stdio 실제 시나리오와 전체 관리 drain/export/scratch 정리/lease 해제를 확인했다. |
| 실제 Windows 파일 기반 source import | 원래 컴파일 산출물에서 command 0, 문서 98,926 bytes와 Raw 131,072 bytes를 같은 commit으로 반영 | 실제 receipt의 문서 raw SHA `d85317291ae5238b96026c62475fd4d784839b70640ad27744e967980583313f`, canonical pin `04f73017a78fecd1c4aea630403fa11d69d0746eae8a520875d6087eb66dab03`, Raw SHA `feb1e4409d009e0ec502eaabe321f86b5197a881e9b765252ec8a75d6957596d`와 새 Project revision을 확인했다. 선택 원본 및 제품 DB/CAS를 보존하고 전체 drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다. 같은 41,807,872 bytes 실행 파일 SHA `ad5a896b20990c48726f4e382188e41c519c651a9925e3ef8e2556bc935ee6b9`의 복사본은 첫 생성 단계에서 Windows Application Control `4551`로 거절됐다. 원본 실패와 두 실행 경로의 결과를 각각 보존했으며 보호 설정을 변경하거나 경로 차이를 확정 원인으로 단정하지 않았다. 전체 source inventory·실제 게임·릴리스 검증과 구분한다. |
| 스물세 번째 Rust CI의 Unix 검사 | Windows job 성공, 두 Unix 및 집계 실패; 두 Unix archive의 bytes·SHA·source 대조 | source `07054ebcd53aef6df52ba6601abb6d3c52c4224b`, [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38561306852). 두 Unix의 Coordinator lib는 각각 243개 통과했다. 이후 실제 native stdio는 Linux `startup_deadline`·drained true·5,023 ms, macOS `native_spawn_memory_limit`·errno 22·drained false·97 ms로 command 101이다. outer 감독은 오류 없이 실제 drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다. 이 실행은 후속 D029 및 닫힌 startup 관측을 아직 포함하지 않으며, CI22의 candidate 첫 stat 실패를 해결했다는 증거로 확대하지 않는다. |
| 열네 번째 JVM CI의 실제 Windows observer 성공과 macOS 후속 실패 | Windows·Linux job 성공, macOS 및 집계 실패; Windows·macOS archive의 bytes·SHA·source 및 managed record 연결 대조 | 같은 source의 [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38561306870). 두 OS의 일곱 모듈 306개·11 task는 통과했다. Windows의 실제 기본 `installed_vswhere` 조회는 508 ms·command 0·EOF와 pin을 확인했고 native build·C header ABI·controlled startup 전체가 통과했다. 원 startup stdout과 승인 raw 5,886 bytes SHA `05ddd70fb7d262cdd352ffbde32e47bb607eb0bcfbe70ba2a632799063326193`가 일치한다. native/header의 D020 owned-tail 정리와 startup의 자연 종료를 구분하며 세 단계 drain/export/scratch 정리/lease 해제를 확인했다. macOS도 native build·header ABI 및 실제 JVM command 0·329 ms·drain·완전한 출력을 보존했으나 후속 관측은 `DEADLINE`으로 거절됐다. 5,886 bytes candidate SHA `8535241e14e3edb4c5d4b4efff961494bd419e0a9743e3efad644627956bf231`는 원 stdout과 같지만 승인 ABI 관측은 아니다. 원래 60초 기한은 유지하며 정확한 후속 실패 phase와 전체 소요는 기존 기록에서 미관측이다. Linux job은 metadata만 확인했고 이 실행의 새 archive를 검사했다고 주장하지 않는다. |
| 현재 요청의 completed-pairing owner 결합 | Windows Coordinator 278개·계약 28개 통과·1 ignored, 두 crate strict all-targets Clippy 통과 | 원 entered request의 같은 기한으로 fresh kernel owner를 확인하고, 같은 잠긴 Store·원 offer root·completion owner·실제 등록 native Project owner 및 현재 route·scope를 callback 전후 검사한다. 실제 native Project를 생성한 양성 및 다른 Store·owner·미등록 Project·route 교체·취소·정책 철회 거절 8개를 통과했다. callback의 첫 오류와 후속 current-check 오류를 함께 보존했다. D031의 실제 dev/test profile을 적용했으며 Windows native stdio도 통과했다. command 0·drain·완전한 출력·export·scratch 정리·lease 해제다. live ACL/lock namespace의 새 검증, source 권리 발급·명시 read policy·게임 인수를 주장하지 않는다. |
| 스물네 번째 Rust CI의 닫힌 startup 관측 | Windows job 성공, 두 Unix 및 집계 실패; 두 Unix archive의 bytes·SHA·source 대조 | source `c368f521ba8f353e864bcb9de055431524a231ed`, [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38564982292). Linux lib 268개 통과 뒤 두 번째 실제 native scenario인 held-stdin startup에서 실패했다. parent image 93,328,120 bytes·hash 2,487 ms·spawn 0 ms·남은 인증 2,513 ms·전체 5,001 ms·accept/read 0·no_connection·drained true를 관측했다. child hash 지연 원인은 미관측이다. macOS lib는 D029 자원 순수 검사를 포함해 269개 통과·1 실패이며 `native_spawn_exec`·errno 9·image 63,814,848 bytes·hash 3,107 ms·spawn 4 ms·drained false다. outer는 두 OS 모두 command 101·실제 drain·출력·export·scratch 정리·lease 해제를 보존했다. 후속 native harness·다른 crate·Clippy는 이 실패 이후 실행되지 않았다. |
| 명시 native host 읽기 정책의 Windows 통합 | CLI 15개·Coordinator 284개·runtime 101개·관리 도구 177개 통과, 두 isolated fixture 직접 실행 제외; 네 crate strict all-targets Clippy 통과 | D032의 실제 SQLite atomic companion 등록·동일 선택 재사용·다른 선택 충돌·누락 거절·재시작·현재 owner/pairing 소비자를 검사했다. 초기 consumer fixture가 원 등록 scope 대신 좁힌 context scope를 사용해 실패한 실행은 보존하고 fixture만 수정했다. 성공 실행의 실제 command 0·native stdio·drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다. macOS의 새 FD 역할 진단과 Linux의 새 pidfd 보조 진단은 순수 및 Windows 구성 검사이며 해당 OS native 성공으로 확대하지 않는다. |
| 아홉 번째 Windows controlled definition startup | 실제 JVM command 0, strict ABI2 5,886 bytes와 12개 입력 전후 pin 일치 | raw SHA `85695f39e0e56216b37e03a7977cc5d4190b5e7766e2f5c29ccaa00707223989`, 실제 native 1,620 ms·전체 관측 9,639 ms·13개 phase 완료를 보존했다. 현재 선택한 source manifest는 기준 SHA와 dirty source 33개를 식별하며 전체 source inventory 증명이 아니다. caller의 최초 31개 인수 조립 실패는 JVM·lease 생성 전 별도 기록으로 남겼다. 후속 실행은 drain·완전한 출력·export·scratch 정리·lease 해제를 통과했으며 실제 게임 SourceAdmission 또는 loaded closure를 승인한 근거가 아니다. |
| observer managed record 분류 및 실패 보존 검사 | 실제 Windows 관리 실행에서 외부 harness 11개 case·command 0 통과 | 실제 native009의 현재 완료 owner와 catalog를 연결해 success/step을 검사했다. CI15 macOS 원 archive의 생성 전 `DEADLINE`·false 및 생성 불명 null clone, 불완전 outcome·잘못된 exit/resource policy 타입·generic supervisor 오류의 성공 거절을 확인했다. CI14 Windows header의 명시 owned-tail 허용과 거절도 검사했다. ZIP 논리 case의 hash는 실제 원문 bytes에 연결했으며 ZIP owner/source pin integration으로 확대하지 않는다. helper SHA `8112ac86d3d301bd6efc56c4e32a4851d839816992f1b9a4b3da3fc94f12b42c`; 외부 실행의 drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다. |
| 스물다섯 번째 Rust CI의 플랫폼별 실패 구분 | 전체 집계 실패; 세 archive의 실제 bytes·SHA·source 대조 | source `66ef38bac9b335e9879cf15f68513a238040dffb`, [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38567143463). Linux tests와 실제 native stdio 시나리오는 command 0·drain/export/정리를 통과했고, 후속 Clippy만 lifecycle test의 `collapsible_if` 두 건으로 실패했다. Windows는 완료 13 suite 740개 통과 후 runtime 수행 중 owned scratch metadata의 native 접근 거부 5로 observation failure다. 실행 281,189 ms·command 124를 timeout 또는 assertion 실패로 해석하지 않으며 runtime 최종 result는 없다. macOS는 Coordinator 276개 통과·2개 실패로 기존 `native_spawn_exec`·errno 9와 owner fixture의 host header 읽기 실패다. 새 FD 역할 진단은 이 SHA에 없으므로 실패 descriptor는 미관측이다. 세 실행의 outer drain·완전한 출력·export·scratch 정리·lease 해제를 각각 확인했다. |
| 열여섯 번째 JVM CI의 macOS observer 성공과 Linux 감독 실패 | Windows·macOS job 성공, Linux와 집계 실패; 두 Unix archive의 실제 bytes·SHA·source 대조 | 같은 source의 [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38567143631). macOS의 53-input manifest, 세 observer 단계의 실제 9개 managed record digest와 prior JVM 5개 digest가 상위 결과에 연결된다. native build·C header·startup 각각 command 0·자연 종료·drain·완전한 출력·export·scratch 정리·lease 해제다. 8개 header pin과 12개 startup pin을 확인했고 승인 raw와 실제 stdout은 모두 5,886 bytes·SHA `7659005ad5f9e558bdf2fc908e0f90f730396779ae21f0a35eab0f84f802db85`다. macOS 및 Linux의 JVM 결과는 각각 306개·11 executed task 통과지만 Linux는 실제 command 0 뒤 reserved-leader RSS open의 native ESRCH 3으로 observation failure이며 observer는 미실행이다. Linux의 drain/export/정리는 별도 완료다. 이번 Windows는 job metadata만 확인했고, manifest의 모든 공개 Git blob·ZIP에 없는 입력 원문·간헐적 DEADLINE 해결·실제 게임 및 릴리스 성공으로 확대하지 않는다. |
| 관리 도구의 비밀 이름 거절 fixture 경합과 수동 복구 | 재검사 실행은 observation failure·command 124·drain 및 완전한 출력, 원 export 실패와 lease 보존 | 기존 검사가 만든 비밀 이름의 빈 디렉터리와 outer observer가 경합했다. 비밀 파일은 생성하거나 열지 않았다. 검사는 실제 경로를 생성하지 않는 lexical selector로 바꾸어 metadata 및 제거 전 거절을 확인한다. 종료한 원 실행·정확한 catalog/owner/lease·다른 active 없음과 알려진 로그 bytes를 대조한 뒤 별도 수동 기록으로 로그를 보존했다. 해당 scratch 하나만 같은 볼륨의 단일 rename으로 외부 evidence에 이동하고 내부는 열거·읽기·hash·삭제하지 않았다. 같은 token과 PID를 유지해 그 슬롯의 lifecycle만 수동 완료하고 정확한 lease를 해제했다. 원 `evidence_exported=false`를 고치거나 정상 finish·scratch 삭제·검사 성공으로 재판정하지 않았다. 일반 중단 lease 채택과 다른 슬롯·cache 회수·제품 자료 변경은 없다. |
| 실제 Windows native workspace의 FN31 읽기 | 실제 daemon·`project.inspect`·두 `artifact.read` 모두 command 0, 원 131,072 bytes·SHA 일치 | foreground 시작 결과는 이미 설치한 현재 workspace의 typed `workspaceContextId`를 listener 시작 성공 후 반환한다. 기존 source-import Project에서 실제 native peer와 현재 context로 65,536 bytes씩 읽었으며 합친 SHA는 `feb1e4409d009e0ec502eaabe321f86b5197a881e9b765252ec8a75d6957596d`다. 실행 파일 41,912,320 bytes·SHA `e5e2db1b277bd69a4c4718fc2d4e77a325e036d5731fefb37dd8b81c2c1e08f3`, 외부 결과 3,112 bytes·SHA `47ac7ed5f56dc00a1cb180963a5bfa25ba83dcb18c411d151f9e559c9408bdba`를 보존했다. 90초 lifetime의 daemon은 강제 종료 없이 exit 0·소유 자식 0·양쪽 EOF로 drain됐고 전체 관측은 101,512 ms다. outer 실행도 drain/export/scratch 정리/lease 해제다. credential·endpoint·DB/CAS 원문을 직접 읽지 않았으며 제품 자료는 보존했다. 이 결과는 runtime resource scope 읽기이며 catalog capture·shape·게임·릴리스 검증을 의미하지 않는다. |
| 실제 Windows MCP facade의 FN31 읽기 | 세 MCP 세션과 daemon 모두 command 0, CLI와 같은 원 bytes·SHA 일치 | 같은 41,912,320 bytes 실행 파일로 MCP `2025-11-25`의 initialize 응답을 확인한 뒤 initialized·tools/call을 보내고 실제 tool 응답 뒤 EOF를 닫았다. 세 세션은 각각 초기화와 도구 응답 두 개, structuredContent와 text JSON의 일치, 실제 exit 0·소유 자식 0·양쪽 EOF와 drain을 확인했다. `project.inspect` 후 두 `artifact.read`의 실제 nextOffset을 따라 131,072 bytes·SHA `feb1e4409d009e0ec502eaabe321f86b5197a881e9b765252ec8a75d6957596d`를 대조했다. daemon 90초 자연 종료·전체 91,091 ms이며 외부 결과 3,859 bytes·SHA `ea8c0e4d7ff778f3688a485738fcbb3091056b329fbe19b248517fcba3acdd31`다. outer drain/export/scratch 정리/lease 해제 및 제품 자료 보존을 확인했다. 실제 게임·catalog capture·shape 인수는 별도다. |
| Fabric task 조회와 caller cache 경로 오류 복구 | 수정된 고정 경로의 실제 task 조회 command 0; 최초 오류와 export 실패는 별도 보존 | caller가 `gradle-project-cache` 대신 다른 이름을 지정한 첫 조회는 Gradle settings의 sibling-directory 검사에서 command 1로 거절됐다. native drain·완전한 출력 뒤 관리 도구도 알 수 없는 cache root를 거절해 원 export false와 lease를 보존했다. 정확한 종료·원 owner/lease를 대조하여 알려진 로그를 복사하고, 새로 만든 그 cache 경로 하나와 해당 scratch만 각각 단일 same-volume rename으로 외부 evidence에 보존했다. 내부 조회·삭제·다른 슬롯 및 제품 변경 없이 별도 수동 lifecycle 복구를 기록했다. 원 실패를 변경하지 않았다. 후속 고정 경로의 Loom 1.17.21 task 조회는 command 0·drain/export/정리/lease 해제이며 현재 구성의 `jar` task를 실제 확인했다. JAR 생성과 게임 실행 성공은 이 조회로 주장하지 않는다. |
| Windows 관리 metadata 재관측과 필수 증거 연결 | 도구 lib 186개·bin 1개 통과·isolated 1 ignored, strict all-targets Clippy 통과 | D033의 Running 전용 재관측과 최초 native 오류·최종 결과, 호출·대기·wall·진단 상한, 소유·link 경계, export 실패 시 lease 보존을 검사했다. bootstrap parent에서 새 관리 실행기를 빌드하고 실제 `mmmm --help`를 감독했다. 빈 companion도 실제 70 bytes·SHA `625ada3644e617b91bcfa1022c0af952adb52a110cf166542b8435ff741d735b`로 생성·flush·sync됐으며 process pin과 일치했다. command 0·drain·완전한 출력·export·scratch 정리·lease 해제다. 실제 CI25의 native 5 race는 이 실행에서 재현되지 않았고 원인 해결로 확대하지 않는다. |
| 로컬 Fabric 호스트와 SDK JAR 생성 및 구조 검사 | 실제 Gradle 11 actionable task 중 4 executed·7 up-to-date, packaging command 0; 별도 inspector command 0 | Host JAR 3,466,694 bytes·SHA `b6d1b7614c1763230276ba3659853fa720d6f294ac24a15479ce9eca066b0786`, SDK JAR 39,643 bytes·SHA `679d4fadb88f5aea481a53b058ba1132f47b0dde60fbe60259ad0b6271683d99`와 양쪽 sources JAR을 관측했다. 명시한 외부 output root에서 네 파일을 held read·전후 hash 검사하고 host 82 entries, Fabric id·version·네 dependency·진입점과 실제 중첩 10개·SDK 및 host-core 존재를 확인했다. 중첩 SDK와 standalone bytes의 동일성을 가정하지 않았다. 선택 tracked source 152개 manifest SHA `580b3fad922fd14bc4353eb084427bb506d12991f19ab867dac4af2eceffcf4b`, inspector 결과 32,557 bytes·SHA `ea46722747d30d6ccb1f40483afa7b93926f6c88ffed7e68ea601903e4de1b85`다. packaging과 검사 각각 outer drain/export/정리/lease 해제를 확인했다. dependency semver 경고 두 건은 보존했으며 원 producer binding·전체 source closure·실제 게임·동일 출시 파일 인수는 별도다. |
| 스물여섯 번째 Rust CI의 실제 실패 경계 | Windows job 성공, Linux·macOS 및 집계 실패; 두 Unix archive의 bytes·SHA·source 대조 | source `8cc777726f481304e0161b403cb52b5f670234a1`, [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38574807674). Linux는 compile 중 23,672 ms에 처음 열거한 candidate의 stat open·native ESRCH 3으로 supervisor failure이며 테스트 stdout 0 bytes다. 확인된 owned member의 RSS·pidfd 경로까지 도달하지 않았다. macOS Coordinator는 282개 통과·2개 실패다. 네 descriptor와 FIFO 검사 이후 `SETEXEC`의 native 9·inner drained false를 보존했고, 별도 completion fixture는 첫 header 0 bytes·WouldBlock 35·당시 deadline 미도달 및 caller Disconnected를 관측했다. 두 Unix의 outer drain·완전한 출력·export·scratch 정리·lease 해제는 완료다. 이전 성공·auxiliary 진단을 이번 테스트나 inner drain 성공으로 대체하지 않는다. |
| 열일곱 번째 JVM CI의 세 OS 관측 기록 대조 | 3개 OS·집계 성공, 각 archive와 실제 record digest 연결 대조 | 같은 source의 [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38574807672). 각 OS의 306개 JVM 검사·필수 11 executed task, observer 세 단계의 실제 9개 managed record와 prior JVM 5개 digest, header 8 pin·startup 12 pin 및 전후 counter 12·13 phase 완료를 확인했다. 승인 raw와 원 stdout은 각각 5,886 bytes이며 Linux SHA `a99c23a840fa43897ad71b6326c740e32f65b12c9811327e393d2c8681ba70b2`, macOS `ca6a6631d0bded45ab06b2b6aff52abe7cf3a4c2d3016df3f6579b3890fce9ea`, Windows `5fd381eeeb5d9c0565975134143aed9434929a629b68e7d9af4bc5dd7fe50d42`다. Unix 세 단계는 자연 종료, Windows native/header는 명시 owned-tail 정리·startup은 자연 종료이며 모두 command 0·drain/export/정리/lease 해제다. 53개 manifest 입력의 Git blob 대조는 Unix 원문 53개 일치, Windows 원문 52개·C witness의 메모리 LF→CRLF 변환 1개 일치다. 미해결 불일치는 없지만 3OS raw 입력 bytes가 같았다고 보고하지 않는다. 후속 checkout부터 해당 C 소스도 LF로 고정하며 로컬 정규화 SHA는 Git blob과 일치한다. ZIP 밖 JDK 원문·전체 closure·간헐적 실패 해결·게임·릴리스 성공을 주장하지 않는다. |
| Native registry 관측 source의 운영 소비자 | Windows Coordinator 296개·Reference 42개·native stdio 통과, 관련 다섯 crate strict all-targets Clippy 통과 | 현재 요청의 완료된 pairing·같은 Store·현재 native Project owner·D032 명시 관측 정책을 각 host I/O 전후 확인해 local-only registry source를 발행한다. 기존 native source도 매 요청 재검증하고 실제 proof가 같을 때만 revision을 재사용한다. explicit/native 충돌을 거절하며 실패 때 원 revision과 opaque receipt가 같은 발행만 철회한다. 후속 capture 읽기는 현재 call에만 있는 checkpoint를 사용하고, host 원 실패 및 후속 소유·취소 실패를 typed 원인으로 함께 보존한다. cancellation wrapper는 기존 partial-capture 의미를 유지한다. 최초 검사 command는 harness-free 실행기가 split test-thread 인수를 거절했으며 원 command 101을 보존하고 `--test-threads=2`로 후속 command 0·drain/export/정리/lease 해제를 확인했다. Clippy의 불필요 borrow 여섯 건도 수정 후 통과했다. artifact/mod/양쪽 pack과 target identity는 계속 미확정이며 TCP fixture 성공을 실제 게임·완전한 capture 인수로 확대하지 않는다. D034의 실제 macOS 결과는 후속 CI가 필요하다. |
| resource-only native import와 Windows 재검사 | CLI 15개·Coordinator 298개·native stdio 및 관련 strict all-targets Clippy 통과 | 문서 없이 완전한 descriptor/bytes 쌍을 같은 기존 reader·owner·Store·정책·head·원자 commit 경로로 처리한다. 빈 배치와 hash/길이 불일치 및 불완전한 쌍을 거절하고 catalog·game 권한을 만들지 않는 실제 cold fixture를 검사했다. 최초 재검사에서 기존 native catalog TCP fixture의 응답 획득 실패 1건을 보존했다. nonblocking listener에서 받은 세 fixture stream에 원래 유한한 blocking 읽기 모드를 명시한 뒤 command 0·drain/export/정리/lease 해제를 확인했다. 제품 timeout·권한·한도와 실제 host I/O 알고리즘을 바꾸지 않았다. |
| 실제 Windows whole-container resource-only import | 문서 0개·JAR resource 1개, 실제 native command 0와 확정 receipt | 새 CLI 42,237,440 bytes·SHA `a4e764cfab4ed4610a75ed2fae29cbbf40fdfbabaa7675d240827971727924ec`로 검증한 host JAR 3,466,694 bytes·SHA `b6d1b7614c1763230276ba3659853fa720d6f294ac24a15479ce9eca066b0786`를 한 번 가져왔다. receipt는 이전 revision `bd2408b01a413258dccd9e1c57150500c3a7833542e49fb70ae7e9e91869a738`에서 `fb9dbd00513ce9ccbfcfc75d1607ea30700596bc78cf62498fe72429c813f22e`로의 commit과 정확한 resource ID·길이·SHA를 보존했다. 입력과 실행 파일의 held read·전후 pin, 512 MiB/8 process Job readback, 실제 자식 0·양쪽 EOF·강제 종료 없는 drain을 확인했다. 전체 10,717 ms, 결과 3,938 bytes·SHA `3ac04824696e4dd860df8345f7adab68591f66b07b3b798b679b9cd3eff6a010`다. outer drain/export/정리/lease 해제와 원본·제품 자료 보존을 확인했다. 새 Project revision의 독립 재계산, MCP 전체 bytes 재독립 읽기, source 사용 승인·게임·릴리스 인수는 이 receipt의 증명 범위가 아니다. |
| 실제 Windows persistent MCP의 whole-container 재독립 읽기 | 53개 slice·55개 응답·전체 길이와 SHA 일치 | 앞선 CLI와 같은 실행 파일로 하나의 MCP 세션을 초기화하고 실제 Project revision `fb9dbd00513ce9ccbfcfc75d1607ea30700596bc78cf62498fe72429c813f22e`와 resource membership을 확인했다. 실제 nextOffset을 잇는 53개 base64 slice의 마지막은 58,822 bytes이며 전체 3,466,694 bytes·SHA `b6d1b7614c1763230276ba3659853fa720d6f294ac24a15479ce9eca066b0786`와 일치한다. 각 tool의 structured/text 의미, 실제 응답 ID·frame digest와 마지막 응답 뒤 EOF를 대조했다. daemon·MCP 각각 512 MiB/8 process Job readback, 자연 종료 0·양쪽 EOF·active 0·drain을 확인했다. 결과는 22,963 bytes·SHA `2eb010cef844fe2f304dca8af500a259baf604d77859b3b5d461c455eec2c39f`, 경과 90,996 ms다. outer command 0·drain/export/정리/lease 해제를 확인했으며 원시 artifact·transcript를 내보내거나 DB·CAS·credential·endpoint 파일을 직접 읽지 않았다. 제품 자료는 보존했고 source 사용 승인·게임·릴리스 인수는 별도다. |
| 스물일곱 번째 Rust CI의 실제 컴파일 및 fixture 실패 | 세 OS·집계 실패; 세 archive의 실제 bytes·SHA·source 대조 | source `3be73920b3dc6638b81c67e032bcba94a002d28b`, [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38582528633). Linux는 PIDFD lifecycle 검사 두 곳에서 `PollCheck`와 `PollObservation`을 직접 비교한 E0369/E0277 컴파일 실패며 supervisor 오류나 실제 lifecycle 성공이 아니다. 후속 소스는 실제 observation 필드를 비교하도록 보완했다. macOS는 Coordinator 288개 통과·8개 실패이며 D034 후 기존 exec native 9 문구는 사라졌지만 stdio의 검증된 drain assertion이 실패했다. bootstrap 세 건은 첫 header WouldBlock 35, catalog 네 건은 HOST_RESULT_UNKNOWN/Disconnected다. Windows는 Coordinator 294개 통과·2개 실패·1 ignored이며 source read counter 부족과 후속 HOST_RESULT_UNKNOWN으로, 이번 archive에 bootstrap header 오류나 stdio drain 실패는 없다. 원 command 101·native drain·완전한 출력·export·scratch 정리·lease 해제를 각각 확인했다. Windows는 명시된 owned-tail 정리를 포함하며 원 실패를 검사 성공으로 바꾸지 않는다. |
| 열여덟 번째 JVM CI의 macOS 감독 실패 | Windows·Linux job 성공 metadata, macOS·집계 실패; macOS 실제 archive 대조 | 같은 source의 [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38582528313). macOS Gradle 및 일곱 모듈·11 executed task 자체는 성공했으나 원 command 0 뒤 reserved leader session/zombie proof의 `process_identity` 실패와 소유 group 종료의 native EPERM 1을 보존했다. 실제 outer drain·완전한 출력·export·scratch 정리·lease 해제는 완료됐고 observer는 미실행이다. observed RSS/footprint/worker/sample-gap 수치는 한도 아래이며 이를 quota 초과나 compiler/test 실패로 분류하지 않는다. 정상 종료 전이와의 구별은 닫힌 native 진단 및 후속 실행이 필요하고, 이전 CI17 성공으로 이번 감독 실패를 대체하지 않는다. |
| Windows 관리 진입 전 실행 오류 보존 | 최초 두 셸의 C000012D 및 C0000005, 해당 관리 증거와 lease 미생성 확인 | 첫 NTSTATUS는 가상 메모리 부족의 정의와 일치하지만 당시 system commit 수치 조회는 5초 timeout으로 미관측이다. 앞선 정확한 checks owner는 complete였으며 두 외부 셸 실패를 별도 630-byte 기록·SHA `f2d551a73588d62fe7a2ea0da450df827c471d5825eb3ede0ad77f6b86cf76d6`로 보존했다. 설정·예산 변경 없이 한 번 수행한 가벼운 metadata 재검사는 442개·위반 0·command 0·drain/export/정리/lease 해제다. SAC/WDAC 오류나 Ubuntu 사용 사유로 분류하지 않았다. |
| Catalog source 사용 선택의 보호 저장 경로 | Windows runtime 114개·strict all-targets Clippy 통과, 독립 소스 리뷰 완료 | D035의 부재·재시작·전체 container pin·원본/현재 provenance·현재 owner/Store/Policy·낙관적 교체·철회 tombstone·오래된 generation 거절·CAS 손상·SQL 실패 및 취소 rollback·수량/metadata 상한·미해결 write fence를 기존 SQLite/CAS fixture로 검사했다. 최초 실행의 기존 101개 통과·새 13개 fixture 실패는 보존했다. resource-only 최초 batch에는 소유 문서 테이블이 없을 수 있으므로 test permit이 실제 부재를 0개로 관측하도록 수정했고 기존 기대 문서 개수·권한 비교는 유지했다. 후속 114개와 strict 검사의 실제 command 0·drain/export/정리/lease 해제를 확인했다. 관리 CLI·native publisher 연결과 실제 게임 source 사용은 아직 이 storage slice의 검증 범위 밖이다. |
| Cold native source-use CLI 연결과 실제 빈 집합 철회 | Windows CLI 15개·Coordinator 305개·native stdio·strict all-targets Clippy 통과, 독립 소스 리뷰 완료 | `catalog-source-use`의 inspect/replace는 초기화된 단일 Store와 실제 native owner를 사용한다. 기대 Project·상태 digest와 명시적 전체 선택 또는 `--withdraw true`를 요구하며, Project·현재 Policy와 이번 선택만 검사해 이전 source 손상이 상태 조회·철회를 막지 않게 한다. 확정 저장 뒤 취소·출력 오류는 receipt와 전달 원인을 보존한다. 새 CLI 42,632,192 bytes·SHA `6f2d2cb93674fa0f53332387dcb10e767ce9ea58bc762ce6284cbc586348ecae`로 실제 개발용 Project의 generation 0 빈 상태를 조회하고 명시적 빈 tombstone generation 1을 저장한 뒤 새 프로세스로 재조회했다. 상태 digest `0d494a2d77989b494843d1cc582b543f590ff81914a36fdcd12c1815dff4bfca`가 지속되고 Project revision `fb9dbd00513ce9ccbfcfc75d1607ea30700596bc78cf62498fe72429c813f22e`는 같다. 세 stdout receipt는 372/438/434 bytes이며 각각 SHA `d1c51156a8f1eb56dae3c6d37b2e1dc681bac36468ee1c30a63ce9a0ae9b9944`·`e16cf4f24a6bbc7c223e1f6ff2b6592a0085cb1c409c40a7e9c482e460db42b1`·`46fc674b2b337b105e0c955a8edb93e670d735892ac085b2fc57d46818d81824`다. 실행 파일 held read·전후 digest 및 세 command 0·자연 drain·출력·export·정리·lease 해제를 확인했다. DB/CAS를 직접 열거나 source 권한을 추가하지 않았고 제품 자료를 보존했다. 관리 선택 사실은 게임의 현재 ACL·mod 사용·SourceAdmission 검사를 대신하지 않는다. |
| Ordinary loader 전달과 관측 발급 마지막 현재성 검사 | Windows observer library 51개·strict all-targets Clippy 통과, 독립 소스 리뷰 완료 | 일반 정의도 실제 ClassLoad/Prepare·시도에서 대조한 loader를 기존 wire 슬롯에 전달하고 실제 bootstrap 0을 보존한다. startup의 실제 ProbeLoader ordinary와 positive hidden은 같은 nonzero loader를 요구하며 samless bootstrap 0은 유지한다. 같은 core 잠금에서 발급한 비공개 issuer/Class/generation/attempt/loader/kind stamp를 JNI 배열 생성 전후와 마지막 ExceptionCheck 뒤에 대조한다. 변경·오류 때 이번 output local reference만 폐기하고 pending exception을 보존한다. 발급 시점 순수 회귀와 실제 command 0·drain/export/정리/lease 해제를 확인했다. 실제 JNI 동시 전이·게임의 closed pipeline·전체 의미 closure 및 SourceAdmission은 별도 검증이다. |
| Darwin 원 leader의 pending-exit 분류와 원 native 진단 | Windows 관리 도구 lib 195개·bin 1개·strict all-targets Clippy 통과, isolated 1 ignored, 독립 소스 리뷰 완료 | D036의 원 예약 anchor·실제 getsid ESRCH 또는 typed memory Exited·INEXIT 조건, 임의 오류 및 다른 member pending 거절, 첫/마지막 진단·signal 권한 상실·부분 budget·원 cadence/gap을 검사했다. bootstrap parent에서 새 도구 2,827,264 bytes·SHA `d82915a8a240b7fc46f296c31d90e31cf70df5fabb4e7e0b073e84b0b74717e7`를 빌드하고 실제 Windows `mmmm --help`를 감독했다. command 0·drain·완전한 출력·export·정리·lease 해제이며 필수 빈 companion은 70 bytes·SHA `625ada3644e617b91bcfa1022c0af952adb52a110cf166542b8435ff741d735b`와 process pin이 일치한다. 이는 실제 macOS 분기의 성공·과거 실패 원인 확정이나 CI29의 별도 inner worker drain 실패 해결을 뜻하지 않는다. |
| 스물여덟 번째 Rust CI의 macOS bootstrap 실패 | Windows·Linux job 성공 metadata, macOS·집계 실패; macOS 실제 archive 대조 | source `9854bd04d3e6e7f34aba1980117a7afa5db0f526`, [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38586185222). macOS archive 3,177 bytes·SHA `8b56efec0a4323672dc25f0443cf7511265838181a536c20c5e607640d9cd3d4`는 `Darwin resource process exit not confirmed by native zombie identity`를 최초 supervisor 실패로 보존한다. 원 memory native result/errno는 미수록이므로 특정 숫자나 getsid 실패로 단정하지 않는다. command exit 미확정·drain/export 완료이며 bootstrap slot과 lease를 보존했다. finish 완료와 Rust 테스트 성공 기록은 없고 뒤 repository/format/test/lint 단계는 미실행이다. 관측한 RSS·footprint·VM·worker·gap은 한도 아래이며 숨은 peak나 일반 원인 해결을 증명하지 않는다. |
| 열아홉 번째 JVM CI의 macOS 실제 결과 | 세 OS·집계 성공 metadata, macOS archive의 내부 digest 연결 대조 | 같은 source의 [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38586185039). macOS archive 532,042 bytes·SHA `7e24a489dc08aa33cfb2c68898e229281b32e09966031f24c26d10d0f4913b7c`에서 7개 모듈·306개 테스트·필수 11 executed task와 실패 0을 확인했다. JVM 및 observer 세 단계의 process/finish/finalization, 실제 9개 record와 prior 5개 digest가 연결되고 모두 command 0·자연 종료·drain·완전한 출력·export·정리·lease 해제다. header pin 8개, startup pin과 각 전후 counter 12개·완료 phase 13개, manifest 입력 53개 연결을 확인했다. ABI2 raw/stdout은 각각 5,886 bytes·SHA `8723fbf1742c5a58c5b87b2f20720ae417a6915974e25955a4d58292ed2f50a2`다. 전체 Git blob/JDK 원문·private kernel receipt의 재검증, 간헐적 실패 해결·게임·릴리스 인수로 확대하지 않는다. |
| 스물아홉 번째 Rust CI의 macOS inner worker 실패 | Windows·Linux job 성공 metadata, macOS·집계 실패; macOS 실제 archive 대조 | source `1071ab0fd1ce6409c8b01d5b17e12e47c76a1dd1`, [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38589407975). macOS archive 31,069 bytes·SHA `50322578d859f6e5283a68bc75d14d4f9313bb37ffc4e7e6829372078a055f95`는 Coordinator 297개 통과·1개 실패를 보존한다. stdio 실패의 닫힌 값은 `worker_exit`·native `101`·native unknown false·inner drained false다. bootstrap/header/catalog fixture 실패는 없고 outer command 101·drain·완전한 출력·export·정리·lease 해제와 supervisor/cleanup 오류 0을 확인했다. 실제 native stdio integration은 시작 기록이 없고 Clippy는 미실행이다. 원인과 inner drain 복구는 후속으로 남기며 D036의 감독기 수정과 합치지 않는다. |
| 스무 번째 JVM CI의 Linux RSS 관측 실패 | Windows·macOS job 성공 metadata, Linux·집계 실패; Linux 실제 archive 대조 | 같은 source의 [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38589407976). Linux archive 62,210 bytes·SHA `c986376f9786ab9a43ee178d1add658663d0670ab779752ab2800118ae24e95d`에서 Gradle 0·7개 모듈 306개 테스트·필수 11 executed task 성공을 확인했다. 원 supervisor는 reserved leader의 rss_rollup open·OS error `Some(3)`이며, 검증된 pidfd terminal poll은 `not_ready`·native errno 없음이다. 과거 candidate stat 실패나 전체 thread group 종료 증명과 다르다. before/after state·threads는 원 기록에 없어 종료 전이로 단정하지 않는다. command 0 뒤 observation failure 1개가 process/finish/finalization에 지속되며 outer drain·출력·export·정리·lease 해제는 완료, observer는 미실행이다. 후속 닫힌 stat 진단은 기존 관측에서 state·threads·원 identity 일치 여부만 보존하고 판정·native 호출·기한·Linux gap 정책을 변경하지 않는다. Windows 도구 lib 199개·bin 1개 및 strict all-targets Clippy가 통과했고 isolated 1개는 ignored다. 독립 소스 리뷰와 실제 command 0·drain/export/정리/lease 해제를 확인했으며 실제 Linux의 새 진단 관측은 후속 CI가 필요하다. |

| Fabric 실제 registry 객체의 정의 관측과 원 응답 취소 연결 | Windows host-core 85개·Fabric host 57개, 총 142개 통과; 실패·오류·skip 없음, 독립 소스 리뷰 완료 | D037의 새 collector 8개와 inspection control 4개를 포함한다. 실제 Gradle에서 host-core test·Fabric compileJava/test 및 의존 모듈의 12 actionable task를 모두 재실행했고 실행 전후 여덟 소스 파일의 digest가 일치했다. 원자료 Class identity 중복 제거·상한·bridge 부재·관측 변경, 원래 기한·late queued 취소·minimal stage 보호와 취소 race를 검사했다. 최초 리뷰에서 응답 stage의 복사만 취소하던 경로를 발견해 원 future 소유자의 hook으로 수정한 뒤 검증했다. 관리 command 0·21,801 ms·자연 종료·drain·완전한 출력·export·scratch 정리·lease 해제를 확인했고 Job commit peak는 1,290,719,232 bytes였다. Java native-access 및 Gradle deprecated 경고는 보존했다. 이번 두 모듈의 실제 실행을 일곱 모듈 전체 재검사, 실제 게임 JNI 실행·최종 변환 증명이나 target admission 성공으로 확대하지 않는다. |
| 서른 번째 Rust CI의 macOS inner worker 실패 | Windows·Linux job 성공 metadata, macOS·집계 실패; macOS 실제 archive 대조 | source `2cfabd159f3d4b36402a8d45b482b3ae02df78e3`, [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38594378185). macOS archive 31,376 bytes·SHA `cebaae08e834a9aa94aa252e8bb430687f689e6dafa675b7f135688b4e0ac177`는 Coordinator 304개 통과·1개 실패를 보존한다. 유일한 startup rejection assertion의 닫힌 값은 `worker_exit`·native `101`·native unknown false·inner drained false이며 원 cleanup 원인은 기록에 없다. outer command 101·142,643 ms·자연 종료·drain·완전한 출력·export·scratch 정리·lease 해제와 supervisor/cleanup 오류 0을 확인했다. outer D036의 native-memory-exits와 pending-leader-exit은 null이므로 해당 분기의 실제 발생을 확정하지 않는다. native stdio integration과 Clippy 성공, 내부 drain 실패 해결은 후속으로 남긴다. |

| 스물한 번째 JVM CI의 Unix 실제 결과 | 세 OS·집계 성공 metadata, macOS·Linux archive의 실제 record 연결 대조 | 같은 source `2cfabd159f3d4b36402a8d45b482b3ae02df78e3`의 [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38594378244). macOS archive 536,056 bytes·SHA `f5bd049d66c3e0f4f4d029a0b78f22f4f9f75cb7bcbde84ad5f7b595b4be438b`, Linux archive 1,861,846 bytes·SHA `a341864558257a15d3cc5db7a5a92de6b936364a6bf30b14487214fbcf7e986c`를 확인했다. 각 OS의 7개 모듈·306개 테스트·필수 11 executed task와 실패 0, observer 세 단계의 실제 9개 managed record·prior JVM 5개 digest 연결을 대조했다. 네 실행은 각각 command 0·자연 종료·drain·완전한 출력·export·scratch 정리·lease 해제이며 supervisor/cleanup 오류 0이다. header 8 pin·startup 12 pin과 각 전후 counter 12·완료 phase 13개·manifest 53개 입력 연결을 확인했다. ABI2 raw와 원 stdout은 각각 5,886 bytes이며 macOS SHA `16de411855ec55779f344e1f7f0cefe74775b00c4f38b837f9b5436f65275c22`, Linux `ecbac14b25df0c9e8317d460de4398e73ac0ebfbbab8c1b9085667e261d48af2`다. source에 고정된 ordinary-loader/current-stamp startup 검사 성공과 기록 연결을 확인했지만 JSON에 별도 loader/current stamp 필드는 없어 raw ABI를 독립 재구성한 검증으로 보고하지 않는다. 새 Linux stat 진단 발생도 없었다. Windows는 job metadata만 확인했으며 이후 Java collector 여덟 파일·간헐적 실패 해결·전체 JDK/의미 closure·게임·릴리스 인수로 확대하지 않는다. |

| 스물두 번째 JVM CI의 Linux 실제 결과 | 세 OS·집계 성공 metadata, Linux 새 archive의 실제 기록 대조 | source `3a6e6bef436e0c6bbdd3135878fcb57b4860a76a`, [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38597005520). Linux archive 1,862,240 bytes·SHA `812fb0a6d80c63d6374a1a1945d62c2c7a47b50f0fd6b90e4258b607c432b972`에서 새 host-core 85개·Fabric host 57개를 포함한 7개 모듈 318개·필수 11 executed task와 실패·오류·skip 0을 확인했다. source·예상 source·PR head가 일치하며 observer 실제 9개 record·prior JVM 5개 digest·manifest 53개 입력과 header 8 pin·startup 12 pin 및 전후 counter 12·완료 phase 13개가 연결된다. ABI2 raw와 stdout은 각각 5,886 bytes·SHA `c1c3d740e6a2d670d7301d0135d22e4c06c5171187f06c34e20ab8cc1e825405`로 같다. JVM과 observer 세 단계는 각각 command 0·자연 종료·drain·출력·export·scratch 정리·lease 해제와 오류 0을 보존한다. stat 진단은 발생하지 않았다. 이 행의 실제 archive 대조는 Linux에 한정하며 이후 D039 변경·실제 게임·SourceAdmission·릴리스 완료의 근거로 사용하지 않는다. |
| 정의 수집 슬롯의 종료·게시 경합과 독립 session close | Windows JVM 7개 모듈 총 326개·29 executed task 통과; 실패·오류·skip 없음 | D039의 host-core 89개·Fabric host 61개를 포함한다. close hook 4개와 collector/slot 12개가 clear 전후 old ticket, 같은/다른 owner, 완료 및 pending raw, 늦은 hook·중복 close·monitor 밖 callback·재진입과 각 16회 경합을 검사한다. 최초 325개 성공 뒤 독립 리뷰에서 옛 endpoint 종료가 새 owner에 영향을 줄 수 있는 경로와 closed/context 해제 순서를 발견했다. route guard 아래에서 정확한 owner·listener를 capture하고 해당 자원만 guard 밖에서 종료하며, context 해제 뒤 closed와 hook을 게시하도록 수정했다. 후속 독립 리뷰의 blocking finding은 없었다. 최종 다섯 변경 소스의 전후 digest가 같으며 실제 Gradle command 0·30,541 ms·자연 종료·drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다. Job commit peak는 1,343,107,072 bytes·peak process 5개·최대 표본 간격 142 ms이며 기존 2 GiB/32 process 한도를 유지했다. 최초 실행과 원 native-access/Gradle deprecated 경고는 보존했다. actual Class 원자료의 host 슬롯 수명 검사이며 native 호출 선점·게임 JVM 실행·정의 최종성·3OS D039 성공을 뜻하지 않는다. |

| 보호 source-use 집합의 native catalog 소비와 철회 전이 | Windows Coordinator 310개·native stdio 인수·Coordinator/CLI strict all-targets Clippy 통과, isolated 1개 ignored | D038의 실제 game Project ACL/container scope·정확 Policy 내부 읽기·현재 mod-use·전체 CAS와 원본/현재 association을 검사했다. 선택 두 container와 registry를 같은 publisher로 병합하되 두 pack stack은 계속 unknown이다. 실제 보호 집합 generation 1을 빈 tombstone 2로 교체해 Project 불변, 다음 capture의 `TARGET_DRIFT`, catalog 관찰 요청 0회와 exact receipt 폐기, 이후 registry-only 새 발행을 옛 receipt가 지우지 못함을 검사했다. 정상 사전 `execution_context` 조회를 catalog 관찰과 분리했다. 최초 300개 통과·9개 실패는 reader마다 D032 전체 읽기를 중첩한 경로였으며 한 bounded read 전후 검사로 정리하고 콜백의 현재 request/owner/Store/게임 권한을 유지했다. 후속 309개 통과·1개 실패의 잘못된 전체 host counter와, 다음 309개 통과·1개 실패의 네 독립 RPC가 하나의 10초 budget을 공유한 fixture를 각각 수정했다. 요청별 기존 10초·Peer 전체 30초·생산 상한과 권한은 늘리지 않았다. 최종 test command 0·58,522 ms·명시 owned-tail 정리 뒤 drain·출력·export·scratch 정리·lease 해제, strict command 0·6,949 ms·자연 종료를 확인했다. lib 필터를 harness-free integration에 넘긴 별도 호출 오류와 잘못된 CLI package ID `mmmm-cli`의 미실행 오류도 보존하고, 올바른 전체 test 및 실제 package `mmmm` strict 성공과 구분했다. 실제 게임 container·팩·최종 정의 admission은 별도다. |
| macOS stdio startup 거절의 닫힌 실패 진단 보완 | Windows 전체 Coordinator 검사와 strict 검사 통과, 독립 소스 리뷰 완료 | 기존 `drained=false`인 테스트 실패에만 cleanup의 code/native/unknown, startup의 기존 Display와 선택한 macOS resource 카운터·정적 code·typed stage/failure/native result/errno를 최대 여섯 record로 남긴다. PID·주소·FD·path·token·frame·raw stderr나 전체 Debug는 출력하지 않는다. 생산 lifecycle·resource·기한·성공 assertion은 변경하지 않았다. macOS 필드·타입의 소스 정합성은 검토했으나 실제 macOS 컴파일·진단 관측과 CI30의 내부 drain 실패 해결은 후속 실행이 필요하다. |

| 서른두 번째 Rust CI의 Linux 컴파일 중 관측 실패 | Windows job 성공, Linux·macOS·집계 실패; Linux 실제 archive 대조 | source `bb05634d500463bcb23a772745af37093a0761b7`, [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38600514808). Linux archive 15,923 bytes·SHA `29c1be97f7e8c8459f6772a1d4f5849e03aa178effddd056f6b0d69690cb21b8`의 source·예상 source·PR head를 대조했다. dependency 컴파일 중 `process_identity` 관측 실패로 command exit 미확정·signal 9·13,920 ms를 기록했으며 테스트 case는 시작하지 않았다. owned member의 before는 zombie·threads 3·원 identity 일치, after는 dead·threads 0·불일치였다. count-only 정책이므로 RSS와 pidfd bind/poll 관측은 없으며 이전 JVM의 pidfd 사실을 이 실행에 적용하지 않는다. 달라진 identity 필드와 실제 kernel version은 기록되지 않아 종료 cleanup으로 원인을 확정하지 않는다. 종료 signal은 관측 실패에 대한 소유 scope 정리의 결과이며 OOM이나 제품 테스트 실패로 바꾸어 보고하지 않는다. drain·완전한 출력·export·scratch 정리·lease 해제와 cleanup 오류 0을 확인했다. |
| Linux stat의 비교 필드와 실제 pidfd 단계 진단 보완 | Windows 도구 lib 201개·bin 1개 및 strict all-targets Clippy 통과, isolated 1개 ignored | D040의 추가 필드·sentinel·count-only/RSS 단계 구분과 원 오류·최초 진단·drain 보존을 검사했다. 독립 소스 리뷰를 마쳤고 첫 strict 검사의 `result_large_err` 64건은 diagnostic 확대로 오류 값이 128 bytes가 된 문제였다. optional payload만 boxing하여 해결하고 lint 예외를 넣지 않았다. 후속 실제 test command 0·16,841 ms·명시 owned-tail 정리와 strict command 0·2,333 ms·자연 종료를 구분한다. 두 실행 모두 drain·완전한 출력·export·scratch 정리·lease 해제와 supervisor/cleanup 오류 0이다. 새 Linux 필드의 실제 CI 관측과 Linux identity 실패 해결은 후속으로 남긴다. |
| 서른두 번째 Rust CI의 macOS inner 종료 실패 지점 | macOS Coordinator 309개 통과·1개 실패; 실제 archive와 닫힌 진단 대조 | 같은 source와 [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38600514808)의 macOS archive 31,750 bytes·SHA `397c4534601231f322c58afe850bebfbc7ddc84d46b9ab6b3e2943e31b16699e`를 대조했다. startup은 `no_connection`·연결/hello 시도/수신 각 0·admission false였으며 주 오류는 `worker_exit`·native 101·inner drained false, cleanup은 `native_terminate`·native 없음·unknown false다. 정확한 source에서 이는 소유 process group의 기존 SIGKILL이 실패하고 errno가 ESRCH가 아닌 경로이며, 원 errno는 저장되지 않아 EPERM 등으로 확정하지 않는다. drain loop의 empty/reap 증명 전에 종료됐다. 확정 zombie 관측 1회·pending 0회이고 typed resource 오류가 없어 D036 pending/memory-exit 실패로 분류하지 않는다. outer command 101·191,331 ms·자연 종료·drain·완전한 출력·export·scratch 정리·lease 해제와 supervisor/cleanup 오류 0을 구분한다. 내부 종료 실패의 원인 해결과 native stdio/Clippy 성공은 후속이다. |
| 스물세 번째 JVM CI 상태 | 세 OS와 집계 성공 metadata 확인 | 같은 source `bb05634d500463bcb23a772745af37093a0761b7`의 [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38600514845)이다. 이 행에서는 새 archive 원문을 대조하지 않았으며 D039의 후속 Java 변경이나 실제 게임·릴리스 인수 성공으로 사용하지 않는다. |

| FN23 production snapshot 소비와 geometry 게시 경계 | Windows Coordinator 319개·native stdio 인수 및 Coordinator/CLI strict all-targets Clippy 통과, isolated 1개 ignored | D041의 private adapter를 기존 FeatureSources·Catalog·ShapeService·FN31 product registry에 연결했다. 새 집중 검사 7개는 geometry identity의 원 snapshot/context/query 결합·크기·실패와 typed 원인 보존을 다룬다. 새 native 전제 검사 2개는 source 미발행 상태의 FN23이 새 source를 발행하지 않음, native 발행 성공 이후에도 artifact 또는 pack identity가 미확정이면 capture·guessed snapshot을 거절하고 기존 발행·shape I/O 0을 유지함을 확인한다. 공통 실제 service 검사는 성공 뒤 invalid output·취소에서 새 pending만 폐기하고 이전 publication을 보존한다. 같은 SQLite/CAS의 실제 FN31은 별도 exact native grant가 source-use 철회와 product registry busy 상태에서도 독립적으로 유효함을 확인한다. 독립 리뷰의 catalog-only 잔여 consumer 검사·마지막 hello 후 durable 검사·공통 최종 검사 전 publication·checkpoint typed 원인 소실을 수정하고 재리뷰의 추가 확정 finding은 없었다. 최종 test command 0·61,893 ms·명시 owned-tail 정리와 strict command 0·7,187 ms·자연 종료를 구분하며 drain·완전한 출력·export·scratch 정리·lease 해제와 supervisor/cleanup 오류 0을 확인했다. 실제 known geometry 보존·opaque receipt의 FN31 양성/stale 소비, mode/neighbor·probe 후 취소·마지막 hello 중 CAS 변경의 통합 경로는 미검증이다. 현재 native game/양쪽 pack identity는 계속 unknown이며 SourceAdmission·VerifiedTarget을 발급하지 않는다. |
| FN23 첫 실행의 잘못된 fixture 전제 보존 | 최초 316개 통과·6개 실패, 후속 317개 통과·2개 실패를 최종 성공과 구분 | 첫 다섯 새 검사는 game artifact·양쪽 ordered pack identity가 없는 native fixture에서 capture 성공을 기대했다. 생산 capture 조건은 유지하고 도달하지 못하는 mode/neighbor/probe 후 취소·마지막 hello 검사를 제거해 두 개의 실제 전제 검사로 좁혔다. 초기와 후속의 CANCELLED는 독립 capture/source_refs/register 호출이 하나의 10초 deadline을 공유한 fixture를 추적해 해당 호출마다 같은 10초 budget을 새로 취득했다. 후속 잘못된 관측 0회 assertion은 pairing 중 발생한 hello를 포함하므로 호출 전후 불변 비교로 교정했다. 의도된 같은 요청의 취소와 생산 권한·기한·자원 상한은 바꾸지 않았으며 실패 원본을 보존했다. |
| Unix stdio 종료 실패의 실제 errno 보존 | Windows의 확장된 순수 진단 검사와 전체 Coordinator/strict 통과, 독립 소스 리뷰 완료 | 기존 소유 group SIGKILL이 실패한 직후 원 OS 오류를 한 번 capture하여 `native_terminate`의 numeric native code에 보존한다. ESRCH만 허용하는 판정·kill 호출 수와 순서·identity/signal 권한·drain·기한·한도·성공 assertion은 유지했다. 기존 순수 검사를 확장해 primary 오류·drained와 cleanup/startup의 native 숫자 및 정적 Display를 확인했다. 과거 CI32의 소실 errno는 복구되지 않으며 실제 새 macOS errno와 내부 종료 실패 해결은 후속 CI가 필요하다. |
| 서른세 번째 Rust CI의 Linux 실제 성공 | Windows·Linux job 성공, macOS·집계 실패 metadata; Linux 새 archive의 실제 검사·영수증 대조 | source `d2144103aa145cc10ca59252c8d4b21816a9c46f`, [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38605205135). Linux archive 49,338 bytes·SHA `ec4b4a1c55b7b881667fe7052ef10812616954b173265e7871c121d0c52a38d4`의 source·예상 source·PR head와 Rust 1.96.0·build jobs 2를 대조했다. 16개 unit/bin 표준 결과는 1,106개 통과·실패 0·ignored 4이며 Coordinator 308개·도구 lib 216개/bin 1개를 포함한다. doc 결과 14개는 모두 성공이고 실제 compiler doc 검사 1개가 포함된다. native_stdio는 별도 custom harness로 한 번 실행돼 Cargo test 전체 0을 확인했으며 표준 pass 수에 임의 합산하지 않았다. 실제 Rust test 193,009 ms·Clippy 44,387 ms와 format·repository 단계가 모두 command 0·자연 종료·drain·완전한 출력·export·scratch 정리·lease 해제·오류 0이다. repository 451개·위반 0을 확인했다. 새 stat 진단은 발생하지 않았으므로 CI32의 간헐 identity 실패 재현·원인 확정·해결의 증거로 확대하지 않는다. 같은 source의 [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38605205149)은 성공 metadata이며 이 행에서 새 JVM archive는 대조하지 않았다. 이후 D041와 새 errno 전달 변경은 이 CI의 source에 포함되지 않는다. |
| ZIP/JAR 입력 inventory의 순수 producer | Windows reference 53개와 strict all-targets Clippy 통과, 독립 소스 리뷰 후 재검증 | D042의 실제 bytes 길이·digest·member kind/원 literal 이름·해제 길이·digest를 opaque getter로 반환한다. 새 11개 합성 메모리 검사는 원 JSON 예제로 표현할 수 없는 ZIP header/count/CRC/descriptor/Deflate 소비·이름·취소 경계에 한정했다. 최초 53개·strict 통과 뒤 독립 리뷰에서 portable fold와 secret selector의 불일치 및 CRC가 descriptor signature 값인 유효 signatureless 입력의 오인을 발견했다. 같은 fold helper와 전체 이름 선검사, 물리 local 경계·central CRC/size를 대조하는 12/16-byte 유일 후보 선택으로 수정했다. 기존 검사에 dotless-i/long-s·late secret과 실제 CRC 충돌 payload·중앙 순서 반전·손상 거절을 추가하고 재리뷰의 추가 확정 finding은 없었다. 최종 test command 0·15,413 ms·명시 owned-tail 정리, strict command 0·1,634 ms·자연 종료와 두 실행의 drain·완전한 출력·export·scratch 정리·lease 해제·오류 0을 확인했다. 기존 exact infrastructure 의존성 네 개를 같은 버전/feature로 연결했고 lock 변경은 reference dependency edge만이다. Coordinator의 현재 source-use/CAS 권한에 묶는 생산·보존 연결, 실제 게임 JAR 호환성과 성능·3OS 인수는 별도다. |
| 서른네 번째 Rust CI의 macOS 종료 중 member 관측 거절 | Windows·Linux job 성공, macOS·집계 실패; macOS 실제 archive 대조 | source `dfd34ab0167cbb3b5954a563e9e592a2f0925ab1`, [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38607946641). macOS archive 16,906 bytes·SHA `e9007909b53ca50720198a5a56d44d23cf04383b966021b52966433183ac4746`의 source·예상 source·PR head가 일치했다. dependency 컴파일 중 ObservedMember의 TaskInfo native result 0·errno 3이 Exited로 분류됐지만, before/after BSD status 2·INEXIT true·동일 anchor true이며 SZOMB가 아니어서 기존 strict member 정책이 거절했다. 전체 표본은 성공 처리하지 않았고 이전 성공 101개·max gap 221 ms를 보존했다. command exit 미확정·signal 9·13,980 ms·observation_failure이며 테스트 case나 stdio 진단은 시작하지 않았다. 원 1,200초 기한·1초 gap·자원 상한 실패로 분류하지 않는다. outer drain·완전한 출력·export·scratch 정리·lease 해제와 cleanup 오류 0을 확인했다. 같은 source에 errno 전달 수정이 있어도 이 실행에서는 해당 stdio 경로를 검증하지 못했다. |
| 스물다섯 번째 JVM CI의 Windows 시작 전 조회 기한 실패 | Linux·macOS job 성공, Windows·집계 실패; Windows 실제 archive 대조 | 같은 source의 [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38607946408). Windows archive 339,997 bytes·SHA `a516650845be97f71053444cc6a7ad2822e489e1ddd9059ed08d984eabf5b9a4`의 context·module 보고서와 observer native/header 영수증 6개·prior JVM 5개·source manifest digest를 대조했다. 실제 7개 JVM 모듈 326개·필수 11 executed task와 Fabric compile은 실패/오류/skip 0이며 native build도 성공했다. header compiler 선택의 vswhere_executable에서 OBSERVER_VSWHERE_PRESPAWN_DEADLINE·RuntimeException HRESULT -2146233087·native 없음이 보존됐다. lookup은 process_started false·출력 0이며 최초 executable digest만 생성한 채 13,968 ms가 경과해 기존 work 5,000 ms를 넘었다. physical I/O·hash·cold runtime·scheduling 중 어느 원인인지는 세부 관측이 없어 미확정이고 SAC/WDAC 근거는 없다. actual ABI/header와 controlled startup은 실행되지 않았다. JVM/native/header outer command는 각각 0/0/1, 114,246/4,976/14,834 ms이며 drain·출력·export·scratch 정리·lease 해제·supervisor/cleanup 오류 0을 확인했다. native의 owned-tail 정리를 별도로 보존하며 내부 미시작 nullable 상태를 outer drain 실패로 바꾸지 않는다. |
| Darwin member의 불완전 메모리 표본과 role별 보존 | Windows 도구 lib 203개·bin 1개 및 strict all-targets Clippy 통과, isolated 1개 ignored | D043의 실제 TaskInfo/Exited/0/ESRCH·양 INEXIT·non-SZOMB·동일 다섯 identity 조건만 허용하고 다른 stage/errno/result/identity를 거절하는 순수 검사를 수행했다. member Pending 뒤 정상 leader의 측정도 부분 상한에 포함하며 전체 Pending의 성공·peak·마지막 성공 시각·empty/drain 비승격과 기존 cadence/gap/부분 상한 실패를 보호한다. 독립 리뷰에서 한 scan의 나중 Pending이 앞선 member 사실을 덮던 문제를 찾아 role별 bounded 집계와 단일 merge로 수정했다. 기존 검사에 member→member·member→leader·혼합·후속 hard error의 first/last/count 보존을 추가하고 재리뷰의 추가 확정 finding은 없었다. 최종 test command 0·16,254 ms·명시 owned-tail 정리와 strict command 0·2,178 ms·자연 종료를 구분하며 drain·완전한 출력·export·scratch 정리·lease 해제·오류 0을 확인했다. macOS cfg의 연결을 소스로 재검토했으며 실제 macOS 컴파일·원 전이 관측·stdio 종료 실패 해결은 후속이다. |
| Windows observer discovery의 시작 전 세부 기록 | Windows 순수 fixture 6개 그룹 통과, 생산 경로의 native 실행은 미검증 | 같은 원 clock의 prepare/program_files_physical/executable_physical/executable_open/executable_hash/spawn_prepare를 닫힌 단계와 정수 started/nullable completed ms로 보존한다. 기존 동기 작업 사이에 원 5초 checkpoint를 적용하고 실행하지 않은 단계와 미완료 단계를 구분한다. 원 FS/open/hash/Start/Kill을 추가·재정렬하지 않고 만료 뒤 후속 진입만 차단하며 pin/revalidation/digest, work 5초·cleanup 2.5초·outer 180초·재시도 없음은 유지한다. 독립 소스 리뷰 후 AST로 생산의 순수 함수 두 개만 추출하여 nullable·순서·4,999/5,000/5,001 ms 경계·후속 작업 차단·JSON 왕복·닫힌 단조 전이를 실제 검사했다. 최초 fixture는 비공개 ParameterBindingValidationException type literal을 해석하지 못해 실패했다. 공개 base type과 정확한 type-name 문자열 비교로 해당 검사만 교정한 뒤 command 0·683 ms·자연 종료·drain·출력·export·scratch 정리·lease 해제·오류 0을 확인했다. 일반 검사 코드 오류와 SAC/WDAC 차단을 구분하며 Ubuntu는 사용하지 않았다. 실제 vswhere/physical lookup/main을 이 fixture에서 실행하지 않았고 기존 13,968 ms의 세부 원인과 새 생산 진단은 후속 Windows CI가 필요하다. |

| 보호 selected input의 archive inventory 보존 | Windows Coordinator 325개·native stdio 인수 및 Coordinator/CLI strict all-targets Clippy 통과, isolated 1개 ignored | D044를 현재 `catalog.capture`에 연결했다. 실제 완료된 native 발행과 같은 Store·owner·현재 Project/Policy·D032/D035 선택·전체 CAS를 전후 확인하고, 한 입력씩 읽어 provenance·member page·manifest를 immutable resource로 등록한다. registry에는 exact 발행 receipt와 작은 참조/summary만 남긴다. 새 순수 검사 5개와 실제 TCP/SQLite의 잘못된 ZIP 거절 검사 1개를 추가하고 기존 empty ZIP·선택 두 입력·취소·철회/cache 검사를 확장했다. 독립 리뷰에서 고정 4 KiB 예약이 긴 canonical mod 선택의 rejection manifest를 보장하지 못함을 찾아 실제 fallback encoding 크기를 입력별 선예약하도록 고쳤다. 같은 helper와 긴 유효 선택으로 exact 16 MiB 경계를 재검사했으며 재리뷰의 추가 확정 finding은 없다. 최초 strict의 collapsible_if 오류를 수정한 뒤 최종 test command 0·73,241 ms·명시 owned-tail 정리와 strict command 0·7,684 ms·자연 종료를 확인했다. 두 실행의 drain·완전한 출력·export·scratch 정리·lease 해제·supervisor/cleanup 오류 0이다. archive 완료는 raw FN31의 독립 grant·effective pack mapping·SourceAdmission·실제 게임 호환성 증거가 아니며 actual 입력 JAR와 3OS 검증은 후속이다. |
| 서른여섯 번째 Rust CI의 macOS stdio 종료 실패 | Windows·Linux job 성공, macOS·집계 실패; macOS 실제 archive 대조 | source `cd2b9dbe8121c61ed05f31b0f344d82ea6d91a9f`, [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38611877510). macOS archive 31,964 bytes·SHA `d4d71a0bffb7bd4a4df9962bf8b535d79d0a091a38708fff5658e150d48b52fe`의 실제 source·expected·PR head가 일치했다. Coordinator 318개 통과·stdio 거절 후 drain 검사 1개 실패이며 주 오류는 worker_exit/native 101·drained false, cleanup은 native_terminate/native 1(EPERM)·unknown false다. startup no_connection·accept/hello 0·362 ms·child admitted false·parent confirmed-zombie 1·pending 0·resource failure 없음이다. exact group SIGKILL 직후 errno 보존 경로를 확인했지만 pre-signal group empty 결과와 커널 하위 원인은 미관측이다. outer command 101·258,133 ms·자연 완료·drain·출력·export·scratch 정리·lease 해제·오류 0을 구분한다. D043 소스의 실제 macOS 컴파일은 진행됐으나 pending leader/member와 memory exit 필드는 모두 null이며 그 전이는 이번 실행에서 검증하지 못했다. 1,832개 표본·max gap 293 ms를 확인했다. |
| 스물일곱 번째 JVM CI의 Windows 성공과 Linux 감독 실패 | Windows·macOS job 성공, Linux·집계 실패; Windows·Linux 원본 archive 대조 | 같은 source의 [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38611878245). Windows 350,983 bytes·SHA `e6d5fdd924dbf5029fc06cdd571f350272b541dc9cd399b001bf460b1ea46e1d`, Linux 63,406 bytes·SHA `684773c97e72662498771f7ae464bf7e3e56221846a31bcc590f0e129daab429`의 source·expected·PR head와 실제 7모듈 326개·11 executed task·실패/오류/skip 0을 각각 확인했다. Windows는 observer native/header/startup의 영수증 9개와 prior JVM 5개·source manifest 53 inputs의 digest 연결이 일치했다. 새 실제 discovery는 전체 574 ms·prespawn 179 ms이고 6단계가 모두 원 5,000 ms 안에 완료됐다. ABI2 원문과 stdout는 각각 5,886 bytes·같은 SHA `84949f898e9fa92f6eba90fe3e67e1efa5723542a2ad91498464ab0c948ee063`이다. native/header의 owned-tail 정리와 JVM/startup의 자연 종료를 구분하며 모두 drain·출력·export·scratch 정리·lease 해제·오류 0이다. Linux는 Gradle 0 뒤 예약 leader RSS rollup open ESRCH로 감독 실패했다. D040은 before/after Zombie·threads 2·PID/start/group/session 각각 일치·sentinel false·BoundValidated pidfd의 실제 not_ready를 보존했다. whole thread group 종료를 증명한 상태는 아니다. command 0·80,068 ms와 observation_failure·감독 오류 1을 구분하고 원 오류와 drain·출력·export·scratch 정리·lease 해제·cleanup 오류 0을 확인했다. Linux observer는 skipped이며 entry도 없고, Windows 성공을 game·loaded closure·SourceAdmission·배포 완료로 승격하지 않는다. |

| Darwin stdio의 fresh terminal/empty 신호 생략 | 소스 독립 검토 및 Windows formatting 통과; 실제 macOS cfg 실행은 미검증 | D045는 기존 `terminate_before`의 strict identity 결과를 보관해 fresh SZOMB·non-pending에 한해 원 기한의 WNOWAIT exit와 기존 scope empty를 확인한다. live/pending/unknown에서 새 probe를 호출하지 않으며 exit 미확인·nonempty는 원 kill을 유지한다. typed 관측/identity/deadline 오류는 원 numeric 오류·자원 사실과 함께 반환한다. 기존 Mac 순수 모듈의 검사 1개에 exit/scope 조합·probe 미호출·typed 오류 보존을 추가했으나 Windows에서는 해당 cfg를 실행하지 않았다. 기존 blocking/poll cancel의 두 안정 관측·reap과 EPERM/ESRCH 처리는 그대로임을 현재 소스로 재검토했다. 원 CI36의 실패와 group empty 미관측을 유지하며 후속 실제 macOS 컴파일·새 검사·원 stdio drain 경로가 필요하다. |

| Deflated 빈 directory와 실제 자체 생성 JAR inventory | Windows reference 54개 및 strict all-targets Clippy 통과, 자체 Gradle JAR 한 개의 실제 producer 실행 통과 | 소유 Gradle JAR의 중앙 metadata에서 82 entries 중 명시 directory 7개가 모두 Deflated임을 관측해 D042의 Stored-only 조건을 보완했다. decoded 0·CRC 0 선언을 유지하며 실제 공통 decoder의 stream end·완전 소비·빈 출력·CRC·SHA를 통과해야 한다. 기존 메모리 compressor를 재사용한 새 검사 1개는 정상 빈 stream·nonempty 위조·잘림·전체 stream 누락·trailing·nonzero CRC/decoded 선언을 보호한다. 독립 소스 리뷰의 확정 finding은 없고 test command 0·16,036 ms·명시 owned-tail 정리, strict command 0·9,924 ms·자연 종료 및 drain·출력·export·정리·lease 해제를 확인했다. 외부 개발 probe의 실제 Windows 실행은 JAR 3,466,694 bytes·SHA `b6d1b7614c1763230276ba3659853fa720d6f294ac24a15479ce9eca066b0786`, member 82개·directory 7개·decoded 4,098,465 bytes·complete true를 확인했다. producer 내부 69 ms와 전체 command 1,472 ms를 구분하며 command 0·자연 drain·출력·export·scratch 정리·lease 해제·오류 0이다. 이 한 개의 자체 생성 입력 호환성은 실제 게임 JAR 전체·effective pack view·SourceAdmission·성능 인수의 증거가 아니다. |
| 개발 probe 출력 경로 오류의 한정 복구 | 컴파일 0 뒤 자동 export 실패를 보존하고 정확한 소유 기록과 미시작 후속 lease를 별도로 복구 | 첫 probe는 허용된 cache 디렉터리 밖에 EXE/PDB를 생성해 관리 도구가 최종 export를 거절했다. 원 command 0·2,782 ms·owned-tail drain·출력 완료와 자동 export false·중단 lease를 보존했다. 비활성인 정확 owner·token·다른 active slot 0·빈 로그를 확인하고, 사용자가 허용한 해당 실행의 수동 복구로 원 로그를 별도 보존하고 빈 scratch만 정리해 owner 완료·lease 해제를 기록했다. 긴 정리 명령의 자동 승인 거절 뒤 정확한 파일과 단계별 검증으로 처리했으며 원 실패 기록은 수정하지 않았다. 동반 PDB를 놓친 후속 시작 전 오류도 별도 보존했고, 이전 완료 owner와 scratch 미생성·새 lease만 존재하는 acquire 반환 전 실패 분기를 대조해 그 소유 lease만 회수했다. EXE 1,217,536 bytes·SHA `154a7e15e9698e64984a033ab09b86b17ceb92730ebe435a399ce201d5882f02`와 PDB 6,336,512 bytes·SHA `7b805584ffce9e3d4aff22d3d8eb8307585d403394d7ea79b50d1eb1a9e0e097`를 허용된 `cargo-target/debug`로 옮겨 digest를 대조했다. cache 최상위가 허용된 디렉터리 5개뿐임을 확인한 뒤 새 probe 실행을 정상 완료했다. 제품 DB/CAS·다른 실행·원 증거는 정리하지 않았고 일반 중단 lease의 자동 채택이나 정책 완화를 추가하지 않았다. |

| Linux JVM의 조건부 leader RSS Pending | Windows 도구 lib 208개·bin 1개 및 strict all-targets Clippy 통과, isolated 1개 ignored | D046의 실제 typed 교집합만 Pending으로 생산하고 다른 member의 실제 lower bound를 같은 예산으로 검사한다. 원 leader anchor·미회수 Child 예약을 모두 요구하며 원 오류와 stat/pidfd first·last·count를 후속 실패에도 한 번 보존한다. 이전 Complete와 100 ms attempt를 분리하고 마지막 실제 Complete부터 1,000 ms가 지난 회복을 수치 갱신 전에 거절한다. count-only empty가 Pending을 지우지 못하며 정상 reap과 실패 후 물리 drain을 구분한다. 기존 stat fixture로 순수 검사 5개를 추가하고 일반 Linux·Pending 없는 JVM 및 Pending 해소 후의 일반 2초 gap 회귀를 유지했다. 독립 소스 리뷰 뒤 첫 컴파일에서 기존 pidfd fixture의 새 known RSS 초기값 누락 1개를 발견해 초기값과 같은 검사의 실제 lower-bound 보존 assert를 보완했다. 최종 test command 0·21,431 ms·명시 owned-tail 정리, strict command 0·4,162 ms·자연 종료, formatting 및 drain·출력·export·scratch 정리·lease 해제·오류 0이다. 새 native 조회·poll·retry/sleep·상한 확대는 없고 실제 Linux 전이의 새 분기 실행은 아직 미검증이다. |
| 스물아홉 번째 JVM CI의 3개 OS 실제 검증 | 같은 source의 세 job·집계 성공과 세 원본 archive의 실행·digest 연결 대조 | source `80e5a221f8fa3eb3068d5fe9b0f12934fed922e9`, [JVM run](https://github.com/daejunnom/MMMM/actions/runs/38615047111). Windows 350,947 bytes·SHA `0ccb6fbd8a5e570135ce5724d565db0770ac2887be2d91d6d4db9b3b27e4c019`, Linux 1,862,465 bytes·SHA `91ad2d7b137488ae5e6ad7111707f05265a8f6d1b8c38e62c840c4effe82a2ac`, macOS 536,746 bytes·SHA `01fd98018f2517057a4df141f9deedf252ecd93bc5331d3f18908cbd067b000f`의 source·expected·PR head를 대조했다. 세 OS 각각 7모듈 326개·필수 11 executed tasks·실패/오류/skip 0이며 observer 9 receipt·prior JVM 5개·manifest·실제 ABI/stdout·startup pin 연결이 일치했다. Linux의 중복 제외 선택 입력 201개는 해당 SHA의 Git blob 길이·SHA와도 일치했다. Header pin 8개, startup acquired/pre/post 12개·13 phases 완료이며 네 managed 단계는 세 OS에서 모두 자연 완료·exit 0·drain·출력·export·scratch 정리·lease 해제·오류 0이다. Windows discovery는 전체 1,674 ms·prespawn 566 ms로 6단계가 원 5초 안에 완료됐다. Linux는 RSS 708 samples·incomplete 0인 별도 성공이며 CI27의 간헐 실패 해결이나 아직 source에 없는 D046의 검증이 아니다. 개발 fixture의 ABI/startup 성공과 실제 게임·SourceAdmission·target policy·whole JDK image·출시 인수를 구분한다. |
| 서른여덟 번째 Rust CI의 macOS stderr 전달량 전제 실패 | Windows·Linux job 성공, macOS·집계 실패; 실제 macOS archive 및 exact source 대조 | 같은 source의 [foundation run](https://github.com/daejunnom/MMMM/actions/runs/38615047112). macOS archive 32,954 bytes·SHA `c56df3d2caf538de1a3c12f3970f44affdd7b98d7b11a27b2706f2e4a0e5acb0`의 source·expected·PR head가 일치했다. 컴파일 오류 없이 실패 전 6개 libtest binary 합계 525개·Coordinator 326개가 통과했고 D045 새 순수 검사와 이전 startup 거절 검사도 ok다. 이후 별도 native_stdio의 blocked raw stderr 검사에서 1 MiB/200 ms의 deadline·실제 drain·EOF를 확인한 뒤 전달량이 양의 부분 길이라는 복합 assertion이 실패했다. 실제 길이는 기록이 없어 0과 전량을 구분할 수 없으며 command 101은 test panic으로 이전 worker exit 101과 다르다. 마지막 native record는 child admitted true·parent confirmed-zombie 1·pending 0·resource failure 없음이며 D045 신호 생략 분기 자체와 group empty는 미관측이다. D043 pending·memory exit도 null이며 해당 도구 검사는 Cargo 중단 뒤 실행되지 않았다. Outer test 101·252,788 ms·자연 drain·출력·export·scratch 정리·lease 해제·오류 0을 확인했다. 원 조건·200 ms·읽기/정리 순서를 유지하고 실패 메시지에 실제 delivered/requested bytes·오류 code를 추가했다. 이 진단 소스의 Windows native_stdio는 command 0·39,290 ms·명시 owned-tail 정리·drain·출력·export·정리·lease 해제·오류 0이며 실제 Mac 길이 관측은 후속이다. Ready의 전체 외부 write/flush ACK 보장과 deadline에서 양의 부분 효과가 보장된다는 fixture 전제를 구분하며 조건이나 기한을 조용히 완화하지 않았다. |

### 후속 CI와 native stderr 준비 조건

source `a7e647b4510bee4da7d131abff1f637bf01a277a`의
[서른한 번째 JVM CI](https://github.com/daejunnom/MMMM/actions/runs/38619727400)는
세 OS와 집계가 성공했다. 실제 archive는 Windows 350,986 bytes·SHA
`043931ef659929554cd1d19eed35eee7b9c778fbeb605b1232c3836ce8ce2deb`,
Linux 1,862,876 bytes·SHA
`4ea17cb02df6bc8f43a420b81669b4888798558d8d6f23b861ede6db1b8e4c89`,
macOS 536,708 bytes·SHA
`28a9500e81f2747e6078a0dcd629ad99d05063d4812f8dd6fc909a2337aa3fd4`다.
각 context의 source·expected·PR head와 7모듈 326개 검사·필수 11 executed tasks,
observer 3단계의 영수증 9개와 prior JVM 5개 digest 연결을 대조했다.
Header pin 8개, startup acquired/pre/post 12개와 13 phases가 완료됐다.
Windows의 native/header는 명시 owned-tail 정리를 거쳤고 나머지 Windows 단계와
Linux·macOS 네 단계는 자연 완료다. 모두 command 0·drain·출력·export·scratch
정리·lease 해제·supervisor/cleanup 오류 0이다. Windows discovery의 실제 전체
571 ms·prespawn 176 ms와 6개 완료 단계도 원 5초 안이다.

같은 Linux archive의 header-managed 실행에서 D046의 실제 조건부 Pending을
한 번 관측했다. 원 RSS Open/ESRCH 3, 양쪽 reserved leader Zombie·threads 2,
고정 PID/start/group/session 일치와 BoundValidated pidfd의 실제
TerminalPoll/NotReady·errno 없음이 first/last/count에 보존됐다. 완전 표본 16개와
불완전 표본 1개는 별도이고 max observed sample gap은 223 ms다.
`pending_leader_complete_gap_limit_ms=1000`은 정책값이며 해당 Pending의 실제
경과 시간이 아니다. 개별 시작·회복 시각은 기록하지 않았다. 현재 소스의 정상
완료 guard와 성공 영수증에 따르면 이후 완전 표본으로 해소된 실행으로 해석할 수
있으나 간헐 실패 전체의 해결로 확대하지 않는다. macOS의 D043 Pending과 native
memory exit 필드는 모두 null이다. 개발 fixture의 ABI/startup 관측은 계속 실제
게임·SourceAdmission·target policy·whole JDK image·출시 인수와 구분한다.

같은 source의 [마흔 번째 Rust CI](https://github.com/daejunnom/MMMM/actions/runs/38619727495)는
Windows·Linux job 성공, macOS·집계 실패다. macOS archive 32,878 bytes·SHA
`c3e26db3b6817ce6fbc00c69a88098ac65f3a16b4c5973007d249eb4726428a8`의 실제
context와 실패 전 6개 libtest binary 합계 525개·Coordinator 326개 통과를 대조했다.
그 뒤 custom native stdio의 새 진단은 요청 1,048,576 bytes·전달 0 bytes·deadline
200 ms·drain 완료를 기록했다. Parent가 64 KiB씩 보내고 worker가 전체 payload를
받은 뒤 외부 쓰기를 시작하므로, 양의 부분전달이 200 ms 안에 발생한다는 전제가
성립하지 않을 수 있다. 정확한 worker 내부 진행 위치는 미관측이다. Outer test
101·238,564 ms·자연 drain·출력·export·scratch 정리·lease 해제·오류 0을
제품 ACK 실패나 이전 worker exit 101과 구분하며 원 실패를 보존한다.

후속 fixture는 같은 1 MiB 요청의 준비를 원 15초 owner 안의 최대 2초로 한정하고,
Unix FIONREAD/Windows PeekNamedPipe로 파이프를 소비하지 않고 양의 실제 진행을
확인한 시각부터 기존 deadline을 최대 200 ms로 단축한다. 관측 후 같은 시각으로
기한과 elapsed를 계산하며 원 기한이 지난 관측은 준비 성공으로 채택하지 않는다.
준비 미관측·query 오류·예상 밖 Ready도 명시 drain·EOF 확인 뒤 실패한다.
종료 후 양의 부분전달·원 byte pattern과 deadline 오류를 요구하며 생산의 전체
external write/flush ACK 조건은 그대로다. 실제 kernel thread 상태나 파이프의
정확한 용량을 관측했다고 주장하지 않는다.

첫 Windows 검사는 live available 8,192 bytes가 종료 뒤 retained 4,096 bytes
이하이어야 한다는 새 가정에서 실패했다. 두 관측 사이 수량 순서 보장이 없음을
확인해 그 순서 조건만 제거하고 양쪽의 실제 양수·최종 부분전달은 유지했다.
독립 리뷰의 늦은 준비 관측 경계도 수정했으며 추가 확정 finding은 없었다.
최종 Windows native stdio는 같은 관측 8,192/4,096 bytes·진행 시각 94 ms와
deadline·drain을 확인해 command 0·12,116 ms·명시 owned-tail 정리·완전한 출력·
export·scratch 정리·lease 해제·오류 0으로 완료했다. 해당 integration target의
strict Clippy도 command 0·20,820 ms·자연 종료·동일 정리 조건으로 완료했다.
해당 fixture의 실제 Linux/macOS 실행 결과는 아래 후속 CI에서 확인했다.

### 새 진행 관측과 source 요청 수명의 후속 검증

source `c86332b6acb1bc77b0af83e47c646c8b4da91cd3`의
[마흔한 번째 Rust CI](https://github.com/daejunnom/MMMM/actions/runs/38622880877)는
Windows·Linux job 성공, macOS·집계 실패다. 실제 세 archive의 source·expected·PR
head를 대조했다. Windows 49,701 bytes·SHA
`f1cf8dc73c1bf2cf099f78224e1510ce370290b270b4742de034de33c6151845`,
Linux 50,332 bytes·SHA
`444ad73529151747d841475e7f4627fe187cbd7d469967331595c5f61cff70ed`,
macOS 53,109 bytes·SHA
`54576e3e170fe82337a807a1f7169038e55ed9146e4de7fdd291ea24ca4996fa`다.
Windows의 표준 unit/bin 검사는 1,128개 통과·2개 ignored와 doc 1개 통과,
Linux는 1,140개 통과·4개 ignored와 doc 1개 통과다. 별도 native stdio 실행도
두 OS에서 통과했다. Linux는 같은 요청의 진행 65,536 bytes·90 ms와 종료 뒤
retained 65,536 bytes, macOS는 65,536 bytes·450 ms와 retained 65,536 bytes를
기록했다. 진행 시각은 최대 2초 준비 구간의 관측 시각이며 관측 이후의 200 ms
구간 길이가 아니다. 실제 deadline·drain을 확인했으며 전달량 사이 순서나 kernel
thread 상태를 추정하지 않는다.

macOS의 전체 test command는 0·261,443 ms·자연 종료다. 이 실행 중 D043의 실제
ObservedMember TaskInfo result 0·ESRCH 3과 양쪽 INEXIT·동일 anchor 조건을 한 번
관측하고 이후 회복했다. 이후 strict Clippy command는 49,596 ms에
`observation_failure`·signal 9·exit unknown으로 실패했다. 원인은 별도 member의
실제 Rusage Exited·result 0·errno 0이며 양쪽 non-SZOMB·INEXIT·동일 anchor가
기록됐다. D043의 TaskInfo 조건과 달라 기존 strict 판정이 거절한 결과다. 해당
실행의 RSS·footprint·VM·worker peak는 기존 상한보다 작으며 compiler/lint 오류나
timeout으로 바꾸어 보고하지 않는다. 세 OS의 관측한 managed 실행은 drain·완전한
출력·export·scratch 정리·lease 해제·supervisor/cleanup 오류 0을 보존했다.

같은 source의 [서른두 번째 JVM CI](https://github.com/daejunnom/MMMM/actions/runs/38622881050)는
Windows·macOS job 성공, Linux·집계 실패다. 실제로 내려받아 대조한 Linux archive는
1,856,037 bytes·SHA
`168484a07ab6db67f2693b5d16cc4dfeccc94ed96aa3fc404752776cda83cc43`다.
JVM 7모듈 326개·필수 11 executed tasks·실패/오류/skip 0이며 managed JVM은
0·91,912 ms·자연 종료다. Header 내부 ABI witness는 성공했으나 그 외부 감독은
5,192 ms에 `observation_failure`·signal 9·exit unknown으로 실패했다. 원 RSS
Open/ESRCH 3의 역할은 OwnedMember이며 양쪽 Zombie·threads 2·동일 원 identity와
실제 BoundValidated pidfd TerminalPoll/NotReady를 기록했다. D046의 reserved
leader 조건과 달라 기존 strict 판정이 거절했다. 마지막 Complete부터 실패까지의
실제 경과는 기록하지 않아 새 1초 정책의 과거 실행 허용 여부를 추정하지 않는다.
native/header의 실제 finalization 6개와 prior JVM 5개 digest 연결이 일치하며
정의 startup은 미실행이다. 내부 witness 성공을 외부 감독·observer 전체 성공으로
올리지 않는다. Windows·macOS는 job 결과만 확인했으며 이 run의 원본 archive는
아직 대조하지 않았다.

제품의 네 source 관측 분기는 원래 InspectionControl과 같은 session·context·server
epoch·registry generation 및 response 수명을 내부 collector까지 전달한다. 기존
5초 관측 상한 안에서 metadata port·파일 metadata·64 KiB 읽기·마지막 재검사와
직렬화의 전후 checkpoint를 확인하며, 원 취소·기한 및 typed RuntimeException을
unknown fallback으로 삼키지 않는다. 기존 비검사 호출은 같은 관측 상한을 유지한다.
동기 syscall 선점이나 새 SourceAdmission·pack 완전성을 보장하지 않는다.
기존 class port 검사가 source metadata fallback에 도달하지 못하므로 기존 검사
파일에 실제 installation port의 전후 종료와 활성 unknown 기준을 확인하는 검사
하나를 추가했다. 독립 소스 리뷰 뒤 Windows의 실제 전체 JVM 검사는 7모듈
327개·실패/오류/skip 0, 29 actionable tasks 모두 executed로 완료했다. command
0·29,169 ms·자연 종료·drain·완전한 출력·export·scratch 정리·lease 해제·오류 0이며
실제 게임 관측이나 다른 OS의 이 새 소스 실행은 별도 검증이다.

### 구성원 Pending의 부분 자원 보존

D047은 CI32에서 실제로 관측한 owned member의 좁은 RSS 전이를 기존 D046과
같은 조건부 Pending에 연결한다. scan 시작과 끝의 원 leader anchor·미회수 Child
예약, member의 원 identity·동일 PGID/SID 및 실제 validated whole-group pidfd
관측이 모두 필요하다. leader/member의 원 typed 오류와 역할별 first·last·count를
성공·실패 양쪽에서 한 번 merge하고, 역할이 달라져도 마지막 실제 Complete부터의
1초와 100 ms attempt clock을 재시작하지 않는다. 불완전 RSS를 0으로 채우지 않고
다른 구성원의 실제 RSS·VM·live lower bound로 같은 상한을 확인한다.

D048은 CI41의 실제 Rusage 종료 전이에 한정한다. 같은 호출에서 성공한 TaskInfo의
sealed VM/RSS와 실제 성공한 rusage의 start/exit timestamp 존재를 별도 partial
사실로 보존하고, 기존 strict API는 같은 native 호출 뒤 원 네 오류 필드를 돌려준다.
후속 member 판정에는 typed Rusage Exited·result 0·errno 0·양쪽 non-SZOMB·INEXIT와
원 다섯 identity 일치가 모두 필요하다. footprint와 timestamp identity를 만들어내지
않고 실제 partial VM/RSS를 scan에 한 번 반영한다.

독립 추가 리뷰에서 memory 없는 Pending 구성원이 worker 수에서 빠져 measured
32개와 Pending 1개를 거절하지 못하는 문제를 발견했다. Pending worker를 관측
횟수와 분리해 최대 33개의 scan별 private identity 집합으로 중복 제거하고 checked
합산하여 기존 32 상한을 적용했다. 같은 worker의 RSS는 최대값 증가분만 더한다.
또한 full Measured memory 뒤 AfterMemory session만 Pending인 leader가 이미 얻은
VM/RSS/footprint를 잃는 기존 경로도 수정했다. 먼저 진단을 기록한 뒤 worker 증가
없는 같은 합산 helper를 호출하고, worker는 Pending 집합에서 한 번만 센다.
private identity는 직렬화·출력에서 제외한다. native PID 목록의 유일성에 대한 기존
measured 경로의 전제와 일반적인 containment 보장을 구분한다.

재리뷰에서 두 누락의 해결과 추가 확정 finding 없음, Windows의 실제 Native process
5개·도구 lib 211개·bin 1개 PASS와 isolated 1개 ignored를 확인했다. 기존 순수
검사들을 여러 역할·hard error·clock·상한·overflow·중복·scan 간 누적 부재로 확장하고,
sealed partial 오류의 strict 호환 검사 1개와 Rusage/partial/worker 검사 3개를 추가했다.
test command 0·18,113 ms·명시 owned-tail 정리, 두 package all-targets strict Clippy
0·2,587 ms·자연 종료다. formatting·drain·출력·export·scratch 정리·lease 해제와
supervisor/cleanup 오류 0이다. Pending은 complete 수·peak·마지막 성공 시각·empty·
terminal·normal reap·drain을 발급하지 않으며 원 native 호출·poll·cadence·기한·상한과
실패 후 물리 drain을 유지한다. Linux/Darwin 전용 native 분기의 새 실행 성공은
Windows 순수 검사로 대신하지 않으며 후속 CI에서 별도로 검증한다.

### 같은 공유 SHA의 3개 OS 기반 검증

source `0def2d60beb73e92fd6a6c2de78d76d035a3669b`의
[Rust CI44](https://github.com/daejunnom/MMMM/actions/runs/38629700909)와
[JVM CI35](https://github.com/daejunnom/MMMM/actions/runs/38629700919)는 세 OS job과
각 집계가 모두 성공했다. 실제 여섯 원본 archive의 bytes·digest와 source·expected·
PR head를 대조했으며 별도 event merge SHA와 구분했다.

Rust archive는 Windows 50,186 bytes·SHA
`8c03853a30be666690f33f0a71ea34273e842ff923862410993a7dfd50e476a0`,
Linux 50,448 bytes·SHA
`e2550297a28b08edb64603d7377624595119ff89874e4b2302a61e76905f05bd`,
macOS 52,654 bytes·SHA
`150e13bff09ccf5d289eaa4d7cf22682d78ca605b9910b6590120575767b325f`다.
표준 unit/bin 16개와 doc 14개, 별도 harness-free native stdio를 구분했다.

| OS | unit/bin PASS | doc PASS | ignored | native stdio |
|---|---:|---:|---:|---|
| Windows | 1,132 | 1 | 2 | PASS, 진행 8,192 bytes·92 ms·retained 4,096 bytes |
| Linux | 1,144 | 1 | 4 | PASS, 진행 65,536 bytes·88 ms·retained 65,536 bytes |
| macOS | 1,141 | 1 | 1 | PASS, 진행 65,536 bytes·491 ms·retained 65,536 bytes |

세 stdio 실행은 같은 1 MiB 요청·진행 후 최대 200 ms·deadline 오류·drain을 확인했다.
Reference 55개와 native process 5개, 도구의 해당 OS 순수 검사가 통과했다. 세 OS의
format·저장소 458개/위반 0·strict Clippy도 성공이다. macOS test는 308,577 ms,
strict는 67,798 ms·자연 종료다. D043 member TaskInfo Exited/result 0/ESRCH 3·양쪽
INEXIT/status 2·동일 anchor를 한 번 보존했고 test command 0·drain까지 완료했다.
TaskInfo partial과 rusage timestamps는 null이므로 D048의 새 Rusage 분기는 미관측이다.
특정 Pending 뒤 complete의 개별 시각도 기록하지 않았다. native 호출·worker 상한을
유지한 순수 검사 성공과 실제 상한 발동을 구분한다. Windows test에는 D033의 실제
PermissionDenied/raw 5 → 2 attempts·19 ms → missing_validated 1회가 companion의
원 오류·digest와 함께 보존됐고, 이번 실행은 정상 종료했다.

JVM archive는 Windows 350,977 bytes·SHA
`05a21d97bd594f925d0fc3cc2f2853e3ee2185c834658417d490f8b5dbae26b0`,
Linux 1,862,927 bytes·SHA
`00302f1cee57efe7e3d1610c3351589328508048a67eb96aa64aa2ddb176a261`,
macOS 536,728 bytes·SHA
`d7fc78ca70b2da4ed9b302aed859f00488a60e662d41fb1f48bd3fec73f0ebf2`다.
각 OS의 7모듈 327개·실패/오류/skip 0·필수 11 executed tasks, observer 영수증 9개와
prior JVM 5개 digest 연결을 확인했다. manifest 53개 입력과 ABI source 및 native
library·JAR·JDK pin 간 연결이 일치했고, Windows·Linux의 53개 선택 source는 고정
Git blob 1,427,518 bytes 전체와도 일치했다. Header 8 pins와 startup acquire/pre/post
각 12 pins·13 phases가 완료됐다. Windows discovery의 6단계는 prespawn 173 ms·
전체 546 ms로 원 5초 안이며 해당 실행의 강제 종료 분기는 미발동이다.

Linux header에서는 D047의 실제 owned member RSS Open/ESRCH 3·양쪽 Zombie·
threads 2·원 네 identity 일치·실제 BoundValidated pidfd TerminalPoll/NotReady를
한 번 보존했다. incomplete 1개·complete 15개·max complete gap 231 ms이며 wrapper
0·1,842 ms·자연 종료다. 정상 완료 guard와 성공 기록에 따른 회복 해석을 개별 Pending의
미기록 age나 전체 간헐 실패 해결로 확대하지 않는다. macOS JVM35의 Pending 및
native memory exit는 네 단계 모두 null이다.

Rust와 JVM의 관측한 managed 실행은 모두 exit 0·drain·완전한 출력·export·scratch
정리·lease 해제·supervisor/cleanup 오류 0이다. Windows Rust test/strict와 JVM의
native/header는 명시 owned-tail 정리를 거쳤고 다른 해당 단계는 자연 완료다.
이 결과는 고정 source의 기반 및 development fixture 검증이다. SourceAdmission·
target policy·whole JDK image와 실제 게임·릴리스 인수는 계속 미검증이며, 이어 작성한
private pack collector의 새 source를 이 성공에 합산하지 않는다.

### Private pack 관측 source의 후속 3개 OS 검증

source `9d071f55c5d05c80865313ba60c01b7d78d6a961`의
[Rust CI45](https://github.com/daejunnom/MMMM/actions/runs/38633639969)와
[JVM CI36](https://github.com/daejunnom/MMMM/actions/runs/38633639659)는 세 OS job 및
각 집계가 모두 성공했다. source·expected·PR head는 이 SHA로 일치하며 event merge
SHA `c32ec1e1a71491a5afb027cd8c1797487d598d63`와 구분했다. 여섯 원본 ZIP을 별도
보존하고 실제 bytes·digest를 대조했다. 다음 수치는 이 source의 실행에 한정한다.

| OS | Rust ZIP bytes / SHA-256 | unit/bin PASS / ignored | doc PASS |
|---|---|---:|---:|
| Windows | 49,807 / `8c9737d0b5aa574ce99ea80fd78703ad823c42cd0a156e6da5d94efc05066920` | 1,132 / 2 | 1 |
| Linux | 50,401 / `0c2e3e744de325b5d56e4b97d5a9b21359d89c9591a5c5df71e727063f54b44b` | 1,144 / 4 | 1 |
| macOS | 52,357 / `8aa1a299833f2c4623efefe349fc8b16a0ef79f82e51820e8da41fbf60380b02` | 1,141 / 1 | 1 |

unit/bin 16개와 doc 14개의 failed는 모두 0이며 별도 harness-free native stdio도
통과했다. 세 OS의 format·strict Clippy와 저장소 검사 464 files / violations 0이
일치한다. Windows stderr의 실제 진행은 4,096 bytes / 88 ms, Linux는
65,536 bytes / 88 ms, macOS는 65,536 bytes / 294 ms다. 사후 witness의
`delivered_bytes`는 각각 4,096 / 65,536 / 65,536이며 별도 `retained_bytes` field는 없다.
같은 1 MiB 요청·진행 후 200 ms 상한·deadline 오류·drain을 각각 구분해 보존한다.

JVM ZIP은 Windows 351,347 bytes·SHA
`4917d25458ea1973311fc2cb650f267f6203dc37e8a2df53ce2fec4f01ef7a8a`、
Linux 1,862,926 bytes·SHA
`5088a624b2432b73a9a1215ae4f389c54be87788ff82b0f5c1d074d07dbae221`、
macOS 537,077 bytes·SHA
`47ed0dbd8bb556316d5119b79ae34419c9c57570342ae6a55cc55bae51b9351f`다.
각 OS의 7 modules / 333 tests / failure·error·skip 0, 필수 11 tasks executed를
확인했다. 내역은 108 / 89 / 17 / 68 / 22 / 18 / 11이며 fabric-host의 새 private pack
경계 검사 6개를 포함한다. observer 9 receipts와 prior JVM 5 receipts의 raw digest,
ABI 8 pins, startup의 13 phases·acquire/pre/post 각 12 pins가 일치한다.
observer manifest 53 source blobs는 세 OS 모두 고정 Git bytes 전체와 일치한다.
JVM source inventory 169개는 Linux/macOS에서 전체 raw Git blobs와도 대조했다.

이번 Linux JVM 세 단계는 incomplete sample 0·leader/member history null이며,
macOS의 Rust/JVM 각 네 단계도 Pending/native-memory-exit history가 null이었다.
CI44/JVM35의 실제 종료 경합을 이번 관측에 이월하지 않고 D047/D048의 순수 검사와
실제 분기 발현을 구분한다. Linux의 일반 Rust AS policy에는 JVM용 history field
자체가 없으며 null인 JVM 기록과도 구분한다. macOS Rust test는 221,779 ms,
strict는 59,751 ms·최대 실제 gap은 294 ms이며 기존 자원 상한 안이었다.

관측한 관리 실행은 exit 0·drain·output·export·scratch 정리·lease 해제와
supervisor/cleanup 오류 0을 유지한다. Windows JVM native/header의 명시 owned-tail
종료는 자연 종료와 구분한다. raw XML 및 archive 밖 JDK/compiler/JAR payload 전체의
재 hash, 실제 Mixin graph 양성, SourceAdmission·target policy·whole JDK image·게임 및
공개 릴리스 인수는 이 성공에 포함하지 않는다.

### 실제 게임 입력의 archive 관측

로컬의 실제 Minecraft merged JAR 관측은 처음에
`INPUT_ARCHIVE_METADATA_LIMIT`으로 거절됐다. 입력은 39,515,741 bytes·34,225 entries,
중앙 directory 4,789,080 bytes였다. 긴 공통 경로의 모든 full prefix를 literal과
folded 문자열로 반복 소유하던 이름 자료구조를 parent node ID·folded component의
공유 구조로 바꿨다. Literal component는 이미 charge한 immutable 중앙 bytes를
빌리고 실제 key/value 크기·소유 folded bytes·노드당 보수적 overhead와 초기 slab을
checked 합산한다. 이는 metadata admission 계산이며 실제 allocator 사용량이나
RSS 측정을 대신하지 않는다. 기존 16 MiB 상한·공개 API·alias/secret 검사·전체 이름
및 물리 header preflight를 유지했다. 기존 작은 alias fixture는 긴 공통 prefix를
대표하지 못하므로 64개 실제 member의 공유 경로 검사 하나를 추가하여 caller의
64 KiB metadata budget 성공과 40 KiB 거절을 함께 확인했다.

독립 소스 리뷰 뒤 Reference 55개 검사가 command 0·12,959 ms·명시 owned-tail
정리로 통과했고, all-targets strict Clippy는 0·1,722 ms·자연 종료다. 새 library를
실제로 빌드한 뒤 외부 probe의 새 실행 파일에 연결하여 같은 게임 입력을 재검증했다.
입력 SHA `9c5cc8208b06eda6f8f625524af77526dad347c0ce00aa416fc80ba73fb977be`,
member 34,225개·directory 1,349개·decoded 76,423,852 bytes·complete true이며
producer 내부 2,543 ms와 전체 command 4,103 ms를 구분한다. 같은 관측 classpath의
Fabric resource-loader v1 JAR도 입력 135,272 bytes·SHA
`2d2fb907728c895640c1261ff3dd115b5087913d88d1ba1d9f3a8a4cfd1ca87e`,
member 135개·directory 20개·decoded 265,624 bytes·complete true를 기록했다.
내부 10 ms·전체 command 166 ms다. 모두 기본 producer 한도와 probe의 원래 10초
기한 안이며 성능 인수나 다른 입력의 전체 호환성으로 확대하지 않는다.

이 두 입력은 실제 Gradle project task 안에서 얻은 classpath의 경로·종류·길이
hint에서 선택했다. 앞선 Windows fileKey 부재와 projectsEvaluated에서의 exclusive
lock 오류는 원 실패로 보존했다. 성공한 metadata task의 124개 경로 hint는 내용
hash·불변 file identity·사용 허가를 발급하지 않는다. 선택한 두 JAR만 별도로 실제
전체 inventory를 검사하고, Windows 읽기 handle의 write/delete 공유를 닫은 동안
producer digest와 held handle digest를 대조했다. 같은 두 handle을 유지한 실제
`javap` 관측에서는 정해진 4개 API 선언과 추가 7개 pack 구현의 선언·bytecode를
읽었고 실행 전후 container digest가 일치했다. 두 command는 0·1,121/1,882 ms·자연
종료다. class filename·선언 관측과 실제 loaded Class·활성 pack/root mapping·
effective pack fingerprint·SourceAdmission을 구분하며 게임 코드를 실행한 관측으로
기록하지 않는다. 모든 관련 실행의 drain·출력·export·scratch 정리·lease 해제와
supervisor/cleanup 오류 0을 확인했다. 원본 JAR·probe·raw logs는 Git에 넣지 않았으며
실패한 이전 binary와 원 증거도 별도 보존했다.

### Private pack root와 active overlay 관측

D049의 Java collector는 실제 FixedPathPackResources·ModNioPackResources·
OverlayedPackResources와 설치된 정확한 read accessor만 읽는다. actual manager·pack
객체 순서·root/type/primary/stack을 전후 대조하고, actual stack을 정렬하거나 overlay를
새로 생성하지 않는다. metadata root와 type별 resource root의 의미를 구분하며
같은 관측의 기존 ordinary archive receipt에만 literal ZipFS member prefix를 연결한다.
새 파일 open/hash·realpath·디렉터리 순회·resource/metadata supplier 실행은 없다.
최소 unknown envelope 공간을 먼저 확보하고 기존 256-entry·256 KiB·5초와 원 control을
공유한다. 한 graph가 상한·cycle·미지원 경계에 닿으면 빈 nodes·null root의 정확한
unknown이 되며 부분 graph를 observed로 게시하지 않는다.

Rust의 private validator는 닫힌 필드와 reason, root 0·ordinal·참조·acyclic/reachable
DAG·scope·prefix의 UTF-8 1,024 bytes/NFC·경로 및 secret/device 규칙과 같은 archives
참조만 검사한다. 전체 node/root/edge work는 256 이하이면서 실제 entryCount 이하여야
한다. legacy의 private field 부재는 unknown으로 허용하고 present null은 거절한다.
공통 pin은 계속 observedAt만 제외하므로 새 graph·prefix·reason·실제 순서가 현재성에
포함된다. 검증 결과는 권한 없는 `()`이며 server/client pack identity는 계속 None이다.
기존 workspace Unicode dependency edge 한 개를 재사용했고 Cargo.lock은 같은 edge만
추가됐으며 package·version·feature·network 입력은 늘지 않았다.

Java/Rust 독립 리뷰의 확정 finding은 없었다. 기존 source 정의 port로는 exact pack
type/accessor 거절을 검증할 수 없어 한 JUnit 파일에 6개 경계 검사를 추가했다.
Windows의 전체 JVM 검사는 333개·실패/오류/skip 0·29 actionable tasks 모두 executed,
command 0·35,576 ms·자연 종료다. Rust는 기존 source identity와 pin 검사 두 개를
확장하여 세 node 종류·reason·wrong source·prefix/NFC·DAG/순환/분리·256/257 및
팩 간 합계 경계를 확인했고, Coordinator lib 325 PASS·1 ignored다. command
0·59,714 ms·명시 owned-tail 정리 및 locked all-targets strict Clippy
0·7,570 ms·자연 종료를 확인했다. metadata의 완료 전에 요청한 formatting 한 번은
catalog busy로 pre-admission 거절돼 자식이 실행되지 않았고, 원 실행의 정상 종료·
lease 반환 뒤 직렬 formatting을 완료했다. 실제 실행의 drain·출력·export·scratch
정리·lease 해제와 오류 0을 보존했다.

실제 Mixin이 설치된 graph 양성·mutable graph drift·게임 manager 양성은 미검증이다.
filter·client active stack·pack completeness·loaded definition·SourceAdmission 및
사용 권한은 unknown/미발급을 유지한다. headless 게임 시작만으로 실제 접속 관리자와
완료 pairing을 요구하는 runtime_sources 양성을 증명하지 않는다. 실제 게임 준비는
build scratch와 별개로 world/EULA/config를 보존할 root 및 실제 runtime launcher
관측이 필요하며, 현재 Gradle dev run 경로를 출시용 launcher로 보고하지 않는다.

### Retained root와 고정 stop 입력의 Windows 검증

D050의 `RetainedGame`과 opt-in `MinecraftStopHandle`을 구현했다. 처음 작성한 Windows
검사는 compile 성공 뒤 225 PASS·1 FAIL·1 ignored였으며, failure는 열린 directory
handle 상태의 rename을 Windows가 PermissionDenied/raw 5로 거절한 fixture 전제였다.
이 실행은 command 101·24,925 ms·명시 owned-tail 종료로 보존했다. Windows의 정확한
native 거절에서 원 root·owner/lease bytes·world 보존을 확인하도록 검사하고, rename이
성공한 환경에서는 기존 교체 identity 거절 검사를 유지했다. 오류를 일반 성공이나 WSL
전환 근거로 재분류하지 않았다.

독립 리뷰에서 bare secret selector의 두 번째 guard가 metadata 뒤에 있던 P2도 발견해
두 lexical guard를 parent/leaf metadata 앞에 배치했다. 존재하지 않는 parent 아래의
세 selector를 이용해 I/O보다 secret 오류가 먼저 반환되는지 검사하며 실제 secret
파일을 생성하거나 열지 않는다. 재리뷰 뒤 Windows 도구 lib 227 PASS·1 ignored,
command 0·23,174 ms·명시 owned-tail 종료와 lib strict Clippy 0·1,736 ms·자연 종료를
확인했다. 이 실행은 bin/전체 workspace 검사를 포함하지 않는다. formatting과 모든
관련 실행의 drain·output·export·scratch 정리·lease 해제, supervisor/cleanup 오류 0을
보존했다.

새 source의 controlled-input 검사 4개는 실제 고정 5 bytes+EOF·one-use control·기본
null/미요청 opt-in·peer read-end 종료의 native 오류 및 drain을 확인하고, 집중 port에서
partial/WouldBlock/뒤따른 오류와 별도 close 오류를 보존한다. retained 검사 12개는
Windows의 소유권·busy·보존·root 교체·combined budget·취소·secret 경계를 확인했다.
Unix 전용 검사와 nonblocking write·Darwin 실행은 미검증이다. lease 해제의 cooperative
verification→unlink 경계를 소스와 빌드 문서에 명시했으며 hostile 동일 UID의 원자
교체 방어를 발급하지 않는다. 실제 CLI 연결·게임 시작·Minecraft 처리/저장 acknowledgement
및 pairing 양성은 이 lib 검증과 별개다.

### Retained CLI의 실제 Windows 종료와 timeout

관리 `run`에 명시 retained root와 선택 stop schedule을 연결했다. 독립 검토에서 원
timeout·취소 checkpoint를 post-drain export에 재사용하던 오류와 최종 완료 측정의
예산 초과를 성공 gate가 놓치던 오류를 수정했다. drain 뒤의 단일 30초 보존 시계와
64 KiB 로그 복사 checkpoint는 원 실행 실패를 바꾸지 않는다. 최종 예산 초과는
`released_over_budget`·실제 lease 해제·`resource_budget` 오류를 함께 보존한다.
이 마지막 예산 초과의 소비 검사는 순수 projection이며 실제 대용량 game 결과가 아니다.

수정한 CLI 검사 4개와 locked all-targets strict Clippy를 Windows에서 실행해 모두
통과했다. 각각 command 0·8,578 ms·명시 owned-tail 종료와 0·6,662 ms·자연 종료다.
기존 supervisor의 고정 snapshot을 부모로 사용해 실행 중인 EXE를 덮어쓰지 않고 새
CLI를 빌드했다. 새 EXE는 3,063,808 bytes·SHA
`520257e12d8b44ab4f2e72d954c02ebe8d3806a8b3c3bb132680f5d48bfe1ade`이며,
formatted `main.rs`는 SHA
`9e61f7d96fe5421deb7eeccf8780b732b695814f90227de99c131d26f6a254fe`다.

첫 실제 CLI fixture는 일반 drive 경로와 Windows verbatim drive 경로를 문자열로
동일시하지 못해 child exit 1로 끝났다. native supervisor 오류는 없었고 stop은
미요청·0 bytes였다. 원 실패와 로그를 보존한 채 fixture의 정확한 drive-prefix 표현만
정규화했다. 제품의 경로·소유권 검사를 완화하거나 WSL로 전환하지 않았다.

수정한 fixture는 command 0·14,616 ms·자연 종료로, 실제 cwd와 retained game 환경의
일치, 고정 stop LF 5 bytes와 EOF, 표식 생성 및 stderr 0을 확인했다. stop 요청은
입장 전 요청 시계의 15,969 ms에서 관측됐으며 정확한 10초 전송을 주장하지 않는다.
같은 complete root 재사용은 command 0·574 ms로 표식 보존과 기본 null stdin의 EOF를
확인했다. 별도 15초 timeout 실행은 실제 command 124·13,714 ms·timeout과 원
`command timeout exceeded`를 유지했다. 이 시간은 입장 전부터 시작한 원 기한과
별도인 native elapsed다. drain 뒤 8,327 ms의 보존 관측 안에서 raw export와 완료를
기록했으며 owner complete·root lease 부재·17-byte 표식 보존을 확인했다.

관련 실제 실행은 native drain·완전한 출력·export·scratch 정리와 build lease 해제를
확인했고 cleanup 오류 0이다. timeout은 예상한 실패 결과이며 전체 CLI exit도 1이다.
게임·EULA 수락·Minecraft 명령 처리/저장 acknowledgement는 실행하거나 발급하지 않았다.
CLI 취소, Unix CLI와 실제 게임 검증은 별도 미검증이다.

### 현재 source의 CI와 macOS bootstrap 실패 보존

source `74c26bcf59b92125fb10d98958710f2556a175b2`의
[Rust CI 46](https://github.com/daejunnom/MMMM/actions/runs/38638920726)은 Linux와
Windows job 성공, macOS bootstrap 및 집계 실패다. 실패 archive는 3,174 bytes·SHA
`59f051624f3a210baf4f6e3002dd2ab1a9353aba7f87e03185ea40f065e596a7`이며 7개
entry를 실제 대조했다. source·예상 source·PR head는 위 SHA로 같고 event SHA
`aea1023a37dce7d1381f3c26a86b7cf187c5f476`는 별도다. 원 오류는 Darwin native
zombie identity로 process exit를 확인하지 못했다는 supervisor failure다.
command exit null·drain/export true를 함께 보존하며 정상 Cargo 종료나 Rust 검사
실패로 재분류하지 않는다. finish는 없고 slot·lease는 보존됐다.

실제 자원 표본 44개·최대 gap 182 ms, RSS 456,704,000 bytes·footprint 215,100,992
bytes·worker 9개는 기존 상한 안이다. 원 native stage/result/errno·BSD status·role와
항목별 identity 비교값이 기록되지 않아 PID 재사용이나 특정 종료 전이를 확정할 수
없다. strict 종료 판정과 상한을 유지하고 진단 보강을 진행한다. 같은 source의
[JVM CI 37](https://github.com/daejunnom/MMMM/actions/runs/38638920986)은 세 OS와
집계 성공 metadata를 확인했으나 이 기록에서는 새 JVM archive를 대조하지 않았다.
위 로컬 CLI 연결 변경은 이 CI source에 포함되지 않는다.

Darwin bootstrap의 진단 유실은 D051로 보강했다. 이미 실행한 원 native stage/result와
즉시 errno, BSD status·INEXIT·identity 및 기존 anchor 검사의 실제 도달 여부만
optional first/last/포화 count에 보존한다. 원 strict 실패·정상 반환·native 조회와
신호·기한·자원 상한은 유지한다. 독립 diff 검토에서 추가 finding 0을 확인했고,
Windows Python 3.10의 isolated/no-bytecode 실행으로 실제 생산 정의를 AST 선별한
22개 순수 사례가 command 0·219 ms·자연 종료했다. native libproc·fork·실제 OS 관측은
차단한 mock이며 실제 macOS 실행 성공이나 CI46 실패 원인의 소급 확정은 아니다.
drain·출력·export·scratch 정리·lease 해제와 supervisor/cleanup 오류 0을 확인했다.

현재 공개 source `090845b1bf9a88acda6833930bbd7fe45f3e0dd2`의
[Rust CI 47](https://github.com/daejunnom/MMMM/actions/runs/38641694293)은 macOS job
성공, Linux test 관리 실행 실패를 관측했다. Linux 실제 archive 16,440 bytes·SHA
`76c05d02a4a1efabd179e7dd5b7b8073e9c9c459133f631d32b96c226f78591b`는 컴파일 중
69,058 ms에 enumerated candidate의 stat open/ESRCH 3으로 supervisor failure가 났다.
stdout 0·Compiling 147건·Finished/test result 0건이므로 실제 테스트 실패를 관측한
것이 아니다. command exit null·signal 9와 원 오류, 정상 cleanup·scratch 및 lease
해제를 함께 보존했다. 해당 순간 candidate의 identity·group·pidfd는 미관측이며
불일치나 owned member로 추정하지 않는다. 같은 source의
[JVM CI 38](https://github.com/daejunnom/MMMM/actions/runs/38641694259)은 세 OS와 집계
성공 metadata다. Windows Rust job과 새 성공 archive 전체의 인수는 이 기록에서
아직 확정하지 않았다. D051은 이 CI source에 포함되지 않는다.

이 Linux 오류에는 D052의 좁은 분류를 추가했다. 원 PID directory FD를 확보한 뒤
EnumeratedCandidate의 최초 Stat/Open에서 실제 raw ESRCH 3일 때만 후보를 건너뛴다.
[공식 procfs 문서](https://docs.kernel.org/filesystems/proc.html#process-specific-subdirectories)는
종료한 proc FD가 재사용된 숫자 PID의 새 process에 작용하지 않으며 ESRCH가 가능함을
설명한다. [Linux v6.11 구현](https://raw.githubusercontent.com/torvalds/linux/v6.11/fs/proc/base.c)의
PID directory permission도 task가 없으면 ESRCH다. 이는 허용한 경로의 근거이며 실제
runner의 정확한 kernel branch나 후보 소유권을 복원한 관측은 아니다.

그 None 자체는 identity·owned exit·RSS 0·empty·signal 권한을 만들지 않는다. 남은
scan과 원 leader 재검증 뒤의 기존 Complete/Pending 및 drain을 유지한다. ENOENT,
다른 errno와 raw errno 부재, leader/member·RSS·다른 operation은 원 typed 오류다.
새 query·retry·sleep·기한·cadence·상한 변경 없이 독립 검토 finding 0을 확인했다.
기존 두 순수 검사의 27개 role/file/operation 조합과 다른 errno 경계를 확장했으며
새 fixture는 만들지 않았다. Windows 도구 lib 227 PASS·1 ignored·command 0/16,031 ms·
명시 owned-tail 종료와 all-targets strict Clippy 0/2,793 ms·자연 종료를 확인했다.
관련 drain·output·export·scratch 정리·lease 해제와 오류 0을 보존했다. 실제 Linux
native 재검증 및 이 좁은 전이의 새 실행 관측은 별도다.

### 게임 실행 전의 launcher 및 보존 경로 준비

Windows의 별도 help action에서 실제 `:fabric-host:runServer` task의 metadata만
조회했다. 앞선 helper의 missing working-directory 후검사 누락은 실행 전 독립
리뷰에서 발견했다. 원본은 미실행으로 보존하고 새 v2에서 missing chain 전체와
nearest-existing physical parent의 metadata를 전후 대조한 뒤 재리뷰했다.
v2 source는 15,321 bytes·SHA
`3a0cd649a931f096b1fbee0f815f9e5f31b6c149e2c081e0aa832806135d3749`다.
실제 help만 1 task executed·command 0·11,846 ms·자연 종료이며 task/dependency/game
action이나 EULA 처리는 실행하지 않았다. 출력은 51,669 bytes·SHA
`8fe2f805f467c153f1b243c3f47ca38cc905555f075c7bec81b6c16641f45c4e`다.

실제 task type은 `net.fabricmc.loom.task.RunGameTask_Decorated`이면서 JavaExec이고,
main은 `net.fabricmc.devlaunchinjector.Main`이다. classpath는 directory 2개·ordinary
file 128개이며 직접 dependency task 5개의 경로를 관측했다. 이 시점의 JavaExec
working directory는 checkout의 `jvm/fabric-host`였다. 추적 runDir 선언과 최종 실행
시 적용되는 경계를 아직 같은 것으로 볼 수 없으므로 이 hint를 최종 game cwd·EULA
위치 또는 완성된 direct Java launch spec으로 사용하지 않는다. metadata 전후 동일은
불변 file identity·내용 검증·SourceAdmission·사용 권한을 발급하지 않는다.

같은 Windows 빌드에서 실제 task 목록을 확인한 뒤 `:fabric-host:jar`를 실행했다.
command 0·9,319 ms·자연 종료, 10 actionable tasks 중 2 executed·8 up-to-date다.
생성된 호스트 JAR은 3,509,931 bytes·SHA
`ef3949b84b24fa686a65eeb8c5698aac8005bbaffdedb13a45399c28acb224b7`이며 별도 실제
archive producer가 complete true·members 108·directories 7·decoded 4,185,463 bytes를
확인했다. producer 내부 71 ms·전체 command 165 ms를 구분한다. 부모의 Windows
read handle에서 write/delete 공유를 닫은 동안 producer digest와 전후 held digest가
일치했다. 선택한 세 metadata member만 8 KiB씩 제한해 읽었으며 manifest의 mapping
namespace `official`·게임 26.3·Loom 1.17.21·Gradle 9.6.0·loader 0.19.5를 관측했다.
내장 Mixin JSON digest는 현재 source와 같고 required/defaultRequire 1을 유지한다.
이는 JAR 생성과 정적 입력 검증이며 실제 loader 설치·Mixin 양성·pairing·SourceAdmission
또는 세 OS에서 배포할 동일 파일의 인수를 의미하지 않는다.

관련 실행의 drain·출력·export·scratch 정리·lease 해제와 supervisor/cleanup 오류 0을
확인했다. 이 준비 시점에는 실제 게임을 실행하지 않았으며 world/config 보존,
실제 관리자 연결과 최종 배포 인수는 후속 단계로 남겼다.

[공식 Fabric server launcher 페이지](https://fabricmc.net/use/?page=server)가 제시한
26.3 / loader 0.19.5 / launcher 1.1.2의 고정 HTTPS 입력을 별도 관리 실행에서
다운로드만 했다. 실제 입력은 181,838 bytes·관측 SHA
`0b56ad54d762172e8b8748e467f584f071e4dedecd93dc336cf2c68837e790be`다.
다운로드 helper 내부 579 ms·command 0/981 ms·자연 종료이며 upstream digest 대조나
불변 file identity·SourceAdmission·사용 권한을 발급하지 않았다. 8 MiB·원 45초,
독립 cleanup·원 오류 및 출력 반환 뒤 기한 검사를 재리뷰하고, 외부 120초 감독과
drain/output/export/scratch/lease를 따로 확인했다. 미실행 이전 helper 두 개도 보존했다.

이 vendor launcher를 제품 archive producer에 넣은 별도 실행은
`INPUT_ARCHIVE_PROFILE_UNSUPPORTED`·command 1/117 ms로 거절됐다. 125개 entry 중
124개의 실제 local header가 versionNeeded 10·Deflate 8이며 central은 versionNeeded
20이었다. 현재 producer는 Deflate에 version 20을 요구한다. 이 원 실패와 정상 drain·
보존 결과를 유지하고 지원 profile이나 상한을 바꾸지 않았다. vendor 도구 입력 관측과
제품 source inventory 인수는 별개다. 같은 held input의 선택한 installer 선언/bytecode를
실제 javap로 읽은 command는 0/1,929 ms·자연 종료다. manifest의 진입점은 실제 게임을
시작하는 ServerLauncher이며, 명시적인 Main의 server 설치 분기와 구분한다. 나머지
일곱 전이 class도 실제 javap command 0·3,039 ms로 읽어 installer Main의 명시 버전
선택·library/server 다운로드와 return을 확인했다. 이 정적 관측은 게임 실행이 아니다.

외부 준비 helper는 실행 전 독립 검토에서 drive 경로 표현, Java 실행 파일 pin과
실패한 hash의 상태 격리를 수정했다. 미실행 v1/v2를 보존하고 최종 v3
13,475 bytes·SHA `c7b5f73c851c376d6230607835b129c4252d3bcdd66ffc4dc2bacee8dc1d5e8c`를
재검토·구문 검사한 뒤 실행했다. held Java는 50,304 bytes·SHA
`5808527e3dfc4eb285c7664ba356bc267055ef906e83ed4660d9f7976da7349b`이며 기존 관측과
전후 일치했다. upstream executable digest 대조나 whole-JDK 인수로 확대하지 않는다.
installer Main은 command 0·4,462 ms·자연 종료, 원 Java exit 0·pre/post 두 pin 일치·
helper 오류 0이었다. 별도 root의 game 자료 66,202,949 bytes를 보존하고 native
drain·출력·export·scratch 정리와 root/build lease 해제를 확인했다. 300초 협력 및
360초 native 기한을 사용했으며 이 단계는 게임 main과 EULA 수락을 호출하지 않았다.

소유 root를 재획득한 정적 관측에서 생성된 `fabric-server-launch.jar`는 616 bytes·SHA
`9421951533f7b894cb203594fe0aef08a89a7fd7332d71c4924f5333d44c5596`였다. 두 member 중
manifest의 Main-Class는 `net.fabricmc.loader.impl.launch.server.FabricServerLauncher`,
classpath는 relative libraries 경로 7개다. `server.jar`는 62,294,556 bytes·SHA
`d052f14d7a173734fba553711e5b570162e2f2a313267ee31a21b975a679be64`로 관측했다.
command 0·725 ms이며 whole-library closure·loaded definition·SourceAdmission은
발급하지 않았다.

별도 helper의 독립 검토와 구문 검사 뒤 두 고정 mod JAR을 held source pin에 대조해
CreateNew·64 KiB 복사·flush·동일 destination handle hash로 배치했다. 호스트는 위의
3,509,931-byte digest와 같고, API는 1,772,377 bytes·SHA
`8626c189b702f466800b1c8ddac6203cf8a1e0bdaee75a5f9a33b18c2baa81b1`다. loopback IP·
online mode·RCON/query 비활성화·2명·view/simulation 2의 고정 properties 185 bytes·SHA
`81bd0ebfefa00f70772af044ee4f99735afc71ea1cb5810895be0ea404aca3db`도 CreateNew로 준비했다.
command 0·932 ms·helper 524 ms·stderr 0·오류 0이며 원 파일을 덮거나 삭제하지 않았다.
정상 drain·출력·export·scratch 정리와 root/build lease 해제 뒤 자료를 보존했다.
이 준비는 실제 mod 로드·ordinary origin 검사·observer 설치나 관리자 pairing을
대신하지 않는다. 이 mod 배치 준비 시점에는 EULA 수락과 게임을 실행하지 않았다.

실제 게임용 observer DLL을 Windows MSVC target으로 locked build했다. command
0·4,251 ms·명시 owned-tail 종료이며 721,408 bytes·SHA
`ceb8fcb92c467d0ae1aa1b85e4b0ab3e81f6550219073b9ebf4bf54e4c54a9b7`다. 별도 소유
game root 재획득 실행에서 단일 새 copy를 CreateNew·flush·같은 handle digest로
대조했다. observer JAR은 28,270 bytes·SHA
`4b2ebdb935eb25c186c978330a992f2173ea4891b2514bc152b121bae7abdf73`이며 game cwd 기준
ASCII 상대 이름 186자·상한 259 안임을 관측했다. JDK archive·modules·선택 JNI DLL의
크기와 digest도 같은 준비에서 관측했으며 선택 source 합계는 302,743,443 bytes다.
command 0·1,424 ms·helper 1,008 ms·stderr 0으로 copy와 자료를 보존하고 정상 drain·
출력·export·scratch 및 root/build lease 해제를 확인했다. 이는 whole-JDK image·
classpath·SourceAdmission·게임에서의 observer 설치 성공을 의미하지 않는다.

### 같은 설치의 EULA 동의와 게임 및 baseline 실패

사용자가 같은 Windows 개발 설치에 한정해 EULA 동의와 실행을 허용한 뒤, 관리 실행
309에서 `eula=true` 10 bytes를 CreateNew·flush로 기록했다. SHA는
`ee27072e4a23e088522f740ddaab0c7c4145c186969e90a86254faa3a5ec5ce6`다.
이 동의와 기록의 범위는 해당 설치다. 앞의 launcher·mod·observer 준비 기록은 그보다
이전 시점의 관측으로 보존한다.

| 실제 Windows 실행 | Java 종료와 시간 | 게임 관측 |
| --- | --- | --- |
| 310: native agent와 Java agent 모두 사용 | exit 0·9,344 ms | Ready 미관측, 90초 stop 요청 전에 종료·입력 0 bytes, 게임 시작 실패 |
| 312: 두 agent 인수만 제거한 같은 설치의 baseline | exit 0·3,901 ms | 같은 실패, Ready 미관측, stop 미요청·입력 0 bytes |

첫 오류는 `MixinExtrasConfigPlugin`의 `knot` loader 객체를 `app` loader의
`IMixinConfigPlugin`으로 cast하지 못한 ClassCastException이다. 이어
`FabricLoaderImpl`의 target class loader 로드 거절과 Fabric API `LivingEntityMixin`의
`MIXINEXTRAS:EXPRESSION` injection point 오류, `Failed to start the minecraft server`를
관측했다. baseline은 같은 설치에서 두 agent 옵션 없이도 같은 실패가 재현됐다는
근거다. observer의 일반적인 무관성이나 실제 게임 인수를 확정하지 않는다.

두 실행은 17개 사전 input pin과 16개 불변 입력의 사후 pin이 일치했다. 185-byte
properties는 사전 pin만 확인했고 게임 실행 후 내용은 읽지 않았다. 기존 180초 실행·
90초 stop 정책, 메모리 2 GiB·process 32개·출력 64 MiB 상한을 유지했다. 위
721,408-byte DLL의 source와 이후 CI 기준 `da95d0dc8ab88b40b9c4bf142d606f30179bd192`의
observer crate 사이에는 source 차이가 없음을 대조했다. drain·완전한 출력·export·
scratch 정리와 root/build lease 해제를 확인했으며 게임 자료를 보존했다. 외부 관리
종료와 Java exit 0은 위 게임 실패를 성공으로 바꾸지 않는다.

### Windows의 같은 게임 파일에 대한 경로 별칭 관측

관리 실행 314는 baseline에 고정 class-load debug 로그만 추가했다. Java exit 0·
79,202 ms이며 같은 최초 cast와 게임 시작 실패를 관측했다. stop은 미요청·0 bytes다.
stdout 19,504 bytes·SHA
`25e73cecae3e0e2b2a072cb862ef681553dc9bcc3fed911b221d24313ccf5fd2`, stderr
4,863,762 bytes·SHA
`a6b0191eab61d5e1322adf85586097380b91fb6c32888680b78f2df5bfcb3d16`를 외부에 보존했다.
app과 Knot가 같은 Loader 및 Mixin 클래스의 길이·VM checksum을 보고했지만 app의
원본 URI는 패키지 캐시의 물리 경로, Knot의 URI는 논리 Roaming 경로였다. URI와
local path는 달랐다. 616-byte launcher의 고정 digest와 두 ZIP entry를 다시 대조해
정확한 `fabric-server-launch.properties` marker의 존재도 확인했다.

실행 315는 game directory·Sponge Mixin JAR·Fabric Loader JAR의 각 두 경로를
`fsutil file queryfileid`로 조회했다. 같은 C: drive이고 조상 reparse/device가 없으며
128-bit file ID 세 쌍이 모두 같았다. command 0·1,079 ms·stderr 0이고 파일 내용·
owner·lease는 읽지 않았다. 이 순차 메타데이터 관측은 spawn까지 유지되는 handle
증명이나 별도 volume serial 대조를 대신하지 않는다.

공식 JDK의 app classpath는 Windows IO의 final-handle canonicalization을 사용하지만,
Fabric의 NIO 경로 집합 비교에는 가상화된 논리 표현이 남을 수 있다. 이는 launcher가
system library에서 제외되지 않고 manifest의 classpath를 Knot에 노출하는 가설과
맞는다. 실제 분류 내부를 관측하거나 checksum을 원 class bytes의 SHA로 해석하지는
않았다. [JDK IO 구현](https://github.com/openjdk/jdk25u/blob/jdk-25.0.4.1%2B1/src/java.base/windows/classes/java/io/WinNTFileSystem.java),
[JDK NIO 구현](https://github.com/openjdk/jdk25u/blob/jdk-25.0.4.1%2B1/src/java.base/windows/classes/sun/nio/fs/WindowsLinkSupport.java),
[Fabric 분류](https://github.com/FabricMC/fabric-loader/blob/0.19.5/src/main/java/net/fabricmc/loader/impl/game/LibClassifier.java).

D053의 명시적인 launch directory는 기존 root·owner·lease를 유지하고 held game
handle의 native volume/file identity와 대조한다. 같은 내용의 다른 디렉터리 거절,
secret·parent 경로의 사전 거절, 취소와 owner 변경의 동시 원인 보존을 검증했다.
실행 320은 library 229 PASS·1 ignored와 CLI 4 PASS, 321은 strict all-target Clippy
0·2,637 ms, 322는 새 runner build 0·920 ms다. 새 runner는 3,073,024 bytes·SHA
`1550b1921fd45ba67500a2f00e934111c78d57fa333209632146da4df9e83d2b`다.

원 실패도 보존한다. 317은 컴파일 중 timeout 124이며 설정 240초와 달리 실제
906,203 ms·최대 native 표본 공백 893,565 ms를 기록했고 테스트 결과는 없다.
원인은 확정하지 않았다. 318은 컴파일 후 228 PASS·1 FAIL·1 ignored로 끝났다.
새 검사의 `PathBuf::join("..")`가 Windows verbatim 경로를 먼저 정규화했으므로,
원 parent component를 직접 구성하는 입력으로 고친 뒤 320에서 통과했다. 두 실패의
drain·출력·export·scratch 정리와 lease 해제는 완료됐으며 실행 상한은 늘리지 않았다.
이 로컬 도구 검사와 명시 경로의 실제 게임 실행·인수는 별도다.

같은 설치의 실행 324는 두 agent를 다시 사용하고, 기존 논리 owner root를 유지한 채
명시한 물리 game directory와 그 root에서 파생하는 `-jar`·native agent·입력 pin을
일관되게 사용했다. 실제 CLI의 explicit alias requested/validated가 모두 true다.
17개 사전 pin과 16개 불변 입력의 사후 pin이 일치했고 observer 상대 ASCII 이름은
186 bytes로 기존 259-byte 제한 안이다. 원 EULA·owner·lease·world를 이동하거나
복사하지 않았으며 properties는 실행 전 기존 185-byte pin만 읽고 닫았다.

서버는 Minecraft 26.3·`mmmm_host 0.1.0`을 로드하고 `127.0.0.1:25565`에서
`Done (2.147s)`를 기록했다. 앞선 Mixin cast·target-loader 실패는 나타나지 않았다.
stop 요청은 원 요청 시계 92,069 ms에 관측됐고 실제 private LF 입력 5 bytes를 한 번
전달했다. 서버의 `Stopping server`·players/worlds/chunks 저장 로그 뒤 Java exit 0·
90,921 ms·자연 종료·완전한 출력과 drain을 확인했다. 감독 receipt의 game-save ACK는
계속 `not_observed`이며 이 로그만으로 world 내용의 독립 readback을 발급하지 않는다.

stdout는 16,881 bytes·SHA
`c856c38289c17566bad4f9b82c2386082fe6352b977e5694f1054b023555d68c`, stderr는
944 bytes·SHA `338f1df16b8905621c55d549c5a43115d379e65146b21b85078b81abf397de4f`다.
Windows Job commit peak는 859,840,512 bytes, 896개 표본의 최대 간격은 148 ms이며
원 2 GiB·32-process 정책을 유지했다. 6,675 ms의 별도 보존 단계에서 자료를 보존하고
scratch·root/build lease를 정상 해제했다. 최종 합산 catalog는 9,271,900,198 bytes로
기존 한도 안이다. 초기 게임 시작과 정상 중지의 양성이며 블록 apply/readback,
clip·adapter·권한 pairing·클라이언트 및 3개 OS 게임 인수는 아직 아니다.

같은 원 로그에는 Perflib 진단과 인증 서비스 연결 거절·`Services are unavailable`도
있다. 전역 성능 counter나 online mode를 바꾸지 않았으며 실제 로그인·관리자 pairing의
성공으로 보고하지 않는다. 실행 후 mutable properties·EULA·world 내용을 다시
읽거나 hash하지 않았다.

### 같은 현재 source의 Rust CI 49와 JVM CI 40

source `da95d0dc8ab88b40b9c4bf142d606f30179bd192`의
[Rust CI 49](https://github.com/daejunnom/MMMM/actions/runs/38644754912)와
[JVM CI 40](https://github.com/daejunnom/MMMM/actions/runs/38644754976)은 각각 세 OS job과
집계 성공을 확인했다. 실제 archive의 source·검사 집계·관리 종료 근거를 대조했으며
앞의 로컬 게임 실패 및 후속 제품 인수와 구분한다.

| Rust CI 49 | 표준 unit/bin PASS | ignored | native stderr 진행의 실제 bytes·시간 |
| --- | ---: | ---: | --- |
| Windows | 1,151 | 2 | 4,096 bytes·89 ms |
| Linux | 1,164 | 4 | 65,536 bytes·90 ms |
| macOS | 1,161 | 1 | 65,536 bytes·342 ms |

각 OS의 doc test 1개와 custom `native_stdio` harness 1회는 위 unit/bin 합계와 별도다.
native stderr 검사는 원 deadline과 drain을 유지했다. repository 검사는 466개·위반
0이며 관련 finish의 정리·lease 해제를 확인했다. macOS는 실제 rusage exit와 부분 task
lower bound 표본에서 member Pending 1회, BSD status 2·INEXIT true·같은 anchor를
보존하고 최종 drain 0을 확인했다. bootstrap의 D051 진단 key와 D052 실행 branch
counter는 해당 기록에 없어 그 경로의 실제 도달 여부를 소급 확정하지 않는다.

JVM CI 40은 일곱 모듈의 333 tests·failures/errors/skipped 0, 필수 task 11개 모두
실제 executed다. 테스트 수는 SDK 108·host-core 89·public adapter 17·Fabric host 68·
definition observer 22·legacy fixture 18·provider fixture 11이다. observer의 세 단계
record digest 9개와 이전 JVM digest 5개, 8개 header pin의 재검증 및 native build·
header witness·startup의 관리 종료를 확인했다. Windows의 이전 JVM·startup은 자연
종료, native build·header 관리 실행은 명시 owned-tail 종료이며 모두 drain/output/
export·supervisor/cleanup 오류 0·scratch 정리·lease 해제를 보존했다.

이번 observer source manifest는 이전 53개가 아닌 54개이며 JVM source 입력은 169개다.
controlled startup은 12개 선택 pin의 획득·실행 전후 재검사와 13개 완료 phase,
5,886-byte ABI2/stdout의 동일 digest를 확인했다. Windows raw SHA는
`5eddf455a2379f51258d0fd54062d595ab26e1a444cc785d1b495a6ebc1e3b54`다. Linux는
reserved leader의 RSS open/ESRCH에서 Pending 1회·pidfd not-ready·현재 identity 일치를
관측했고 대응 macOS optional 진단은 null로 남았다. 이 기록들은
`development_fixture`이며 game/release는 not-run, SourceAdmission·target policy·
whole-JDK image 인수는 false다. 현재 실제 게임 실패의 해결이나 제품 배포를 의미하지
않는다.

실패한 실행의 원본 판정은 유지한다. native drain과 정확한 소유 기록을 확인하고
로그를 별도로 내보내며 digest를 대조한 경우에만 해당 실행의 알려진 임시 파일을
정리했다. 원래 자동 export 실패와 수동 보존 성공을 같은 결과로 기록하지 않는다.
원본 증거와 회수 기록은 저장소 밖에 보존한다. 이 표는 로컬 WIP 소스의 관측이며
고정된 출시 SHA, 3개 OS 통과 또는 실제 게임 인수를 의미하지 않는다.

첫 원격 실행은 source `f8e083811c61e9b845dc88db97727575f9081035`의
[foundation run](https://github.com/daejunnom/MMMM/actions/runs/38432345224)이다.
실패 로그와 Windows 시작 실패 artifact를 외부 증거 위치에 보존했다.
실행 파일 경로 선택 및 native 오류 진단을 수정한 source로 후속 CI를 진행하며,
실제 결과를 확인하기 전 원격 보호의 필수 성공 검사나 G0 인수를 등록하지 않는다.

두 번째 원격 실행은 source `098327185c202c0c2f9ae14008654feb56627613`의
[foundation run](https://github.com/daejunnom/MMMM/actions/runs/38435093729)이다.
Linux job의 성공과 Windows bootstrap 자체의 성공을 확인했으나 전체 집계는
실패했다. Windows workflow 종료 판정과 Unix 실패 단계 진단을 보완해 다음
source에서 재검증한다. macOS의 EPERM은 단계 진단 없이 원인을 단정하거나
process 관찰·자원 한도를 완화하지 않는다.

세 번째 원격 실행은 source `97d52b104a75f732a0fefe9d63b62dd0c62b7bd3`의
[foundation run](https://github.com/daejunnom/MMMM/actions/runs/38437712210)이다.
Windows와 Linux는 구조·formatting·tests·Clippy까지 통과했다. macOS는
`prepare and supervise Cargo build` 단계에서 실패했고 원인을 확인하는 진단을
추가했다. 전체 집계의 실패는 유지하며 세 OS 통과로 표시하지 않는다.

네 번째 원격 실행은 source `7a77858d9e32831941404d824d7dd3a97716bdca`의
[foundation run](https://github.com/daejunnom/MMMM/actions/runs/38438925123)이다.
Windows와 Linux는 전체 기반 검사를 통과했다. macOS의 원본 artifact bytes와
SHA-256을 대조하고 한정된 supervision 기록을 확인했다. Cargo는 실행되지
않았고 launcher의 `ValueError`가 주된 실패이며, 종료 시 `EPERM`도 기록됐다.
자원 한도와 process 관찰을 완화하지 않고 native 실패 지점을 확인한다.

다섯 번째 원격 실행은 source `580bab7e418ebb8a7ab4a334277d88f22477a031`의
[foundation run](https://github.com/daejunnom/MMMM/actions/runs/38440722051)이다.
Windows와 Linux는 전체 기반 검사를 통과했다. macOS의 보존 artifact bytes와
digest를 대조해 `set address space limit`의 native `EINVAL`을 확인했다.
Darwin 전용 자원 정책의 채택과 구현을 실제 CI 성공으로 표시하지 않는다.

여섯 번째 원격 실행은 source `40510b7a8f5554084c40445b5b0a76fc477d2dc1`의
[foundation run](https://github.com/daejunnom/MMMM/actions/runs/38447616775)이다.
Windows와 Linux는 전체 기반 검사를 통과했다. macOS는 `RLIMIT_AS` 설정과
readback을 완료하고 Cargo를 시작했으나, 동기 파일 크기 검사 중 완전한 native
표본 간격이 2817 ms로 늘어 실패했다. 보존 artifact의 정확한 bytes와 digest를
대조했으며 실패·drain·export와 보존한 lease를 기록했다. 파일 순회와 출력 배치
사이에 실제 native 관측을 연결했고, 단일 호출이 1초 이상 막히면 계속 실패한다.
자원 한도를 늘리거나 성공한 것처럼 heartbeat를 기록하지 않는다.

일곱 번째 원격 실행은 source `3f022c91e32324ae0a16fe7abbfe00fd4ce98ce4`의
[foundation run](https://github.com/daejunnom/MMMM/actions/runs/38452370274)이다.
Linux와 macOS는 전체 기반 job을 통과했다. Windows는 실제 제품 검사를 진행하다
저장 크기 관측에서 `Access is denied`로 실패했으며 정확한 artifact bytes와 digest,
실제 종료·drain·export 및 lease 해제를 확인했다. 실패 위치 진단을 추가하되 native
오류나 관측 정책을 완화하지 않는다.

여덟 번째 원격 실행은 source `8d2ac7f49132eea55ba527f53232958f966abdc1`의
[foundation run](https://github.com/daejunnom/MMMM/actions/runs/38453149507)이다.
모든 OS에서 bootstrap·구조·formatting을 통과했으나 제품 컴파일에서 실패했다.
보존한 세 OS artifact의 bytes와 digest를 대조했고, Windows·Linux의 존재하지 않는
테스트 취소 호출과 Darwin의 variadic 정수 승격 오류를 확인했다. Darwin 제품
컴파일 실행의 실제 자원 관측은 611개 표본과 최대 230 ms 간격을 기록했다.

## 단계별 규약 적용

| 단계 | 연결할 규약 | 필요한 결과 |
|---|---|---|
| G0 | 계약 정본, 저장 기반, 구조 정책과 빌드 수명 | 계약 및 도구의 실제 검증, 출력 경로, crash와 거절 경로 |
| G1 | 도메인, plan, 가상 실행과 PR 소비자 영향 | 입력 거절 시 상태 보존, 독립 기대값, 원장과 CAS 참조 보존 |
| G2 | 실제 JVM 호스트와 SDK, 권한 및 종료 수명 | 3개 OS의 실제 서버 연결, 적용 및 readback, 취소와 파일 회수 |
| G3 | 교환 및 컴파일, 결정적 생성과 fixture 유지비 | 관련 함수 계약, target에 맞는 출력, digest와 보존 조건 |
| G4 | CLI 및 MCP, 강화, 인수와 릴리스 | 필수 인수 판정, 고정 SHA와 동일 배포 파일, 실제 검증과 공개 배포 |

기능 계약 FN01부터 FN36까지와 G0부터 G4의 A부터 G까지 필수 인수 항목을
결과에 연결한다. 명세 파일 검사, fixture 검사, mock과 실제 게임 검증을 구분한다.
선택 기능의 미지원 및 거절 검사는 해당 계약을 지키는 범위로 기록한다.

## 구조 검사 인수

검사 대상은 stage 0의 경로, Git mode, 객체 종류와 크기다. 내용은 stage된
`.github/repository-policy.json` 하나만 읽는다. 해당 blob이 regular file이며
64 KiB 이하인지 확인한 뒤 정책을 검증한다.

unmerged index, 등록되지 않은 root, 비밀 이름, generated 경로, 초과 크기,
비정상 경로, Windows 장치 이름, 대소문자 및 Unicode 충돌, symlink와 submodule을
거절한다. 예외는 정확한 경로의 generated 또는 size만 허용하고 비존재,
불필요 및 중복 예외를 거절한다. 정상 `build.rs` 같은 소스 파일명을 생성물로 오인하지 않는다.

unstaged와 ignored 자료를 검사했다고 표시하지 않는다. 비밀 내용이나 링크 대상을
읽지 않는 범위를 검증한다. Git hash 길이와 NUL 구분 metadata, 비정상 정책,
잘린 metadata 및 객체 정보 실패를 확인한다.

## 빌드 수명 인수

[빌드 수명주기](build-system.md)의 소유 루트와 lease, 유한한 자원 및 종료 조건을
3개 OS에서 검증한다. 정상 및 실패 종료, timeout, 취소, 남은 자식, hard kill,
busy와 중단 lease, 소유 기록 변경, 한도 초과와 외부 경로를 포함한다.

생성물 정리 전 보존 자료를 내보내며 명령 결과, supervisor 결과와 정리 결과를
각각 확인한다. 제품 DB, CAS, 작업 원장, 복구 자료, 사용자 원본, 다른 checkout과
릴리스 증거가 정리되지 않음을 확인한다. 검증된 결과에 실제 명령과 환경을 등록한다.

## Sealed pose와 직접 블록 및 Compatibility 연결 작업

현재 작업은 세 경계를 분리하여 연결한다. compiler의 새 `display_pose`는 같은
sealed scene과 animation draft의 exact clip revision·target·TPS·instance/node
binding을 대조한다. 이미 컴파일한 target f32 pose만 사용하고 caller matrix나
UUID를 받지 않으며, 기존 display의 세 interpolation/teleport 필드를 0으로 고정한다.
이 projection은 실제 tick scheduler, 현재 world before-state 또는 실행 권한이 아니다.

직접 `mmmm:block_patch`는 실제 AIR/STONE 기본 상태와 27셀의 loaded/current 상태를
전후 확인하는 좁은 preflight와 연결 중이다. Rust는 직접 block-state와 block-entity
부재를 별도 reader/CAS로 포착한다. `full_target`은 그 정확한 subject bytes의 범위다.
조명·POI·entity·neighbor 효과는 `not_observed`이며 정확 undo를 보장하지 않는다.
`INDIRECT_ENGINE_EFFECTS_EXCLUDED` loss는 명시 승인을 요구한다. 이 관측을 모든
engine 효과의 완전 footprint나 새로운 native profile/관리자 승인으로 사용하지 않는다.
Composite의 precondition·dispatch·before-capture·readback·reconcile을 실제 소비
경로에 연결했다. 현재 저장 invocation·plan·step과 같은 Store·원 scope를 확인하고
dispatch에는 현재 Apply 승인, poll에는 현재 Observe 권한을 적용한다. actual host
witness 취득은 원 기한으로 execution-context RPC를 한 번 수행한다. 이후 main RPC
전후의 witness·grant·scope 검사는 로컬에서 수행하며 새 기한을 만들지 않는다.
독립 리뷰에서 발견한 응답 후 grant·lease 재검사 누락을 수정했고, 원 native 오류와
동시 권한 상실을 함께 보존한다. 실제 게임 write·readback 인수는 여전히 미실행이다.

Compatibility 승인 저장은 기존 보호 Store에 actual native owner·Project·원본
ResourceRef raw SHA와 별도의 profile/artifact/interface pin·현재 Policy/local-use scope를
보존한다. 같은 ref의 exact replay만 허용하고 다른 pin은 충돌한다. cold CLI 선택,
FN19와 inventory의 같은 canonical binder, 원 bootstrap의 유한 map 전달을 연결 중이다.
Java의 metadata resolver는 실제 Fabric 단일 일반 JAR·mod 버전·현재 loader에 연결했다.
초기화를 요청하지 않고 정확한 public static signature와 source 입력 pin을 확인하며,
실제 inventory의 metadata binding도 incompatible/ready=false와 고정 실행 거절을
유지한다. 기존 LoadedClassApproval과 executable Candidate는 별도다. snapshot과
명시적 파일 I/O는 각각 64 MiB 안으로 제한하고 caller의 원 크기 예약을 payload 읽기
전에 대조한다. classloader 내부 I/O는 이 명시적 counter의 측정 범위 밖이다.
source 실패와 동시 취소·기한 원인을 보존한다. 원 connect 기한·취소를 install까지
유지하며 전체 사전 검사 뒤에만 metadata 등록을 시작한다. 현재 source의 Java 통합
검사는 별도 수행 전이고 실제 게임 AD01/AD02 및 FN33 실행 인수는 미완료다.

Windows 관리 실행 `implementation-checks-20261014-330`은 새 compiler 오류 반환의
타입 불일치로 컴파일 exit 101이었다. 이를 수정한 `332`는 compiler 89개와 runtime
120개 unit 및 compiler doctest 1개가 통과했고 `333`의 두 package/all-target strict
Clippy도 exit 0이었다. 새 protected record 검사는 기존 SQLite/CAS fixture를 사용하며
실제 Java/게임 관측을 만들지 않는다. 두 실행의 원 stdout·stderr와 결과는 외부 증거에
보존했고 drain·출력·export·scratch 정리 및 lease 해제를 확인했다. 나머지 연결의
전체 Rust/JVM 검사는 별도 수행·기록하며 이 부분 성공을 전체 인수로 확대하지 않는다.

추가 통합의 Windows `335`는 새 observer 하위 모듈의 세 메서드 접근 범위와 기존
bootstrap fixture 초기화 세 곳 누락으로 컴파일 exit 101이었다. 해당 연결을 수정한
`337`은 컴파일을 마쳤지만 앱 테스트 EXE가 실제 Application Control `4551`로
차단되어 한 테스트도 실행되지 않았다. Coordinator 검사가 실행됐다고도 기록하지
않는다. 원 오류와 stdout·stderr 및 관리 결과는 보존했고 drain·export·scratch와
lease는 정상 완료했다. 이는 사용자 조건에 따른 해당 검사의 Ubuntu 대체 근거이며,
Ubuntu 결과는 아직 발급하지 않는다. 선택적 승인 payload의 전체 JSON node 한도와
Project의 사전 크기·chunk 취소 경계는 독립 리뷰에 따라 보완했다. 보호 DB의 현재
Project head·blob·길이를 bounded metadata로 먼저 대조하고, 8 MiB 상한과 원 요청의
chunk별 취소 검사를 통과한 실제 Project만 읽는다. 선택적 map 부착으로 전체 node
한도를 넘으면 정확한 크기 오류로 처리하며 기본 native pairing은 unavailable map으로
계속할 수 있다. malformed frame을 일괄 fallback하지 않는다.

Windows `341`의 기본 test thread 구성에서는 기존 native catalog 검사 하나가 기대한
`SOURCE_UNAVAILABLE` 대신 `CANCELLED`를 받아 실패했다. 소스·기대값·기한을 바꾸지
않고 CI와 같은 `--test-threads=2`로 실행한 `342`에서는 Coordinator unit 343개가
통과하고 1개가 ignored였으며, 별도 native stdio의 실제 deadline·drain 검증도 통과했다.
두 결과를 모두 보존하며 동시 부하를 확정 원인으로 기록하지 않는다. 이어 실행될
새 Runtime test EXE는 Application Control `4551`로 시작되지 않았으므로 새 Project
head 검사 3개는 해당 로컬 실행에서 미실행이다. `343`의 앱 unit 16개는 Windows에서 실제 통과했다.
`342`와 `343`은 출력·drain·export·scratch 정리·lease 해제를 완료했다. 직접 블록의
Composite 위임은 아직 연결 전이므로 관련 메서드의 unused 경고가 남아 있고,
당시 변경의 Java 검사는 아래 후속 `346`에서 별도로 수행했다.

WIP `49c053cb21d30bc7e6badbfebb20593f4dd14124`는 같은 feature 브랜치와
Draft PR에 공유하고 정확한 원격 SHA를 확인했다. Windows JVM 관리 실행 `345`는
Gradle 이전 JVM 초기화의 `jimage file name is null` 오류로 종료됐다. 그 실행이
checkout에 생성한 오류 보고서는 내용을 열지 않고 정확한 소유 증거 루트로 옮겼다.
관리 경로의 extended 접두사를 native DOS 경로로 정규화한 `346`은 7개 모듈의
353개 테스트와 Gradle 33개 executed tasks를 통과했다. 모듈별 tests는 SDK 108,
host-core 92, public-java-adapter 19, Fabric host 83, definition-observer 22,
legacy fixture 18, provider fixture 11이며 실패·오류·skip은 모두 0이다.
로컬 report 요약 SHA는
`a0c2d481480950431c32d62061a1cf704ba4c164dd95b331d516aac83519815e`다.
같은 실행의 command 0·36,426 ms·자연 drain·완전한 출력·export·scratch 정리 및
lease 해제를 확인했다. Job commit peak는 1,386,319,872 bytes, peak process 6개,
최대 표본 간격 146 ms이며 기존 2 GiB/32 process 상한을 유지했다. Gradle native
access와 deprecated 경고는 보존했다. 이는 로컬 검사이며 CI·게임 성공으로
재분류하지 않는다. 해당 source의 JVM CI 42 (`38744776835`)는 세 OS 및 집계의
성공을 관측했다. Rust CI 51 (`38744776812`)도 세 OS의 실제 tests가 통과했지만
strict Clippy와 집계는 실패했다. 실제 ZIP 6개를 별도 보존·감사했고 source/expected/
PR head 및 별도 event SHA `8286282aff6a7f2fb026d58411a627337872273c`, raw digest와
종료·정리 연결을 대조했다. 새 Project head 검사 3개는 세 OS stdout에서 실제 `ok`를
확인했다. Clippy의 실제 세 오류는 direct observer 메서드 미사용, 같은 모듈의
`int_plus_one`, peer codec의 `unused_unit`이며 후속 consumer 연결·표현식 수정을
진행한다. Windows 로컬 SAC 차단과 원격 Windows 검사 성공은 별도 결과다.

후속 direct consumer의 Windows `354`는 병렬 rustc 컴파일 중 LLVM OOM과 실제
Job commit 2,149,158,912 bytes를 관측해 자원 상한으로 종료됐고 테스트는 시작하지
못했다. 원 로그와 typed resource 오류를 보존했으며 drain·export·scratch 정리와
lease 해제를 확인했다. D055에 따라 상한은 그대로 두고 Cargo 빌드 작업만 1개로
명시한 `355`는 Coordinator unit 347개 통과/1개 ignored 및 별도 native stdio 검증을
통과했다. command 0·114,236 ms, Job commit peak 1,397,723,136 bytes·peak process
7개·최대 표본 간격 147 ms였고 출력·drain·export·scratch·lease를 정상 완료했다.
`356`의 같은 package/all-target strict Clippy도 exit 0과 정상 정리를 확인했다.
두 실행은 아직 실제 게임이나 후속 Compatibility resolver 검증의 근거가 아니다.

실제 원본 26.3 JAR을 held read와 전후 digest로 고정한 static API·bytecode 검사
`348`–`350`에서 함수 실행의 preseed 관측 시점과 반환 callback 부재 분기를 확인했다.
클래스 초기화·게임·world/config 읽기는 수행하지 않았다. D056의 두 private v2
codec은 관측되지 않은 반환을 null로 보존하고, 선택 source와 독립 readback의
null/Int32를 정확히 비교한다. `359`는 집중 unit 13개가 통과했지만 필터 인수가 별도
harness-free native fixture에도 전달되어 명령 전체는 exit 101이었다. 올바른 `--lib`
선택의 `360`은 같은 unit 13개 통과와 정상 정리를 확인했고 `361`의 같은 package
all-target strict Clippy도 exit 0이었다. 기존 검사만 확장했으며 새 fixture는 없다.
실제 calibration runner·ADMIN 전용 bootstrap permit·issuer/provenance 연결과
47개 case의 실제 게임 실행은 이 codec 수정으로 완료되지 않는다.

공유 `052116b09f31d565ee70f99470a2b2475d862717`의 Windows JVM `363`은 실제
제품 Java와 Fabric 컴파일을 마쳤지만, 새 public adapter test의 JUnit `fail` import
누락으로 해당 test compile이 실패해 Gradle exit 1이었다. 다른 모듈 task의 실행을
전체 성공으로 집계하지 않는다. 원 stdout·stderr와 source/tool digest 및 drain·export·
scratch 정리·lease 해제를 보존했고 누락 import를 보완하여 같은 범위로 재검증한다.

후속 `be6cc8e0556de396d8cb5cb3a5f26043b97aed31`의 Windows JVM `365`는 모든
Java 컴파일과 Gradle 33개 task를 실제 실행했지만 public adapter 29개 테스트 중
1개가 실패해 전체 exit 1이었다. metadata 전용 등록 검사가 HostRuntime의 공통 읽기
사전 조건을 mutation으로 잘못 간주한 실패다. 제품 HostRuntime과 실행 거절 코드는
바꾸지 않고, 기존 검사에서 원래 context·arguments와 게임 스레드의 읽기 사전 조건,
쓰기 권한 요청 0회, 효과 관측 0개, 대상 API 호출 0회 및 초기화 부재를 각각 확인하도록
수정한다. 원 실패·출력과 정상 drain·export·scratch 정리·lease 해제를 보존하며,
다른 모듈의 성공을 전체 JVM 성공으로 집계하지 않는다.

수정한 `0cedbf05d948319c5fc6cc9eb694d88bfc5b5027`의 Windows JVM `367`은 같은
고정 JDK·Gradle 및 원 7모듈 범위에서 374개 테스트/30개 reports와 33개 executed
tasks를 통과했다. 모듈별 tests는 SDK 108, host-core 92, public-java-adapter 29,
Fabric host 94, definition-observer 22, legacy fixture 18, provider fixture 11이며
실패·오류·skip은 모두 0이다. 원 stdout·stderr와 XML digest 목록을 외부 증거로
보존한 로컬 요약 SHA는
`5654bdf7f9c463b7f957622781c4687b49896990fe1efb676799c5be8af1543f`다.
command 0·32,304 ms, Job commit peak 1,396,297,728 bytes·peak process 6개·최대
표본 간격 146 ms였고 기존 2 GiB/32 process 상한을 유지했다. drain·완전한 출력·
export·scratch 정리·lease 해제를 확인했다. 이 결과는 metadata source·서명 확인과
실행 차단을 포함한 로컬 검사이며 실제 게임 metadata·실행 adapter·CI 전체 인수나
공개 배포 성공으로 확대하지 않는다. 같은 SHA의 Rust CI 56 (`38754198908`)과
JVM CI 47 (`38754199266`)은 등록을 확인했다. 이후 같은 JVM CI의 세 OS와 집계 성공을
관측했고 실제 ZIP 3개를 외부 보존하여 감사를 진행한다. 이전 `be6cc8e`의 JVM CI 46
(`38752720205`)은 세 OS 모두 같은 metadata test 이름과 258행의 AssertionFailedError를
기록했다. 원 XML은 artifact에 없어 전체 stack은 CI ZIP에서 독립 재확인하지 못했다.
당시 원 stdout·stderr, source/expected/PR head 및 별도 event SHA, 374개 중 실패 1개와
원 종료·정리 연결을 대조했다. 해당 SHA의 Rust CI 55 (`38752720231`)는 Linux·macOS
전체 job이 성공했지만 Windows는 `NotFound` 이후 surviving ancestry의 metadata
조회에서 native 오류 5를 받아 `observation_failure`로 중단됐고 집계가 실패했다.
완료된 test summary를 전체 test 성공으로 집계하지 않는다. Windows의 원 오류와
출력·drain·export·scratch 정리·lease 해제는 보존했으며 어느 component의 삭제 경합인지
ACL 거절인지는 현 진단만으로 확정하지 않는다.

후속 D059 구현은 실제 JNI Class 조회에서만 private `CurrentLoadedExecutable`을
발급하고 collector와 현재 owner slot에 보존한다. Class·실제 loader 객체·원 native
stamp와 전체 envelope를 재검사하며, 현재 native loader ID 0은 실제 bootstrap을
뜻하고 nonbootstrap은 실제 loader 객체와 해당 ID를 대조한다. raw fixture에는 view가
없어 executable 조회를 만족시키지 못한다.
기존 startup fixture의 실제 ordinary·hidden 세 Class는 새 발급 및 현재성 경로를
사용하도록 연결했다. 기존 64 Class/8 MiB 안에 decoded byte payload까지 계상하고
slot의 JNI와 원 checkpoint는 monitor 밖에서 실행한 뒤 현재 ticket·owner를 다시
확인한다. 현재 입력은 registry의 기존 다섯 Class 역할이므로 parser·predicate·handler·
source factory의 수집과 admission 양성은 아직 연결하지 않았다. 새 VM snapshot이나
최종 classfile, 일반 쓰기·profile·calibration 승인을 발급한 것으로 보고하지 않으며
수정한 소스의 실제 JVM·native startup 검증은 후속 실행에서 확인한다.

공유한 `45789e938307cef6362c30fbc06aba9947333332`의 Windows JVM `373`은 제품
Java와 observer 검사를 컴파일했지만 Fabric test compile에서 새 관측 타입을 찾지
못해 exit 1이었다. observer는 생산 경계에서 의도한 compile-only 의존성이며 agent가
별도로 제공한다. 테스트가 새 API를 직접 참조하므로 같은 내부 observer 프로젝트를
testImplementation에도 추가한다. 외부 의존성이나 생산 JAR의 포함 범위는 바꾸지 않는다.
Gradle 32 executed tasks와 원 진단·출력을 보존하고 drain·export·scratch 정리·lease
해제를 확인했다. Fabric의 오래된 XML 결과를 이 실패 실행의 성공으로 집계하지 않는다.

같은 내부 test classpath를 보완한 `ffb9b1bb1b11b4f7f88095677f3dccfb8ea895ed`의
Windows JVM `375`는 7모듈 378 tests/30 reports 및 33 executed tasks를 통과했다.
SDK 108, host-core 92, public-java-adapter 29, Fabric host 96, definition-observer
24, legacy fixture 18, provider fixture 11이며 failure/error/skipped는 모두 0이다.
외부 로컬 요약 SHA는
`7a57da902f5ce806d59510fe757c5cf9ac802c15ed69b4b8d5cbf899c88a5e3a`다.
command 0·29,473 ms, Job commit peak 1,392,861,184 bytes·peak process 6개·최대
표본 간격 126 ms였고 원 2 GiB/32 process 상한·drain·완전한 출력·export·scratch
정리·lease 해제를 확인했다. 실제 새 view 발급의 native startup과 slot 양성·JNI 중
owner 교체는 이 순수 JVM 검사에서 미실행이며 별도 근거를 요구한다.

앞선 고정 `0cedbf0`의 JVM CI 47 실제 ZIP 3개 감사는 완료했다. 각 OS 374 tests와
필수 task 11개, observer native build·ABI·startup의 raw receipt 및 pin 연결과 정상
종료·정리가 일치했다. 원 XML·owner 및 일부 JDK/JAR 원문은 포함되지 않아 모두의
원 bytes를 독립 hash한 것으로 보고하지 않는다. JVM source inventory 175개 중
`jvm/gradle.properties`만 Windows 271 bytes/CRLF, Linux·macOS 264 bytes/LF였고
고정 Git blob의 LF→CRLF 변환 SHA가 Windows pin과 정확히 일치했다. 같은 source
SHA의 성공과 OS 사이 전체 입력 bytes의 동일성을 구분한다. 후속 `45789e9`는 소유
작성 properties의 LF 규칙과 실제 test/Clippy jobs 1·bootstrap jobs 2의 CI metadata
구분을 반영했다. 이는 앞선 artifact를 변경한 것이 아니며 새 CI에서 다시 관측한다.

D060의 Windows vanished ancestry 보완은 원 `NotFound`와 component native 5를 함께
보존하고 기존 Running 공유 재관측 예산만 사용한다. 실제 재등장 metadata를 측정
경로로 돌려주며 directory 열거 재개는 미처리 pending 자식만 되돌린다. 새 fixture
파일 없이 기존 실제 임시 파일·owner 및 주입 port를 사용한 검사 3개와 기존 취소·
link·owner 교체·공유 예산 검사를 확장했다. Windows 관리 실행 `377`의 소유 두 파일
formatting, `378`의 xtask lib 232 PASS/1 ignored 및 `379`의 같은 package/all-target
strict Clippy가 통과했다. `378`은 command 0·28,152 ms, Job commit peak 447,070,208
bytes·peak process 10개·최대 표본 간격 123 ms였고 명시한 소유 잔여 자식 정리 뒤
drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다. 앞선 감독 EXE가 이
검사를 실행했으며 새 코드로 부모 관리 도구를 교체했다고 기록하지 않는다. 실제
CI의 native 5 경합 회복과 OS별 새 소스 검증은 아직 별도 결과가 필요하다.

`ffb9b1b`의 JVM CI 49 (`38757755437`)는 세 OS의 378개 JVM 테스트가 성공했지만
native observer 단계와 집계는 실패했다. 실제 ZIP 3개에서 native build와 ABI witness는
성공했고, startup의 공통 Java 원인은 `ORDINARY_ACTUAL_LOADER_UNAVAILABLE`였다.
새 fixture가 nonbootstrap `ProbeLoader`의 실제 loader ID에 0을 요구한 잘못된 비교다.
현재 Rust producer는 이미 일반·hidden 모두 실제 `record.loader_id`를 기록하고 실제
bootstrap loader만 0으로 식별한다. fixture에서 nonbootstrap ID 0을 거절하도록
비교를 교정하며 실제 ClassLoader 객체 일치·non-null·source 역할 및 현재성 검사는
유지한다. Mac/Linux signal 6과 Windows exit 1 및 정상 drain·출력·export·scratch·
lease 결과를 보존한다. before/after native status 숫자는 이 실패에서 관측되지 않았고
만들어 채우지 않는다. 후속 실제 startup 성공은 별도 확인한다.

D061의 새 `NativeLoadedCalibrationSources`는 실제 winner source와 등록 함수 object를
읽기 전용으로 관측한다. 실제 원본 26.3 JAR을 held read·전후 digest로 고정한 static
검사 `370`·`376`에서 manager/pack/reload API와 함수 loader의 winner-map 및 native
FileToIdConverter 매핑을 확인했다. 새 producer는 exact getResource만 사용하고 전역
함수 자료를 열거하지 않는다. 최대 47함수·함수별 64 KiB·합계 1 MiB와 두 pass의
공유 stream read 한도, pack 목록 256개와 원 checkpoint를 적용한다. 실제 server
thread, manager·선택 pack·winner·함수 object/ID와 source 원문을 전후 확인한다.
원 취소와 open/read/close 및 후행 현재성 오류를 보존하며 raw test scan은 production
view로 변환되지 않는다. 기존 fixture에 복수 manager/winner 교체와 두 source read
경계가 없어 작은 순수 port fixture와 검사 8개를 별도 소스에 작성했다. 독립 소스
리뷰의 blocking finding은 없다. 정확한 `518013125f332a602b2c3936ce2eb8dcd9ea18b0`의
Windows 관리 실행 `383`은 7모듈 386 tests/31 reports와 33 executed tasks를 통과했다.
SDK 108, host-core 92, public-java-adapter 29, Fabric host 104, definition-observer
24, legacy fixture 18, provider fixture 11이며 failure/error/skipped는 모두 0이다.
외부 로컬 요약 SHA는
`2b1d16247ee87f7a3a76a002886d45258f9d3e7cb7dbcaaa7fe85b01bb757390`다.
command 0·28,934 ms, Job commit peak 1,375,506,432 bytes·peak process 6개·최대
표본 간격 124 ms였고 원 2 GiB/32 process 상한과 drain·완전한 출력·export·scratch
정리·lease 해제를 확인했다. JVM source 범위의 tracked 변경과 미등록 파일이 없음을
실행 전후 검사하여 다른 소스를 해당 SHA의 성공에 섞지 않았다.
liveHost·paired/context/epoch/generation/reload 및 원 요청 기한 callback 설치, 실제
load→parsed function 인과, staging·permit·runner·수치 readback·issuer는 미연결이다.
현재 helper는 instantiate·parse·handler·reload·쓰기나 profile 승인을 수행하지 않는다.

교정한 `5d9c1df99b67cfab32d6b7a68a09c1d6ff10e10c`의 JVM CI 51
(`38759797927`)은 세 OS와 집계가 성공했다. 원 ZIP 3개 감사에서 source/expected/PR
head와 별도 event SHA `6d38d5a5cf9e9036968ece5a8909d5ae9f9c1a02`, 각 OS의 378
tests/30 reports/필수 11 executed tasks 및 observer build·header·startup의 원 digest와
receipt 연결을 대조했다. 실제 startup은 세 OS 모두 command 0·drained/output complete,
5,886-byte ABI2 frame과 stdout의 digest가 일치했고 내부 native observed status 255,
direct absence flag 1과 summary target class status 7을 확인했다. 고정 fixture는 실제
ordinary·samless hidden·positive hidden view의 발급·현재성과 direct raw/view 부재를
재검사한 뒤에만 frame을 출력한다. 개별 JNI query의 before/after status 숫자는
export되지 않아 따로 추정하지 않는다. 각 OS properties는 264 bytes와 고정 Git blob
SHA가 일치했으며 종료·drain·export·scratch·lease가 정상 완료됐다. 원 owner와 일부
JDK/JAR 원문은 ZIP에 없으므로 전부를 재hash한 것으로 보고하지 않는다. 이 통제된
startup 성공은 slot 양성·실제 게임·SourceAdmission·쓰기나 profile 승인 증거가 아니다.
같은 SHA의 Rust CI 60 (`38759798078`)은 세 OS tests·strict Clippy 및 집계가 성공했고
원 ZIP 3개 감사를 마쳤다. source/expected/PR head·별도 event SHA와 실제 raw digest 및
format/repository/test/Clippy 12개 managed process의 exit 0·drain·출력·export·scratch·
lease가 일치했다. 원 stdout의 각 30개 harness summary 합계는 Windows 1,193 PASS/
2 ignored, Linux 1,206 PASS/4 ignored, macOS 1,203 PASS/1 ignored이며 doctest를
포함한다. 별도 native stdio binary도 각 원 stderr에서 실제 호출을 확인했다. D060의
새 세 검사와 기존 owner/link/cancel/budget 검사는 실제 통과했고 각 CI bootstrap은
해당 source의 xtask 컴파일·정상 실행을 기록한다. 다만 모든 phase의 observation retry
records는 0개이므로 실제 native 5 경합의 발현·회복 양성으로 보고하지 않는다.

후속 `5180131`의 JVM CI 52 (`38760866044`)는 세 OS JVM 단계와 Windows·macOS의
native observer 단계가 성공했지만 Linux native observer 단계와 집계가 실패했다.
원 ZIP 3개를 별도 보존했다. Linux는 build·header가 성공했고 startup 명령도 0으로
끝났지만 reserved leader의 RSS Open/ESRCH 관측 오류로 `PROCESS_INCOMPLETE`였다.
전후 Zombie·threads 3·원 identity 일치·BoundValidated pidfd TerminalPoll/NotReady를
보존하며 기존 threads 2의 제한된 Pending 조건과 별도로 검토한다. ABI decode/hash
단계는 미도달이므로 stdout을 검증된 ABI 성공으로 올리지 않는다. drain·출력·export·
scratch 정리·lease 해제는 정상 완료했고 원 오류와 상세 pin 연결을 보존했다. 앞선 CI 51
성공이나 로컬 `383`의 성공으로 이 실패를 대신하지 않는다. 같은 SHA의 Rust CI 61
(`38760866094`)은 이후 세 OS tests·Clippy와 집계의 성공을 관측했다. 이 job 관측과
앞선 CI 60의 실제 ZIP 감사는 구분한다.

CI 52 원 ZIP 감사도 완료했다. source/expected/PR head와 별도 event SHA
`ed8ff30f8d265e9d55eead841e97c6483016d121`, OS별 386 tests/31 reports/11 executed
tasks, 새 source helper 검사 8개와 실제 pin/receipt가 일치했다. Linux는 원 오류 뒤
별도 post-check 12개를 완료했고 post-check error는 없지만 raw candidate·summary와
ABI2 artifact가 없어 startup 성공으로 승격하지 않는다. Windows·macOS는 5,886-byte
ABI2와 stdout digest가 같고 실제 current-view fixture까지 완료했다. 세 OS의 properties
264 bytes·source inventory 177개 및 중요 source 13개의 고정 Git blob 대조가 일치했다.
원 owner·일부 JDK/JAR 원문은 미포함이며 실제 게임 calibration 실행은 여전히 미실행이다.

`826e8b7b0c7bc416de408ed6b0fb365e6e4f07a8`의 JVM CI 53 (`38763086193`)도 세 OS와
집계가 성공했고 원 ZIP 3개 감사도 마쳤다. source/expected/PR head 및 별도 event SHA
`f931e7c3d76524359da08e893885ad7b7b3037ba`, 각 OS 386 tests/31 reports/11 executed
tasks와 native 3단계·12 source pin·원 receipt 및 정상 종료·정리를 대조했다. CI 52와
JVM inventory 177개 및 selected source 54개의 경로·길이·SHA·순서가 같아 해당 입력
분석을 재사용할 수 있으나 새 실제 실행의 성공은 CI 53 원 receipt로 확인했다.
Windows DLL digest는 앞선 실행과 달라 이번 실제 bytes를 다시 hash하여 pin과
대조했고 원인은 관측되지 않아 추정하지 않는다. Linux startup은 Complete 3개·최대
sample gap 111 ms·incomplete 0이며 leader/member Pending history는 없다. 이 실행은
D062 source 정정 이전이고 Pending 양성이 없어 threads 3 전이의 회복으로 기록하지
않는다. inventory 두 개를 저장소와 supervisor의 전체 영향 입력으로 확대하지 않는다.

D062는 `linux_resources.rs`의 reserved leader에만 stable threads 3 조건을 추가한다.
기존 동일 threads 2와 모든 anchor·identity·typed errno·pidfd 조건을 유지하고 일반
member·불일치·다른 수를 거절한다. 기존 순수 검사 한 곳을 확장했으며 새 fixture는
없다. 독립 소스 리뷰 blocking finding은 0개이고 Windows `388`의 해당 파일 format과
`389`의 xtask lib 232 PASS/1 ignored 및 `390`의 package/all-target strict Clippy가
통과했다. 이 Windows 검사는 Linux 전용 모듈을 실행한 근거가 아니며 실제 Linux
검사·native 전이 회복은 후속 CI가 필요하다. WSL/Ubuntu는 사용하지 않았다. `389`는
command 0·28,216 ms, Job commit peak 453,840,896 bytes·peak process 10개·최대
표본 간격 146 ms, 소유 잔여 자식 정리 이후 drain·출력·export·scratch·lease 정상
완료이며 원 2 GiB/32 process 상한을 유지했다.

공유한 `6b60643caa19f8e9cfbadcda0b642d8ef4d1a9e4`의 JVM CI 54
(`38764462668`)도 세 OS와 집계가 성공했고 실제 ZIP 3개 감사를 마쳤다. source/expected/
PR head·별도 event SHA `5833577245a37305cd4b6876ce67b5ab46e7fa63`, OS별 386 tests와
필수 11 executed tasks, 실제 native 3단계 및 pin/receipt·정상 종료/정리가 일치했다.
JVM inventory 177개는 CI 53과 같고 selected source 54개 중 D062의 한 파일만 달랐으며
그 원 bytes를 고정 Git blob과 대조했다. Linux header witness에 전후 threads 2의
reserved leader Pending 1건이 실제 남았고 해당 phase는 정상 완료했다. 새 threads 3
조건의 실제 양성 record는 없어 그 회복 근거로 확대하지 않는다. macOS startup에도
기존 before-memory/session native ESRCH Pending 1건이 있었지만 memory/rusage exit
분기 관측으로 바꾸지 않는다. 이번 새 source bootstrap·현재 실제 결과와 이전 입력의
좁은 분석 재사용을 구분하며 실제 게임·calibration runner나 release는 미실행이다.

D061의 Rust 연결은 sealed plan의 `loaded_source_expectations()`에서 원 function ID와
logical entry bytes·digest를 빌려 주고 native resource lookup ID를 구분한다. 정본
47개 순서·고유성·원 source/hash와 함수별 64 KiB·합계 1 MiB를 검증하며 recipe 및
suite digest를 바꾸지 않는다. 독립 소스 리뷰 blocking finding은 0개이며 기존 검사
두 곳을 확장해 원 데이터 borrow·native ID 매핑·source/path/중복 변조 거절을 확인한다.
새 fixture는 없다. Windows `384`의 소유 두 파일 format과 `385`의 compiler unit
89개·compile-fail doctest 1개가 통과했고 `386`의 package/all-target strict Clippy도
exit 0이었다. `385`는 command 0·27,626 ms, Job commit peak 751,947,776 bytes·peak
process 6개·최대 표본 간격 128 ms였고 소유 잔여 자식 정리 후 drain·출력·export·
scratch·lease를 완료했다. 원 2 GiB/32 process 상한을 유지했다. 이는 비교 자료의
생산 경로이며 아직 Java 전달·실제 pack load 관측이나 실행 승인을 발급하지 않는다.

고정 `b854b617846036bcb09058ca7da3eed303a1e680`의 Rust CI 50
(`38698720838`)과 JVM CI 41 (`38698720798`)은 세 OS 및 집계가 모두 성공했다.
실제 ZIP 6개를 별도 보존하여 크기·SHA와 source/expected/PR head, 별도 event SHA
`7b9574498d7a29880d36004b4bd987d6dc1ba0b2`, 명령·raw pin 및 종료·정리 연결을
대조했다. JVM은 각 OS 7모듈 333개와 필수 11 tasks를 실제 실행했다. 이 결과는
추가 중인 현재 source나 게임 인수의 성공을 대신하지 않는다. Linux 최초 candidate
stat-open ESRCH의 실제 skip 양성은 해당 성공 자료에 없고, macOS Rust test의 실제
rusage/member Pending 1건은 start/exit 존재 bool을 보존하지만 전환 지속시간은 없다.

사용자가 계정 인증 문제로 Minecraft 클라이언트에 접속할 수 없다고 확인했다.
로그인·실제 관리자 pairing·클라이언트 시각 검증은 미실행이며, 계정 설정이나 인증
우회로 이 항목을 대체하지 않는다. 초기 Windows 서버 Ready와 정상 stop/save 로그는
앞서 기록한 범위의 관측으로 유지하고 전체 G2/G3 또는 공개 배포 완료로 표시하지 않는다.

## Calibration 승인과 intent 연결의 부분 구현

D063의 Runtime은 같은 보호 Store에 native owner의 plan 선택과 ADMIN 완료 확인을
구분해 보존하는 API 및 one-use claim을 구현했다. record와 사전 검증 seal에는 공개
역직렬화 경로가 없고, 실제 owner·정본 recipe·ADMIN/source 사실은 필수 trusted port가
검사한다. claim은 기존 Invocation·fence·operation과 같은 Immediate transaction에
들어가며 첫 durable intent에서 하나의 operation에 고정한다. 실패·취소 뒤 claim을
해제하거나 다른 operation으로 옮기지 않는다. 신규 table이 없는 기존 DB의 일반
dispatch는 기존 동작을 유지하고, 명시적 selection 등록에서만 내부 schema를 만든다.
기존 외부 SQLite/CAS/native-owner fixture로 새 검사 6개를 작성한 이유는 47개 원
claim·재시작·같은 transaction rollback·선택/확정 분리 및 원 오류와 checkpoint 오류의
동시 보존이 기존 fixture 검사에 없기 때문이다. 대형 fixture는 추가하지 않았다.

Application은 non-undo intent에서 같은 Store·operation·step·Invocation 및 원 resolution
witness를 ProviderPort의 좁은 저장 hook에 전달한다. 기본 구현은 기존 Runtime 두
함수를 그대로 호출하고 GuardedProvider는 원 admission 뒤 전달한다. registered undo는
별도 기존 claim 경로를 유지한다. 기존 검사 5개를 확장했으며 새 fixture는 없다.
Runtime 6파일과 Application/guard 5파일의 독립 소스 리뷰에서 새 blocking finding은
없었다. 실제 Composite calibration 선택, Coordinator의 native owner/ADMIN 확인
producer와 Java purpose route의 전체 검증은 이 부분 구현의 성공으로 대신하지 않는다.

Windows 관리 실행 `392`·`394`는 동결된 소유 source를 format했고 `393`은 Application
56개와 Runtime 129개 unit test가 전부 통과했다. Runtime의 새 claim 검사 6개도 실제
`ok`를 확인했다. command 0·68,844 ms, Job commit peak 751,157,248 bytes·peak process
6개·최대 표본 간격 139 ms였으며 원 2 GiB/32 process 상한과 소유 잔여 자식 정리 후
drain·완전한 출력·export·scratch 정리·lease 반환을 확인했다. 실제 Windows에서 두
test EXE가 실행됐으며 WSL/Ubuntu로 전환하지 않았다.

같은 두 package/all-target strict Clippy `395`는 표현식 경고 세 개로 exit 101이었다.
경고 억제 없이 동등 표현식으로 정리하는 중 잘못 선택한 유사 closure의 문법 오류로
`396` format과 `397` compile도 실패했다. 원 실패와 정상 drain·export·scratch·lease
기록을 보존했다. 정확한 두 closure를 복구한 `398` format 및 `399`의 같은 범위 strict
Clippy는 exit 0이었다. 동등 표현식 정리와 format 결과로 기존 테스트를 재실행한
것처럼 기록하지 않으며 현재 source의 전체 CI는 별도로 확인한다.

Application의 기존 intent 오류 뒤 진단 note 저장도 실패하면 원 오류가 대체되던 경계는
원 intent의 code/message와 두 typed cause를 보존하도록 보완했다. note 성공 때는 원
AppError를 그대로 반환한다. 기존 외부 SQLite/CAS fixture의 정확한 소유 및 plain-tree
경계를 검사하고, 비어 있는 incoming 하나에만 CreateNew blocker를 두어 실제 진단 I/O
실패와 원복을 검사했다. 새 fixture·의존성·dispatch·재시도 권한은 추가하지 않았다.
Windows 관리 실행 `404` format 및 `405`의 Application 56개 unit test가 통과했으며,
동일 실행의 두 package 명령은 exit 0이었다. 원 2 GiB/32 process 상한, Job drain·완전한
출력·export·scratch 정리·lease 반환을 확인했다. 실제 게임 runner와 issuer/readback·최초
target profile·클라이언트 및 공개 배포 인수는 미완료다.
같은 Application package의 all-target strict Clippy `406`도 exit 0이며 정상 정리를 확인했다.

공유 `6b60643`의 Rust CI 63 (`38764462975`)은 세 OS tests·strict Clippy와 집계 성공을
관측했고 원 ZIP 3개를 별도 보존했다. 앞서 감사한 JVM CI 54와 함께 이전 고정 source의
검증이며, 위 미커밋 calibration 연결의 성공으로 확대하지 않는다.

공유 `5d0409b`의 Rust CI 64 (`38777543185`)와 JVM CI 55 (`38777543213`)는 세 OS의
각 실제 작업과 집계 작업이 모두 성공한 것을 별도로 조회했다. 해당 결과는 고정된
Runtime claim·Application hook source의 CI 결과다. 이후 미커밋 Coordinator·Java 승인
연결이나 위 진단 오류 보존 보완의 CI 성공으로 재사용하지 않는다. 이 두 실행의 원 ZIP
감사는 아직 수행하지 않았다.

Java host에는 고정 normative47 plan만 받는 별도 calibration purpose 승인 route를
작성했다. 원 player ADMIN·pairing·runtime source·epoch/generation 및 30초 원 기한을
전후 검사하며, exact Complete·EOF·소유 bridge 자식 exit 0·stderr drain 뒤에만 listener를
활성화한다. 일반 read route와 `verifiedWriteProfile=false`는 유지한다. prepare는 plan을
소비하지 않으며 실제 runner가 없으면 `CALIBRATION_RUNNER_UNAVAILABLE`로 거절한다.
runner failure와 후행 현재성 오류 및 bridge output close 오류의 원인 보존 두 건은
독립 소스 리뷰로 보완을 확인했다. Coordinator publisher와 실제 execution consumer는
별도 미커밋 작업이며, Java source만으로 plan 생성·로드·실행·readback 성공을 주장하지 않는다.

공유 `b350fea`의 Windows 관리 실행 `410`은 실제 JDK/Gradle launcher digest와 원
source 174개의 전후 일치를 확인하고 필수 11개 task를 모두 실제 실행했다. Fabric
compile 및 JUnit은 32개 XML 보고서의 394개 test가 통과했고 실패·오류·skip은 0이다.
새 purpose 승인 검사는 5개이며 실패 전용 runner와 기존 47행 Harness를 재사용한 검사다.
원 XML 32개 74,325 bytes와 보고서별 digest를 증거 루트에 보존했다. 명령은 exit 0·
66,354 ms, Job commit peak 1,398,284,288 bytes·6 process·최대 표본 간격 140 ms였고
자연 종료·Job drain·완전한 출력·export·scratch 정리·lease 반환을 확인했다. 요약 digest는
`87c724ccc67981fbf4044b8190a15dfeb6c2d1c10c0d5532a8877f37a77f907e`다. 외부 실행
준비용 shell 인용 오류는 관리 실행에 도달하지 않았으며 검사 성공으로 세지 않았다.

같은 `b350fea`의 JVM CI 57 (`38781127673`)은 실제 세 OS compile/test/native 관측 및
집계 성공을 조회했고 원 ZIP 3개를 외부에 보존했다. 독립 원 ZIP 감사에서 source·expected·
PR head는 모두 같은 `b350fea`, 별도 event SHA는 `e869de78c3d8f9bd98e73aada01d1d40502c6a58`,
attempt 1이며 세 OS 각각 32 reports·394 tests·실패/오류/skip 0·필수 11 tasks executed를
대조했다. native 3단계의 process/finish/finalization 9개와 prior JVM 5개 raw hash 연결,
54개 build-source 입력 manifest·실제 native library·8개 header pin·startup 13단계와
원 source pin 12개의 전후 일치 및 정상 정리도 대조했다. ZIP에 원 XML·owner·JAR·JDK
archive가 없어 해당 원본을 독립 재hash했다고 기록하지 않는다. Linux의 ESRCH Pending은
기존 zombie threads 2 한 번이며 threads 3 양성은 없고, Windows ancestry 5 race 및
macOS memory/rusage 종료 Pending의 native 양성도 없다. Rust CI 66 (`38781127682`)은
마지막 조회에서 in_progress였으며 성공을 확인하지 않았다. 실제 player ADMIN·게임 실행·
클라이언트 검증과 공개 배포는 미완료다.

Runtime에는 `verify_calibration_intent_claim`을 추가했다. existing approval과 operation/
step claim을 명시적으로 JOIN한 뒤 원 operation·step·Invocation ID, 저장된 실제 CAS
bytes의 raw digest·길이 및 파싱한 Invocation을 대조한다. 새 schema·claim·원장이나
현재 Apply grant를 만들지 않는 사실 조회다. 기존 47-step/restart fixture와 좁은 검사로
unclaimed·다른 Store·원 Invocation 변경·claim digest 변조·원 오류와 후행 취소 병존을
확인했다. Windows 관리 실행 `412`의 Runtime 130개 unit test가 전부 통과했고 실패·
ignored는 0이다. 명령 exit 0·57,337 ms, Job commit peak 711,147,520 bytes·6 process·
최대 표본 간격 144 ms 및 소유 자식 정리 후 drain/output/export/scratch/lease 완료를
확인했다. `413`은 이 두 소유 파일만 format했고 `414` Runtime/all-target strict Clippy도
exit 0·정상 정리였다. 같은 source의 전체 Coordinator 연결 검증과 구분한다.

## Calibration 공통 계획과 실행 소비자 연결

D064의 `calibration-plan` CLI는 이미 실행 중인 Coordinator에 실제 native session으로
접속한다. 입력은 data root·project ID·expected revision·context ID의 locator 네 개이며
CLI에서 별도 plan/apply 알고리즘을 만들지 않는다. 기존 ApplicationService의 실제
Plan 요청과 유한 예산 아래 현재 owner·Project head·host context·실제 command action
descriptor와 등록 dependency pin을 확인하고 공통 `prepare_setup`/freeze로 저장한다.
새 `SetupPlanningPort`는 trusted bounded Project 읽기와 head 현재성 검사를 요구한다.
원 Project 자료는 8 MiB로 제한하며 같은 Store와 owner·원 요청의 전후 검사를 유지한다.

계획은 Rust sealed normative47의 원 명령·선행 chain·독립 readback 요구에서 투영한다.
objective/storage에서 정하는 94개 footprint locator는 선언이며 실제 게임 target이나
예약·ADMIN·관측 자료를 발급하지 않는다. 실제 scope는 기존 LocalAuthority가 검사한다.
불필요한 별도 recipe/body staging과 원장을 추가하지 않았으며 원 recipe CAS는 기존
owner 선택 단계가 생성하고 Runtime이 대조한다. host descriptor나 pin이 없으면
가상 action/profile을 만들지 않고 unavailable로 남긴다.

저장 전 실패와 저장 후 checkpoint 실패를 구분한다. 후자는 실제 plan ID/hash와
`SETUP_PLAN_COMMITTED` 및 원 typed 원인을 보존한다. private plan 교환은 최대 32개
진단 기록과 실제 session·offer digest·현재 교환의 Finished를 사용한다. 재배달 때 원
최초 completion을 보존하되 현재 delivery completion은 별도로 확인하여 이전 ACK로
새 교환을 완료하지 않는다. 정상 ACK/EOF 뒤 CLI stdout 실패에도 원 locator가 남고
자동 재시도하지 않는다. 이 경계 뒤 같은 selector로 명령을 새로 실행하면 새 plan이
생성될 수 있으므로 동일 locator의 멱등 재시도를 보장하지 않는다.

D065의 daemon·bootstrap·ProductionFactory·Composite는 같은 calibration registry를
공유한다. 실제 Runtime 승인·ADMIN private 완료·host route를 함께 보존하며 실패한
LocalAuthority 발행은 admission으로 사용하지 않는다. 소비자는 현재 들어온 실제
RequestContextWitness와 새 owner 관측으로 같은 Store·원 operation/plan/recipe·현재
Project/Policy·scope·grant·private generation을 검사한다. 원 bootstrap budget을 재사용하지
않고 일치하지만 무효인 calibration을 일반 action 경로로 fallback하지 않는다.

intent 저장은 실제 private prepare readiness를 전후 검사한 뒤 기존 Runtime의 원
Invocation transaction을 사용한다. transaction 안에서는 로컬 owner/grant/request와
claim만 검사하며 host RPC를 넣지 않는다. commit이 완료되면 성공을 그대로 반환하고
후속 dispatch의 현재성 오류를 intent 거절로 바꾸지 않는다. private route는 원 read
owner/lease를 확인하며 일반 route map과 grant를 보존한다. 원 attempt key/digest는
최초 dispatch 시 소비 전에 기록하고 재시도로 다른 원문을 전송하지 않는다.

획득한 실제 host 응답은 후행 취소·source 검사보다 먼저 기존 CAS evidence에 보존한다.
positive/negative 응답과 후행 오류, 원 runner 실패와 후행 현재성 실패 및 evidence I/O
실패를 typed 원인으로 남긴다. 실제 runner·capture/preconditions·독립 readback producer가
없으면 해당 unavailable 오류를 반환하며 빈 관측이나 profile 승인으로 대체하지 않는다.
Java purpose 승인 route가 존재하는 것과 실제 관리자·47개 실행·profile 인수는 구분한다.

독립 소스 리뷰로 registry/Runtime claim·공통 creator·CLI/session 전송·Composite route의
현재성, commit 이후 상태와 오류 보존을 확인하고 지적된 경계를 보완했다. 기존 소유
SQLite/CAS·Application/loopback fixture를 재사용했다. 새 Application 검사 하나는 저장
전후 실패 8개 조합과 원 locator/이중 원인 보존을, host 검사 두 개는 응답 후 취소와
prepare 실패 후 source 철회를 실제 경로로 확인하기 위해 추가했다. 새 대형 fixture는 없다.

Windows 관리 실행 `418`은 기존 native catalog 테스트의 DaemonHandles 구성에 새
registry field가 빠져 compile에서 실패했고 test는 실행되지 않았다. 해당 기존 fixture의
구성 한 곳을 보완했다. `419`의 동일 CLI/Application/Coordinator unit·bin 검사는 각각
16/57/359 PASS, Coordinator의 기존 1 ignored였으며 실패는 0이다. 실제 추가 host 두
검사와 setup·projection·현재 delivery 검사가 포함된다. command 0·169,826 ms, Job
commit peak 1,424,076,800 bytes·peak process 6개·최대 표본 간격 148 ms였다. 원
2 GiB/32 process 상한과 소유 잔여 자식 정리 뒤 drain·완전한 출력·export·scratch 정리·
lease 해제를 확인했다. 원 compile 실패 증거도 보존했다. WSL/Ubuntu는 사용하지 않았다.

`420` strict Clippy는 Boolean 표현식 두 곳, 후속 `422`는 테스트의 중첩 if 한 곳에서
실패했다. 경고 억제 없이 동등 조건식으로 정리했고 `421`·`423`은 해당 소유 파일만
format했다. 원 실패와 정상 drain/export/scratch/lease 기록을 보존한다. 이 표현식·format
정리 뒤 `419` 테스트를 재실행한 것으로 표시하지 않는다. `424`의 동일 세 package/
all-target strict Clippy는 exit 0·27,506 ms, Job commit peak 857,006,080 bytes·peak
process 7개·최대 표본 간격 120 ms였다. 자연 종료·drain/output/export/scratch/lease가
정상 완료됐다. 현재 source의 전체 CI는 이 로컬 검사와 별도로 확인한다.

## 실제 게임 API와 부분 관측 producer

private program manifest에는 Rust sealed getter의 `commands`, `preseedEndIndex`,
`selectedCommandStageIndex`, `initializationCommands`, `cleanupCommands`를 추가했다.
원 comments/LF를 포함한 source bytes는 그대로 유지하고 Java에서 body를 다시 해석하지
않는다. Rust는 47개 원 순서와 source·명령·단계·주소·init/cleanup 전체를 정본과 대조하며
Java는 닫힌 field·정수·명령 수/UTF-8 byte 범위와 immutable 입력을 검사한다. 기존
4096-node/1 MiB frame 한도는 바꾸지 않았다. 독립 source review finding은 0개다.
Windows 관리 실행 `428` format·`429`의 해당 Rust 검사 3개가 통과했다. `429`는 exit 0·
55,539 ms, Job commit peak 1,420,500,992 bytes·6 process·최대 표본 간격 145 ms였다.
소유 잔여 빌드 자식 정리 뒤 drain/output/export/scratch/lease가 정상 완료됐다. 이후
full-frame fixture의 read/write footprint를 실제 두 locator 형상으로 보완했으며 해당
보완의 새 실행 결과와 Java 검사는 별도로 확인한다.

Windows `427`·`430`은 초기 개발 서버 자료에서 실제 사용 경로가 확인된 공식 bundle만
읽기 전용으로 조사했다. 원 `server.jar` 62,294,556 bytes·SHA-256
`d052f14d7a173734fba553711e5b570162e2f2a313267ee31a21b975a679be64`와 complete owner·
retained lease 부재를 전후 검사했다. 실제 nested game JAR는 26,652,008 bytes·SHA-256
`a362163eec5d1612d520772bc16e5b39c09e3b234fdc045f56bf544284ee8ae6`, Brigadier 1.3.11은
80,151 bytes·SHA-256 `9d09cf4819de83dfcd38bcb212d5f2227131791cef3abbfca3321d6fb2b9a64d`다.
관리 scratch의 제한된 추출과 JDK 25 javap로 각각 29개/18개 실제 class API를 확인했다.
원 게임 자료 변경·서버나 installer/game main 실행은 없었다. 경계는 협조적 path metadata와
held Read stream이며 final path/file ID/hardlink 동등성을 증명했다고 확대하지 않는다.
선행 `426`은 helper script scope 초기화 오류로 분석 전에 실패했으며 원 실패·정상 정리를
보존했다. 별도 실행 준비 인용 오류도 관리 실행에 도달하지 않았고 JDK/SAC 실패가 아니다.

실제 native 함수 parser는 `BuildContexts.Unbound(String, ContextChain)`를 생성한다.
현재 constructor RETURN mixin과 `NativeCalibrationFunctions`는 정확한 vanilla entry와
PlainTextFunction class, actual 등록 Identifier·entry 순서·원 constructor 입력 및 chain
참조만 관측한다. manager/pack/winner/function 현재성과 원 파일 bytes 재관측을 구분하고
원 callback은 보관하지 않는다. 이는 chain 내부 input·완전 소비·selected node·실제 실행
증거가 아니다. actual runtime Mixin 적중도 아직 확인하지 않았다.

선택 executable collector는 actual receiver/reflect Method를 D059 actual Class view와
대조하며 ordinary virtual/상속/erased bridge와 native matcher가 지원하는 zero-capture
static hidden forwarder만 다룬다. actual loader·issuer/class/generation·method descriptor/
modifiers/code kind를 검사하고 256 selection·64 Class·8 MiB retained payload를 제한한다.
이는 `current_vm_executable` 사실 역할이며 SourceAdmission이나 profile을 발급하지 않는다.
captured/virtual hidden recipe의 미지원 경계와 실제 JNI 양성 미실행을 유지한다.

fixed-address state reader는 실제 server/현재 level/owner/context/원 Control 아래 기존
score와 cached storage의 고정 `inputs`·`invocation` 값만 읽는다. 전체 cached key를 4096개
한도 안에서 확인한 뒤 get하며, 미관측 namespace를 load하거나 score를 생성하지 않는다.
원 int·Float raw bits·부재/unknown 및 stale 원자료를 보존하고 success/seeded/command return을
기대값에서 만들지 않는다. 추가 소스 리뷰의 현재 level identity와 초기 context 오류 보존
지적을 보완했고 동일 reviewer의 재검토에서 모두 해소됐다. 실제 compilation·fixture
실행·게임 관측은 별도 결과로 기록한다.

실제 430 API에서 `BuildContexts`는 CustomModifierExecutor/CustomCommandExecutor 경로도
갖는다. ExecuteCommand-only hook을 모든 명령의 실행으로 일반화하지 않는다. native queue는
quota/overflow 때 정상 반환할 수 있어 drain 반환도 전체 entry 완료 증거가 아니다. 실제
stage/preseed/selected return·v3 issuer·독립 readback consumer는 후속 연결 중이며 이 부분
관측 producer만으로 dispatch를 활성화하지 않는다.

`3b74916c605c5d1711a35f6ad1329c27f74ece6a`를 공유한 Windows 관리 JVM `433`은 원
source 181개와 JDK/Gradle pin의 전후 일치를 확인했다. production Fabric compile은
실제 통과했지만 새 state reader 테스트의 제거 예정 NBT 생성자 6곳이 Werror로 거절돼
Fabric unit test에는 도달하지 않았다. 명령 exit 1·39,284 ms, Job commit peak
1,429,372,928 bytes·6 process·최대 sample gap 134 ms이고 자연 종료·drain·완전한 출력·
export·scratch 정리·lease 해제는 정상이다. Gradle task 10개가 실제 실행된 부분 결과이며
11개 필수 작업 전체 성공이나 새 테스트 통과로 표시하지 않는다.

후속 관리 `434`는 같은 원 JAR/owner 경계를 재대조하고 실제 NBT API 7개를 읽었다.
FloatTag의 factory뿐 아니라 TYPE.load도 readFloat 뒤 valueOf를 호출해 음수 0을 양수 0으로
정규화한다. streaming visitor의 primitive 전달은 FloatTag 생성과 구분한다. 명령 exit 0·
6,155 ms, Job commit peak 174,866,432 bytes·4 process이며 정상 drain/export/scratch/lease를
확인했다. 원 stdout 71,205 bytes·SHA-256
`6dd4a1445a50cd5d39497fab30022afb00933e055a9b311ffe0a307d684f6f74`를 보존했다.
D067에 따라 normal Int/Byte/NaN 다섯 입력은 factory로 고치고 raw negative-zero 한 입력의
local 변수에만 근거를 적은 removal 경고 예외를 뒀다. 원 bits와 NaN payload 기대값은
유지하며 실제 getter의 관측 계약을 검사한다. production reader는 변경하지 않았다.
소스 리뷰와 이후 새 JVM 실행 결과는 구분한다.

후속 Windows 관리 JVM `435`는 고정 source
`47a11eaef7f718bf84e360104763e2b64fd690fd`의 7개 모듈 404 tests/34 reports와 필수
11개 Gradle task 실제 실행을 모두 통과했다. 원 source 181개를 실행 전후 대조했고
source-input manifest SHA-256은
`b7e058c9fc8b9c5b16f06b2c53987fc7b0463b8e748df4fcbf92b644138f6948`다.
새 approval 6개·executable 5개·state reader 4개 테스트가 포함되며 실제 Mixin 주입·JNI
positive 실행·게임 stage runner나 관리자 승인을 검증한 것으로 확대하지 않는다.
명령 exit 0·43,635 ms, Job commit peak 1,404,518,400 bytes·6 process·최대 sample gap
147 ms이며 자연 종료·drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다.
원 JUnit XML 34개를 외부 evidence에 CreateNew/flush/hash 대조하여 보존했고,
요약 12,109 bytes·SHA-256
`4a11453d72529f98a3c3af756451525a1d85c6d6dca52fa9841bfcfd4d4a1057`를 기록했다.
실패한 `433` 원 근거를 대체하거나 현재 개발 자료를 최종 출시 증거로 승격하지 않는다.

## 수동 교환 native ingress와 현재 회귀

D068의 `manual-import`는 원 FN24 selection을 가진 현재 native owner, 실제 선택 파일과
명시적 static delta를 같은 Coordinator/Store의 기존 diff·stable patch·scene planner에
연결한다. SourceMap과 편집 payload의 원 bytes 및 정본 patch를 private CAS에 보존하며
Project head와 권리 상태를 변경하지 않는다. 불투명한 생산 admission만 원 protected
product와 현재 CAS를 재검사한 뒤 call-local source map에 연결한다. 일반 resource 읽기
순서와 권한, 실제 sealed bake 없는 clip 부착 거절을 유지한다. 같은 offer의 Busy,
ACK/EOF/stdout 및 후행 checkpoint 실패에는 원 locator와 원인을 보존한다.

Windows 관리 `436`은 소유 Rust 17파일 format을 통과했다. `437`은 컴파일·CLI 16개와
Coordinator 362개 통과/새 회귀 2개 실패/기존 1 ignored다. 당시 full normative manifest
fixture는 실제 466,350 bytes/3939 nodes로 기존 1 MiB/4096 한도 안임을 관측했다.
실패한 parser fixture는 managed scratch의 verbatim 경로 표현과 충돌했고, catalog fixture는
필수 mod/pack source 집합을 unknown으로 제공했다. production 거절 조건은 유지하고 두
fixture만 교정하여 `440`에서 format을 통과했다. `441`의 Runtime 131개 unit은 모두 통과했다.
새 단일 registration diagnostic 알고리즘의 실제 schema/CAS/SQLite 실패 원인과 기존 공개
오류 동일성 검사가 포함된다.

`442`의 수동 교환 집중 검사 6개는 5개 통과/1개 실패다. parser·tokenless transport·기존
manual codec/bundle 회귀는 통과했고 실제 FN24→파일 import→CAS 보존→Project/head 불변을
확인한 새 회귀는 후속 scene.plan에서 예상한 CONTEXT_UNKNOWN 대신 REVISION_CONFLICT를
반환했다. 충돌 원인을 추적 중이며 expected code를 낮춰 통과시키거나 실제 게임 또는
EX14 전체 인수 성공으로 표시하지 않는다. 마지막 두 실행은 각각 command 0/101·
47,996/76,552 ms, Job commit peak 708,636,672/1,473,343,488 bytes·6 process다.
원 로그·실패를 보존했고 owned-tail 정리 뒤 drain·완전한 출력·export·scratch 정리·
lease 해제를 확인했다. 이 source의 strict Clippy와 새 고정 SHA CI는 아직 미실행이다.

후속 source 수정은 원 `load_owned` cache와 selected JSON 문서 전체의 JCS digest를 비교하여
정수/실수 표현 차이가 revision 충돌을 만들지 않게 했다. FN24의 선행 `verify_owned`도
같은 비교를 사용한다. 원 schema·identity·self-digest와 Project revision pin 검사는
유지하며 typed 재직렬화나 원 CAS·raw SHA·pin 재작성은 하지 않는다. protected authored
manual record만 실제 세 번째
payload를 SceneSource에 공급하고, 현재 principal/Project/context의 정확한 세 issued pin을
다시 검사한다. planner는 그 실제 CAS bytes를 기존 누적 예산으로 읽고 정규 `/entries/N`,
qualified instance/node/kind·명시적 delta·map output resource를 대조한다. legacy producer는
기존 source 형식을 유지하고 새 payload를 임의로 발급하지 못한다. 공통 planner의 원
AppError cause도 서비스 경계에 보존한다.

수정한 7파일은 `445`에서 format을 통과했고 `446`의 planner unit 38개가 통과했다.
command exit 0·42,423 ms, Job commit peak 597,176,320 bytes·6 process·최대 sample gap
145 ms이며 owned-tail 정리 뒤 drain·완전한 출력·export·scratch 정리·lease 해제를
확인했다. 당시 원 FN24 native 통합 회귀의 수정 후 로컬 재실행은 미실행이었고 이후
calibration Rust source와 함께 동결해 `463`에서 통과했다. 이전 `442` 실패를
소급해 성공으로 표시하지 않는다.

최종 비교 교정은 기존 FN24 통합 fixture의 실제 stored 정수 `0` 한 곳을 selection에서
`0.0`으로 표현하고 전체 JCS digest·원 revision의 동일성을 확인한다. `455`의 세 파일
format과 `456`의 planner 38개 unit이 통과했다. 후자는 command 0·33,702 ms·Job commit
peak 597,020,672 bytes·6 process·최대 gap 150 ms이며 owned-tail 정리 뒤 drain·완전한
출력·export·scratch 정리·lease 해제를 확인했다. 당시 새 FN24 통합 회귀 자체의 수정 후
재실행은 미실행이었으며 후속 `463`의 실제 통합 통과와 planner unit 통과를 구분한다.

## 공통 Invocation reservation 집중 검증

D069는 기존 NativePlanApproval의 sticky 상태만 권한 중립 primitive로 분리하며 일반
resource ACL을 유지한다. 독립 source 리뷰에서 inspect와 insert 사이 만료 P2를 발견해
최초 insert 직전에 원 Clock/expiry를 다시 검사했고 재리뷰에서 해소했다. 외부 Candidate,
stale generation, 원 Invocation 재바인딩과 ACL 실패는 새 claim을 만들지 않으며 정확한
historical nonwrite 조회는 기존 동작을 유지한다.

Windows 관리 JVM `444`는 source base `bf0f253b5d0dcdaa2208637a6959bd6dacc2fb6b`와
수정된 host-core 3파일을 구분해 검증했다. 고정 전체 SHA의 clean checkout 검사가 아니다.
선택한 SDK/host-core·계약/예제·Gradle 설정 입력 94개의 전후 pin이 같았고 input manifest
SHA-256은 `f543b4b0caea700cfd38d5a7584e3a1c324bc226c57a7428add69dd04d3bdf05`다.
두 필수 Gradle test task가 실제 실행되어 SDK 108개·host-core 96개가 통과했으며 XML
14개를 CreateNew/flush/hash 대조하여 외부 evidence에 보존했다. command exit 0·22,191 ms,
Job commit peak 1,192,431,616 bytes·6 process·최대 sample gap 148 ms이며 자연 종료·
drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다. 요약 6,551 bytes·SHA-256은
`f73038d7d668db68aaccd075159d39826f3ee82db8f90513601fa9a1fa61d9c3`다.
작성 중인 Fabric 승인 binding·full image·실제 runner/Source3는 이 집중 검사의 입력이나
성공 범위에 포함하지 않는다. 전체 JVM 및 게임 검증은 조합 source 동결 뒤 별도다.

## Darwin member의 불완전 자원 관측

D070은 원 nonleader의 TaskInfo 0/ESRCH 뒤 실제 BSD 0/ESRCH가 나온 경우에만 deferred
candidate를 만들고, 캡처한 원 순회의 leader를 마지막에 처리하여 실제 held/unreaped
anchor를 대조한 뒤 Pending으로 받는다. 이전 owned scope의 실제 Complete, 원 100ms
시도와 1000ms 창·상한을 유지한다. PID/UID/PGID/birth latch는 최대 33개이며 다른 SID나
identity를 새 member로 받아들이지 않는다. membership/NotDue만으로 해소하지 않고,
늦은 Complete는 count/peak/last-success 수정 전에 거절한다. Mac 정상 reap에도 fence를
연결했다. 후속 identity가 불완전한 memory는 owned 합계에 넣지 않으며 원 native 오류와
나중의 admission anchor를 별도 사실로 남긴다.

독립 source 리뷰와 Root `448`의 두 Rust 파일 format을 거쳐 `449` Windows Python
AST/mock 검사가 통과했다. 정확한 missing 조건·거절 13개·latch drift 9개·해소 3개·부분
예산 4개와 cadence/reap/오류 보존을 검사했으며 native_execution=false다. `450`의 도구
lib 235개·bin 4개가 통과했고 기존 isolated 1개는 ignored다. `451`의 같은 도구
all-targets strict Clippy도 통과했다. 명령 exit는 모두 0이며 `450`은 32,339 ms·Job
commit peak 491,098,112 bytes·10 process·최대 sample gap 150 ms, `451`은 4,805 ms·
358,440,960 bytes·7 process다. 전자는 owned-tail 정리 뒤, 후자는 자연 종료 뒤 drain·
완전한 출력·export·scratch 정리·lease 해제를 확인했다. 실제 macOS 전이·회복은 미관측이며
새 supervisor를 로컬 관리 parent로 교체한 검사도 아니다. 후속 고정 source CI와 구분한다.

## Linux JVM owned member의 정확한 Z4 Pending

D071은 실제 CI62에서 거절된 stable Zombie·threads 4 owned member를 기존 유한 Pending
조건에 포함한다. 원 full identity·같은 전후 count·RSS open ESRCH·실제 validated pidfd의
NotReady/errno 없음·held original leader와 최종 leader 검사를 유지한다. member 2 또는 4,
leader 기존 2 또는 3만 허용하며 다른 count·상태·오류는 거절한다. 새 query·retry·sleep·
한도 변경 없이 원 prior Complete·100ms·1000ms·부분 사용량·late Complete·reap fence를
그대로 사용한다. 미관측 RSS는 None이며 종료·0·Complete·empty·drain 성공으로 바꾸지 않는다.

독립 source 리뷰, `462/466` format 후 `468` Windows 도구 lib 235개·bin 4개가 통과했고
기존 isolated 1개는 ignored다. 기존 pure matrix에 stable Z4와 거절 조건을 확장했으며 실제
Linux native 회복 검사가 아니다. command 0·39,954 ms·Job commit peak 455,847,936 bytes·
10 process·최대 gap 150 ms이며 owned-tail 정리 후 drain·완전한 출력·export·scratch 정리·
lease 해제를 확인했다. 실제 CI62의 793 samples·과거 maximum gap 167ms는 실패 순간 age나
새 조건의 Pending 진입/회복을 증명하지 않는다. 수정 후 actual Linux 관측은 별도다.

## Full-target 이미지와 실제 native calibration 생산·소비 경계

D072의 Java 생산 경로는 actual function constructor 입력·stored chain·선택 node와 현재
VM executable을 읽고 실제 원 function invocation을 같은 native queue로 실행한다.
standard/custom handler·frame callback·command callback·queue 완료를 구분하며 scope 종료,
quota/overflow·두 queue·source 재관측·whole before/after 검사를 모두 통과한 private
CompletedRun만 immutable Source3를 만든다. 일반 command의 single-callback 계약은
유지하고 전용 action은 실제 callback 수와 nullable return을 보존한다. 호스트에 caller의
Rust CAS ref 또는 readback digest를 완료 사실로 돌려주는 경로는 없다.

전체 objective/owned-storage 이미지는 기존 native read 알고리즘을 재사용하고 Float/Double
원 비트 sidecar를 함께 보존한다. uncached namespace는 unknown이며 read/ready에서
load·초기화하지 않는다. Rust는 typed target binding, 원 NBT와 raw-bit 관계·native UTF-16,
실제 List writer/loader의 한 겹 wrapper를 검사한다. NBT 64 KiB·image 256 KiB·pair 512 KiB와
RPC 1 MiB/depth 64/4096 nodes는 그대로다. List의 물리 wrapper 비용만 별도 derived
128-depth/32768-node 상한으로 읽고 해제 후 actual tree의 원 64/16384를 다시 검사한다.

private manifest는 `/2`와 exact 두 targetBindings를 사용하고 원 47-step metadata 및
94개 full-target precondition을 유지한다. 각 step은 자기 두 조건만 투영한다. 같은 Runtime
intent/claim 전에 실제 fresh prepare와 retained before를 대조하고, dispatch 후 원 durable
claim에 결합한 Source3를 확인한 뒤 별도 fresh native state를 읽는다. 실제 HostResponse를
기존 operation evidence에 보존하고 DirectChange는 원 RecoverySnapshot 흐름에 전달한다.
원 Invocation blob의 raw SHA와 Source3의 canonical Invocation digest를 구분한다.

Java 25파일과 Rust 12파일은 독립 source 리뷰 후 동결했다. Method join·event role 및 단일
outcome·성공 case의 실제 selected return 존재에 관한 세 P2를 수정하고 재리뷰했다. `458`의
Rust format은 통과했으나 `459`는 누락 import 두 곳으로 compile 실패하여 unit은 미도달이다.
두 import만 추가해 `462` format을 통과한 뒤 통합 재검사한다. 고정 Java `2e13846`의
Windows `461` full JVM은 선택 입력 193개 전후 pin 일치·manifest SHA-256
`1bd68ec848ee427d0d409fa78fcd741240dc1ef94963206e624bc16719039c83`를 보존했다.
Gradle 31 task가 실행됐으나 InterruptedTrace의 nonserializable 필드 경고 네 개가 Werror로
거절돼 Fabric unit은 미도달이다. command 1·58,919 ms·Job commit peak 1,376,202,752 bytes·
6 process·최대 gap 150 ms이며 drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다.

`463`은 CLI 16개·Coordinator 368개·Runtime 131개, 합계 515개 unit을 통과했고 기존 isolated
1개는 ignored다. FN24 native 통합 회귀도 CONTEXT_UNKNOWN 기대값을 유지해 통과했다.
새 manifest full-frame fixture의 기존 1 MiB/4096-node 검사도 통과했으며 수치 출력은
캡처되어 이 기록에 새 bytes/nodes 값을 추정하지 않는다. command 0·232,433 ms·Job
commit peak 1,557,188,608 bytes·7 process·최대 gap 150 ms이며 owned-tail 정리 후 drain·
완전한 출력·export·scratch 정리·lease 해제를 확인했다. 이후 unused method 1개 제거와
test-only helper의 cfg(test) 격리를 수행했다. `469` strict는 중첩 if 두 곳으로 거절돼
조건·오류를 유지한 let-chain으로 정리하고 `470` format을 통과했다.

`471`은 base `148b2af`와 실제 수정 Rust 15개를 구분한 집중 검사다. 입력 전후 pin이 같고
manifest SHA-256은 `8635c51bf99a59377b7bad9203e8124286feec3c48fdd93b386fd36454b34512`다.
native backend 12개와 원 authority frame 1개가 통과했다. 후자는 실제 **467,199 bytes/
3400 nodes**로 기존 1 MiB/4096 안임을 출력했다. 기존 437의 466,350/3939 값과 다른 source
이며 어느 쪽도 게임 실행 자료가 아니다. 뒤 all-target strict는 test의 clone 두 곳에서
거절돼 해당 두 줄만 from_ref로 정리했다. test 0/0과 Clippy 101을 한 성공으로 합치지 않는다.
관리 command 101·107,088 ms·Job commit peak 1,548,099,584 bytes·9 process·최대 gap 149 ms,
owned-tail 정리 후 drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다. 기존
집중 test는 이 동등 교정 뒤 반복하지 않으며 format 후 strict만 별도 재검사한다.

`472` format 후 `473`은 Runtime·Coordinator·CLI·Planner·도구 5 package의 all-targets
strict Clippy를 통과했다. 입력 base와 수정 15개를 구분하고 개별 목록을 원 stdout에
보존했으며 전후 manifest SHA-256은
`ca9cc1867484e45b8f2e9a58bd2e4224f34a6cb07b7da82d9b250d6ce7d3e84c`로 같았다. command 0·
31,402 ms·Job commit peak 957,550,592 bytes·8 process·최대 gap 142 ms이며 자연 종료 뒤
drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다. 이는 이전 test의 재실행이나
전체 clean checkout CI 성공을 뜻하지 않는다.

Java `ff83cca`는 앞선 InterruptedTrace 네 필드만 transient로 바꿔 원 JVM 안의 진단과
불변 사실을 유지한다. `464`는 그 경고 해소 후 미참조 try resource 경고 한 곳으로
Fabric compile이 다시 거절됐다. 입력 193개 전후 pin은 같았고 manifest SHA-256은
`5f2ce3b12d43b31af348fa543531fed8298609b771c9a1a42930b7f47b9566cd`다. command 1·
56,454 ms·Job commit peak 1,377,497,088 bytes·6 process·최대 gap 148 ms이며 drain·완전한
출력·export·scratch 정리·lease 해제를 확인했다. `148b2af`는 Runner 한 곳과 같은 형태의
test 네 곳의 resource 선언만 옮겨 원 try-with-resources close·primary/suppressed 순서를
유지했다. 독립 재검토 뒤 full JVM을 재검사하며 이전 실패를 소급해 성공으로 표시하지
않는다. 실제 Java serialization 지원도 주장하지 않는다.

고정 `148b2afdf9f3175aee894e6863735bf17df084ab`의 `467`은 전체 JVM 7모듈 411개를
통과했다. SDK 108·host-core 96·public adapter 29·Fabric 125·observer 24·legacy 18·provider
11개이며 실패·오류·skip은 0이다. 필수 11 task가 모두 실제 실행됐고 JUnit XML 36개를
별도로 CreateNew/flush/hash 대조해 보존했다. 입력 193개 전후 pin 일치·manifest SHA-256은
`e52e768135790e74e9b9df03c6e8bc82b50022b5f188a3e8dc953dacb75bb95b`다. command 0·
63,541 ms·Job commit peak 1,454,309,376 bytes·6 process·최대 gap 146 ms이며 자연 종료 뒤
drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다. 요약 12,594 bytes·SHA-256은
`987226e45661205c0d9d49c941996f8af00522a4e287e94d648fd11d4c190d26`다. 실제 Mixin 적중·
native observer/JNI positive·게임 실행을 이 단위 및 컴파일 검사에 포함하지 않는다.

Windows API `465`는 같은 중지 서버의 원 JAR에서 13개 실제 class를 javap로 관측했다.
실제 저장 타입은 SavedDataStorage이고 후보 DimensionDataStorage는 ZIP에 없어 읽지
않았다. helper 준비의 문자열 치환 오류는 관리 실행 전 preflight_failure로 보존하고
Parser 0-error 확인 후 한 번 실행했다. 원 JAR·owner의 전후 pin이 같고 command 0·
22,319 ms·Job commit peak 184,864,768 bytes·4 process·최대 gap 125 ms, stdout 312,816
bytes·SHA-256 `6e7a22e32704d76a9d68e3b81d1fec50efd874f0913d2f5066d343977ed0ab3b`·stderr 0이다.
정확한 개발 output-root에서 drain·완전한 출력·export·scratch 정리·lease 해제를 확인했다.
이는 API 본문 관측이며 실제 SavedData load/save·팩 설치·reload 또는 게임 실행은 아니다.
SavedDataStorage의 기존 disk read는 unlimitedHeap·DFU·partial/null 오류 소비를 포함하고,
쓰기 전에 dirty를 해제하며 IO 실패를 로그로 소비할 수 있다. 일반 get/null/save future를
유한 취득·확정 부재·영속 쓰기 증거로 사용하지 않는다. FolderRepositorySource 재검색도
디렉터리 생성과 오류 소비를 포함한다. 실제 producer는 원 파일·현재 권한·bounded input·
독립 후행 사실을 보존해야 하며 단순 API 호출로 이 경계를 완화하지 않는다.

실제 Mixin callsite·47개 게임 실행·실제 Source3 용량 적합성·새 profile admission은
아직 미검증이다. Pack 설치·owned storage 초기화·reload·새 pairing은 별도 실제 operation이
필요하며 이 구현의 read/ready가 대신하지 않는다. 실제 animation evidence와 Clip→Pack
생산 연결, client 시각 인수와 공개 배포도 미완료다.

Static Owned Pack의 생산 경로는 실제 SceneDraft가 cover한 object ID 대신 빈 집합을 넘기는
오류를 별도 두 파일에서 교정했다. sealed `covered_owned_sources()`의 실제 ID만 같은
PackBuildInputs에 전달하며 Project catalog 전체를 성공 flag로 복사하지 않는다. 원
SceneRegistryVerifier·Clip/Physics 거절과 downstream exact kind/object/revision·Project·
target/compiler pin을 유지한다. 기존 block_scene fixture를 재사용한 정적 성공과 missing·
extra·stale 거절 회귀를 작성하고 독립 리뷰/`466` format 뒤 `471`의 focused 12개에서
통과했다. 이는 정적 소비자 연결 검증이며 actual scene/animation evidence 발급 또는
게임 인수로 확대하지 않는다.

## cached storage 부재 관측과 실제 JVM 검사

후속 cache-only source는 실제 `CommandStorage.namespaces`와 Container의 `storage` map을
두 read accessor로 관측한다. 실제 cached namespace 안의 key 부재만 기존 full image의
storagePresent=false/양 subtree absent/null로 발급하며 namespace 미관측은 unknown이다.
get/getContainer·SavedData load·dirty·새 CompoundTag를 사용하지 않는다. 원 callback을
보관하지 않고 실제 map/container/root identity와 원 control을 전후 확인하며, namespace
4096개·전체 cached key 합계 4096개를 끝까지 검사한다. 일반 NativeTargets는 조기 일치 후
검사 중단만 제거했으며 일반 knownness와 ACL·wire를 확장하지 않는다.

Rust calibration validator는 bool 타입을 유지하고 false이면 양 subtree 부재/null과 top
absence를 요구한다. 원 false/true·bytes·digest 차이와 unknown/full-scope·source pin 검사를
유지한다. `475` format 뒤 base `021ad5a`+수정 Rust 두 파일을 구분한 `476`에서 기존
집중 회귀 1개와 Coordinator all-target strict Clippy가 통과했다. 전후 manifest SHA-256은
`b49b6b09c695b929534c11842294134a65053a5a84ea541a059c27ffdf4153e6`로 같으며 개별 목록도
보존했다. command 0·83,315 ms·Job commit peak 1,550,729,216 bytes·9 process·최대 gap
148 ms이며 owned-tail 정리 후 drain·완전한 출력·export·scratch 정리·lease 해제다.
독립 source 리뷰 후 Java 9파일을 동결했고 Rust와 동일 shape도 대조했다. `477`의
staged 12파일 repository/diff 검사 뒤 고정 `773dadd1eda519ed88762054c7126229f19b61f3`의
`478`에서 전체 JVM 7모듈 411개·36 XML·필수 11 executed task가 통과했다. 실패·오류·skip은
0이다. 입력 196개의 전후 manifest SHA-256은
`b9fd9eb7f903a62b7edd2181a4d59c01a1efd042e1a4c8fdb477802485d4ff2f`로 같고 원 XML을 별도
보존했다. summary 12,594 bytes·SHA-256은
`fdbb977e848016d9d15b54edac83e16c9e270055d755e674206d9ba9ce5451cf`다. command 0·62,432 ms·
Job commit peak 1,379,459,072 bytes·6 process·최대 gap 137 ms이며 자연 종료·drain·완전한
출력·export·scratch 정리·lease 해제를 확인했다. 새 Java의 컴파일·단위 검사와 실제 게임의
Mixin 적용·cache 관측을 구분하며 후자는 아직 미실행이다.

## 공유 고정 SHA의 CI 실패 구분

추가 Windows API 관측 `438`은 Brigadier/native custom 실행 interface 10개,
`439`는 DoubleTag 1개를 각각 원 JAR과 고정 JDK의 javap로 확인했다. 두 실행은 command
0·stderr 0, 각각 7,951/3,977 ms와 Job commit peak 177,094,656/171,249,664 bytes·
4 process이며 drain·완전한 출력·export·scratch 정리·lease 해제가 정상이다. 원 stdout은
65,443 bytes·SHA-256 `291ced3084b2b97d556fe2891929ca74336959361dfe2f3c3e93622cdf6f4163`,
9,335 bytes·SHA-256 `472b0bd09ee9a7a132b2a82da110f881df810ed5928400acf204acb257d658c7`다.
실제 getter·SAM descriptor·custom 경로와 queue overflow의 한계를 확인한 근거이며
게임 실행·완료 stage나 복원 성공의 증거가 아니다.

이 조사에서 `430/434/438/439`의 outer 명령이 output-root를 누락해 제품 기본 루트 아래
별도의 `build/managed-v1` catalog를 사용한 오류를 확인했다. 고정 개발 catalog와 동일한
크기 관측 또는 지정 개발 루트 준수로 보고하지 않는다. 정확한 checks/jvm owner 두 개는
원 checkout·purpose와 일치하고 complete이며 lease·scratch가 없는 상태를 확인했다.
원 evidence와 완료 cache는 보존했고 다른 자료를 삭제하거나 이동하지 않았다. 후속 실행은
지정 개발 output-root를 명시한다. 이 실수는 제품 SQLite/CAS의 수명 또는 중단 lease를
자동으로 회수하는 예외를 만들지 않는다.

후속 고정 source `47a11eaef7f718bf84e360104763e2b64fd690fd`의 JVM CI 61
(`38792722101`)과 Rust CI 70 (`38792722276`)는 각각 Windows x64/Linux x64/macOS
ARM64 세 job 및 집계 성공을 관측했다. Rust 70의 macOS bootstrap 성공은 이 실행의
실제 결과이며 선행 68의 ESRCH가 재현됐거나 그 실패 정책이 이미 보완됐다는 증거는 아니다.
두 실행의 새 원 ZIP 감사는 수행하지 않았다. 이후 미커밋 구현과 게임 및 공개 배포를
이 고정 SHA의 검사 성공에 포함하지 않는다.

`54af8a8708d399b3e7044f036828bdd0e40219b1`의 JVM CI 59 (`38787591379`)는 세 OS와
집계 성공을 관측했다. 원 ZIP 감사는 선행 고정 source의 CI 57과 구분하며 이번 원본은
아직 감사하지 않았다. 같은 SHA의 Rust CI 68 (`38787591397`)은 Windows·Linux의 모든
단계가 성공했지만 macOS bootstrap과 집계가 실패했다. macOS repo/fmt/test/lint는 skipped다.
원 ZIP 3336 bytes·SHA-256 `dbe4ee90c5b1fc0c222c44084fbc38b8173e36aaafc24f476ec9b2934b3976fc`를
외부에 보존하고 7 entries/확장 합계 5026 bytes를 감사했다. source/expected/PR head와
별도 event SHA `141b799a42a843ccaee332ab5445994d541ad25e`를 대조했다.

실제 오류는 Darwin observed-member의 TaskInfo result 0/ESRCH 후 BSD identity를 얻지
못한 strict 실패다. before status 2/INEXIT true, after BSD 없음·memory identity match
false, 해당 scan의 leader anchor 확인은 미도달이고 Rusage도 미도달이다. 값이 실제로
바뀌었다거나 종료/reap을 관측한 것으로 바꾸지 않는다. complete sample 51개·최대 간격
199 ms·peak RSS 452,493,312 bytes·footprint 213,872,064 bytes이며 상한 초과 근거는 없다.
command exit는 null·supervisor_failure이고 drain/export는 완료했으며 slot/lease는 실패
정책대로 보존했다. 원 Cargo stderr에는 compile 시작만 있어 compile/test 완료가 아니다.
D060 Windows ancestry 또는 D062 Linux RSS 조건을 이 실패에 적용하지 않는다.

고정 source `6c7c6ccd5fa2d7fb0b4a87b5de6985641d1c2a6c`의 JVM CI 63
(`38797941297`)은 세 OS와 집계 실패를 관측했다. Windows 원 ZIP 66,251 bytes·SHA-256
`2b613458e44e2a6aa8eb662e42f697d5a08420bee58fa2747c5ec233b8c4f4b7`의 source·expected·
PR head를 대조했다. 실제 7모듈 406개 중 402개 통과·4개 실패이며 실패는 Fabric의
`NativeCalibrationApprovalTest` 네 사례에 기록된 347행 ClassCastException이다. SDK
108개와 host-core 96개는 통과하여 로컬 집중 `444`와 범위가 다르다. command 1·108,057 ms,
Job commit peak 1,733,632,000 bytes·6 process이며 drain·완전한 출력·export·scratch 정리·
lease 해제를 확인했다. Linux·macOS 원 ZIP은 이번에 감사하지 않았으므로 같은 원인으로
실패했다고 확대하지 않는다. native observer는 skipped, 게임·릴리스는 not_run이다.

source `bf0f253b5d0dcdaa2208637a6959bd6dacc2fb6b`의 JVM CI 62 (`38796054576`)
Linux 원 ZIP 57,652 bytes·SHA-256
`ef56ec837932510066c2a7bb8fafdab3d655b63149bca295402fa87bccc97da7`도 같은 source pin을
대조했다. Gradle은 7모듈의 test task와 `BUILD SUCCESSFUL in 1m 28s`를 출력했지만 이후
owned member의 RSS open ESRCH로 관리 실행이 실패했다. 원 identity가 같은 전후 Zombie·
threads 4와 BoundValidated pidfd의 terminal_poll/not_ready를 기록했고 Pending은 없었다.
command exit null·signal 9·98,395 ms·observation_failure이며 peak RSS 413,917,184 bytes·
3 process·793 samples·최대 gap 167 ms다. drain·완전한 출력·export·정리는 완료했다.
모듈 JSON/XML은 없으므로 test 개수나 정규 JVM 검증 성공을 선언하지 않는다. 이 오류를
OOM·종료 확인·RSS 0 또는 새 유예의 회복 성공으로 바꾸지 않는다.

같은 `6c7c6cc`의 Rust CI 72 (`38797940869`) Windows ZIP 32,010 bytes·SHA-256
`bae197b2f44396aceb23e9cc681ae29edb9d292148d23b4991ccae2c12c4a17a`는 format·repository
command 0 뒤 Coordinator 363개 통과·1개 실패·기존 1 ignored를 보존한다. 실패는 위 FN24
native 통합 회귀의 REVISION_CONFLICT/CONTEXT_UNKNOWN 불일치이며 test command 101·
417,859 ms, owned-tail 정리 후 drain·완전한 출력·export·scratch 정리·lease 해제다.
후속 Clippy/native stdio 성공 근거는 없고 이후 수정이나 planner 통과를 이 과거 실행의
성공으로 소급하지 않는다. 세 ZIP 모두 외부에 원문을 보존했으며 제품 DB/CAS는 대상이 아니다.

고정 `021ad5aabbde08fc7dd57dd4143eaeab927c54a7`의 JVM CI 70 (`38806684418`)는
Windows·Linux·macOS 및 집계 성공을 관측했다. 같은 source의 Rust CI 79
(`38806685427`)는 Windows·Linux 성공, macOS tests 성공 뒤 lint와 집계 실패다.
macOS 원 ZIP 55,515 bytes·SHA-256
`f02363f2711981794e04970048cd333dc6636dfb88933dc91352533806e1cfab`를 밖에 보존하고
source·expected·PR head를 대조했다. 실제 오류는 `process.rs::live_group_members`의 인수
8개에 대한 `clippy::too_many_arguments`이며 compile 101이다. 원 lint 실행은 35,549 ms·
drain·완전한 출력·export·scratch 정리·lease 해제이며 supervisor/cleanup 오류는 없다.
테스트 실패나 자원 관측 실패로 바꾸지 않는다.

후속 source는 같은 memory-exit·Pending·missing 진단의 원 mutable reference 세 개를
macOS 전용 `MacGroupDiagnostics`로 묶고 함수 진입 시 해체한다. 관측 본문·순서·한도·원
오류 보존 및 lint 정책을 바꾸지 않았다. 독립 source 리뷰 뒤 `479` format과 `480`의
Windows 도구 all-target strict Clippy가 통과했다. `480`은 command 0·4,562 ms·Job commit
peak 360,484,864 bytes·7 process·최대 gap 102 ms이며 자연 종료·drain·완전한 출력·export·
scratch 정리·lease 해제다. 실제 macOS 컴파일·lint 통과는 이 Windows 검사로 주장하지 않는다.

JVM 70의 세 원 ZIP도 exact bytes·SHA-256과 같은 source/expected/PR head·별도 event
`4d2793a6d6cfa8d00104fcf4ab34e41ec78a7e30`를 대조했다. 각 jvm-result의 7모듈 411개·
36 report metadata·실패/오류/skip 0·필수 11 executed task와 실제 Gradle 성공 stdout을
확인했다. 원 XML을 감사한 것으로 확대하지 않는다. Windows/Linux/macOS managed는 각각
command 0·121,744/129,224/114,710 ms이며 drain·완전한 출력이다. 각 OS의 bootstrap·managed·
native-build·header-managed·definition-startup finish 다섯 개는 모두 command 0·supervisor/
cleanup 오류 0·scratch 정리·lease 해제다. Windows native-build/header의 owned-tail 정리와
자연 종료는 구분한다. Linux와 macOS의 Pending 및 관측 회복 자료는 null/0으로 회복 분기
실증이 아니다. Linux의 native `.so` 6,533,176 bytes는 개별 entry 4 MiB 한도 때문에 내용
열람을 제외했으며 inner binary의 독립 digest 검증을 주장하지 않는다. startup은 모두
`development_fixture` 관측이며 game/release는 `not_run`이다. 새 bootstrap·display 소비자
구현과 이 이전 고정 source의 성공을 구분한다.

## 실제 display readback의 의미 소비자

새 `native_display_readback`은 기존 public `observe_display_retained`를 통해 실제 paired
관측·보존의 private NativeRead를 취득한다. 같은 Store·원 요청/session·deadline/cancel·
paired owner·현재 ACL을 전후 검사하고 최종 현재성 검사 후에만 factual snapshot을 만든다.
파싱 중의 원 NativeTargetError와 decode 이후 권한 실패를 함께 보존한다. 원 HostResponse·
관측/NBT digest·원/현재 context digest와 registry generation을 구분해 남긴다.

기존 bounded NBT decoder를 공유하여 실제 signed UUID 네 단어·Double 위치 세 값·정확한
태그와 owner tag를 교차 대조한다. 원 UTF-16·floating type/bits, matrix/decomposed 변환과
billboard·세 interpolation 필드를 해석하고 생략 값은 None으로 유지한다. 기존 calibration
4필드/rawFloatingBits·452 one-layer unwrap·byte/depth/node 한도와 별도 persisted 3필드
seam을 구분한다. scene·animation·client·profile·write 권한을 발급하지 않는다.

5파일의 독립 source 리뷰는 추가 P0–P2 및 명백한 type/lint 문제를 찾지 못했다. `482`의
명시 5파일 format은 command 0·3,212 ms·자연 종료·drain·완전한 출력·export·scratch 정리·
lease 해제다. 순수 해석 3개와 실제 Store/public reader의 no-entered-request 거절 1개를
작성했지만 아직 compile/test는 미실행이다. 다른 코호트와의 통합 검사 전 WIP로 공유하며
가짜 NativeRead·ADMIN·양성 snapshot fixture로 실제 발급을 대신하지 않았다. 실제 게임
display·geometry·시각 관측은 별도 미실행이다.

## 정직한 NotRun 릴리스 자료의 소비

내부 ReleaseProofClaim의 `NotRun`만 tested-artifact 집합을 비워 표현할 수 있도록
정책을 좁게 수정했다. Passed/Failed 및 nonempty NotRun의 기존 tested-bundle 조건,
실제 binding·source/profile·bundle/inventory·result artifact·원 verifier와 전체 canonical
claim digest 인증은 유지한다. NotRun은 여전히 필수 인수를 통과하지 못하며 생산
`release_evidence=None`의 거절도 바꾸지 않았다. 실제 미실행을 위해 가짜 tested SHA나
릴리스 bundle을 만들지 않는다.

기존 fixture 검사 하나를 확장했고 독립 source 리뷰 뒤 `484` format을 수행했다. `485`의
Windows policy 30개와 kernel 순수 3개가 통과했으며 policy의 기존 failed/notRun 구분
회귀도 실제 통과했다. base `57d7717`과 수정 입력 14개를 구분해 전후 SHA-256
`605e439707ea18025fab036fdef827266a02b1c896d2ad7df324fb6eb717ebf8` 일치를 확인했다.
별도 supplemental source 기록 2,523 bytes·SHA-256
`43b6850cd23d97e5820e79d504a0863a2c5191c3b6fbc5812aae7137332ae361`을 외부에 보존했고
원 managed receipt는 수정하지 않았다. `485`는 command 0·11,676 ms·Job commit peak
435,798,016 bytes·6 process·최대 gap 116 ms이며 owned-tail 정리 후 drain·완전한 출력·
export·scratch 정리·lease 해제다. 실제 filesystem/JNI/game 인수는 이 순수 검사에 없다.
후속 `488`에서 observer/kernel/policy 세 package의 all-target strict Clippy도 통과했으며
이는 별도 미공유 구현을 포함한 로컬 검사다. 생산 릴리스 증거 발급·collector 또는 출시
완료를 뜻하지 않는다.

고정 `57d7717dbdff23c89de8000c6c7db3da4431fd57`의 JVM CI 73 (`38811299947`)는
성공 metadata를 관측했고, Rust CI 82 (`38811299924`)는 세 OS의 모든 test/lint 단계와
집계 성공을 확인했다. 이 두 새 원 ZIP 감사는 수행하지 않았다. 이후 미공유 bootstrap·
파일 kernel·정책 변경의 성공 근거로 사용하지 않는다.

## 소유 파일 kernel과 최초 설치의 native 경계

`mmmm-owned-files`는 기존 selected-file reader의 held ancestry·ordinary identity·
NOFOLLOW/reparse·원 checkpoint와 명시 close를 옮긴 실제 공통 kernel이다. 새 owned
디렉터리는 Windows의 held parent에서 `NtCreateFile(FILE_CREATE)`로 원자적으로
생성하고, 반환한 동일 handle·FILE_CREATED·ordinary/reparse·volume/file identity를
검사한다. STATUS_PENDING은 입력/출력 allocation과 parent를 한 번만 격리하며 더 이상
같은 생성 capability를 사용하지 않는다. POSIX는 openat/O_EXCL과 협력적 named/held
관측을 사용하며 동일 UID의 rename/ABA를 원자적으로 막는다고 주장하지 않는다.
새 파일은 CreateNew·bounded write·sync·같은 handle의 독립 재읽기 두 번과 원 bytes/SHA를
검사한다. 기존 빈 디렉터리도 채택하지 않고 부분 생성 뒤 실패는 자동 삭제하지 않는다.

observer JNI는 Rust 정본 normative47에서 나온 정확한 48개 roster·원문·전체 bundle을
검증한 뒤 이 kernel을 소비한다. Java가 source를 재생성하거나 별도 파일 알고리즘을
갖지 않는다. 실제 Class/loader/generation·원 request/operation lease를 유지하며 native
오류와 Java Throwable 및 후행 current 실패를 함께 보존한다. fresh storage 검사는 실제
서버의 world ROOT를 발급하고 실제 dataFolder/getDataFile의 제한된 하위 상대 경로만
native absence walk에 전달한다. dataFolder 자체가 없을 때도 이 첫 부재를 읽기만 한다.
새 Mixin 접근자는 실제 SavedData type·constructor·cache 관계를 확인한 fresh-only 취득에
한정하며 get/load/negative cache를 부재 증거로 사용하지 않는다. Java 설치·초기화·reload
생산자는 현재 WIP이며 Rust 공통 bootstrap operation 연결은 별도 진행 중이다.

kernel과 JNI/Java 경계의 독립 source 리뷰는 확정 신규 P0–P2가 없었다. `487`의 observer
56개와 `488`의 observer/kernel/policy strict 검사가 통과했다. 후속 Java world ROOT 두
파일은 별도 독립 재리뷰를 마쳤으며, 이전 JVM478 성공을 이 새 Java의 성공으로 사용하지
않는다. 새 JNI 여섯 slot의 C header witness·실제 JNI 호출·새 Java 컴파일은 아직 미실행이다.

Windows `493`에서 CLI 16개·Application 58개·Coordinator 381개·kernel 3개가 통과했고
기존 Coordinator 1개 ignored를 유지했다. 실제 CreateNew와 원 bytes 검증·기존 child
거절·partial/cancel 보존·nested absence·secret guard 및 기존 selected-file Windows
공유 경계 회귀를 포함한다. Unix symlink/rename 검증이나 게임 설치 결과로 확대하지 않는다.
display 순수 해석 3개와 실제 Store/no-entered-request 거절, bootstrap raw Invocation
pin·frame 한도·두 fresh preflight·만료 reply의 I/O 전 중단 회귀도 이 실행에서 통과했다.
이는 일부 미공유 bootstrap 소스를 포함한 로컬 검사이며 전체 고정 SHA 인수와 구분한다.

`493`의 base는 `21de15b5a2f52e419c4039daaa66cdd269bbd303`, 영향 입력 304개·
7,658,414 bytes의 전후 manifest SHA는
`aa89560bc7aa17845fcff3a35b7366d54b5c6107cb84ae26151f98c4dcbafd68`로 일치했다.
별도 source-binding은 43,208 bytes·SHA
`2cf99e26a0c7cc55152b27c7834cabbe524bab1d3d09399b211d326dbc5693d9`로 보존했고
원 managed receipt를 변경하지 않았다. command 0·252,027 ms·Job commit peak
1,630,527,488 bytes·6 process·최대 sample gap 146 ms이며 owned-tail 정리 뒤 drain·
완전한 출력·export·scratch 정리·lease 해제를 확인했다. 후속 `494`의 strict Clippy는
실제 exit 101로 실패했다. 새 bootstrap의 collapsible-if 2건과 인자 수 3건이 원인이며
22,672 ms·정상 drain/export/정리를 별도 보존했다. 그 교정과 재검증은 진행 중이다.

실제 source 설치·fresh cache 취득·47개 초기화·reload·새 pairing과 readonly reconcile,
게임 ADMIN·Mixin/JNI 적중·최종 3OS 및 client 인수는 아직 미실행이다. closed file facts를
이후 root의 identity 연속성이나 loaded 함수의 source 인과 증명으로 바꾸지 않는다.

## 최초 설치의 공통 계획과 작업 원장 연결

Rust 공통 bootstrap은 같은 daemon의 하나의 제한된 registry를 management·Provider·
observer가 공유한다. 실제 native owner·현재 Project revision과 원 요청을 확인한 뒤
정본 48개 source와 recipe를 같은 CAS에 보존하고 기존 Application setup/freeze로 계획을
만든다. CLI의 `calibration-bootstrap-plan`은 고정 purpose만 선택한다. host-setup의 명시
opt-in은 빈 externalTargetIds 입력에 정본 95개 target을 채울 뿐이며, owner 선택·게임
ADMIN의 실제 ACK/EOF 완료·새 plan.apply 요청은 각각 별도 조건이다. 일반 numeric route와
write profile은 확대하지 않는다.

실제 before는 완료된 private route에서 새로 얻어 operation에 보존하고, capture 뒤와
intent 직전에도 새 관측으로 확인한다. 공통 ProviderPort의 optional batch 경계는 bootstrap
preflight마다 실제 95-target 관측 한 번을 반환하고 Application이 원 순서와 phase expected를
직접 비교한다. 일반 provider는 None으로 기존 개별 fail-fast 루프를 유지한다. 원 durable
Invocation의 raw encode_json SHA와 길이는 canonical capture-map key와 구분하며, 실제
consuming RPC 전 sticky attempt를 남긴다. 원 host 응답은 후행 현재성 검사보다 먼저 CAS에
보존하고 원 실패·후행 취소/철회 실패를 함께 남긴다. management의 더 짧은 reply 기한도
원 cancel을 유지하며 실제 RPC deadline까지 전달한다.

`493`의 관련 unit 결과와 입력 pin은 앞 절에 기록했다. 독립 재리뷰에서 이전 raw/canonical
혼동·반복 관측·reply 기한 누락 세 결함은 해소됐으며 새 확정 P0–P2는 없었다. 후속 `494`
Clippy 진단은 동작을 유지하는 두 borrow 구조체와 let-chain 두 곳으로 교정했고 `498`의
명시 5파일 format 뒤 `499`에서 Application/Coordinator/CLI/kernel all-target strict가
통과했다. command 0·41,327 ms·Job commit peak 960,348,160 bytes·7 process·최대 gap
151 ms이며 자연 종료·drain·완전한 출력·export·scratch 정리·lease 해제다. `493`은 lint
교정 전의 unit 실행이며, 교정 후 unit 전체를 다시 실행한 것으로 표시하지 않는다.

고정 `bfc509a`의 Windows JVM `497`은 입력 203개가 전후 같았고 manifest SHA는
`59ad6e90e12310ac32bc0d47b23ea31ea6c1443d76fef4a2118f215854d39ab5`였다.
definition-observer 예외의 nonserializable receipt 필드 두 개가 serial 경고를 내어 실제
compileJava가 실패했고 나머지 dependency task는 실행되지 않았다. command 1·52,697 ms·
Job commit peak 1,341,911,040 bytes·6 process·최대 gap 145 ms이며 자연 종료·drain·
완전한 출력·export·scratch 정리·lease 해제를 별도로 확인했다. 두 필드의 프로세스 내
보존은 유지하며 transient로 교정했고 새 JVM 검증 전이다. 전체 11 task나 새 JNI header
검사를 성공으로 기록하지 않는다.

같은 source의 Rust CI 84 (`38816348469`)는 세 OS의 tests 단계 성공, Windows job 성공,
Linux/macOS lint 및 집계 실패를 관측했다. 두 원 ZIP의 byte/SHA를 API metadata와 대조한
뒤 실제 clippy stderr에서 Windows 테스트 전용 Component import 한 건을 확인했다.
그 import를 cfg(all(test, windows))로 좁혔고 Unix의 실제 재검증은 후속 CI 대상이다.
JVM CI 75 (`38816348441`)는 세 OS와 집계 실패, native observer 단계 skipped다.
이 metadata 관측을 새 원 JVM ZIP 감사로 확대하지 않는다.

reload는 마지막 효과이며 원 route가 종료된 결과를 성공으로 바꾸지 않는다. 현재 새
pairing을 통한 readonly reconcile은 unavailable이며 실제 original-result capsule과
원 operation의 관측 연결을 추가해야 한다. 새 pairing의 현재 파일·상태가 기대와 같아도
원 ProviderResult나 추가 효과 가능성 해소를 합성하지 않고 원 journal의 fence를 유지한다.
scene/animation 발급자, DataPack calibration 및 실제 target-profile 생산자도 후속 구현이다.

## 실제 JVM 재검증과 bootstrap successor의 부분 관측

고정 `47add35df7ae1f15651a54961a4020f468bbd93e`의 Windows `502`는 7모듈
412개·원 XML 36개·필수 11 task의 실제 실행이 모두 통과했고 failure/error/skip은 0이다.
입력 203개의 전후 manifest SHA는
`b8011efb8a10f774fdeee6bd4e1239240abc7593f37d463377f2de18fdae8698`로 같았다.
원 XML을 별도로 보존했으며 summary 12,594 bytes의 SHA는
`761f790651130f8d301c53e5985c4ece4fc3cabc967aa9e56bd9ce73f59b437e`다.
command 0·79,244 ms·Job commit peak 1,380,569,088 bytes·6 process·최대 gap 145 ms,
자연 종료·drain·완전한 출력·export·scratch 정리·lease 해제다. 앞선 `497`의 serial
compile 실패를 수정하거나 이 후속 성공으로 지우지 않았다.

`503`은 같은 head에서 실제 선택 MSVC와 JDK 25 헤더로 C witness를 컴파일·실행했다.
42 table signature·6 callback·4 entry 검사 및 입력 8개의 전후 재검증이 통과했다.
fixture/helper/Rust FFI/선택 compiler/JNI·JVMTI·platform header/실제 witness image를
pin했다. command 0·13,063 ms·Job commit peak 174,862,336 bytes·7 process·최대 gap
127 ms이며 owned-tail 정리 뒤 drain·완전한 출력·export·scratch 정리·lease 해제다.
helper의 source SHA는 caller-bound이며 VM/table 호출·게임·whole-toolchain 검증을
발급하지 않는다. JVM CI 76 (`38859789149`)도 세 OS의 JVM 및 native observer
ABI/controlled-startup 단계와 집계 성공을 관측했다. 새 원 ZIP 감사는 아직 미실행이다.
Rust CI 85 (`38859789187`)도 후속 조회에서 세 OS의 실제 테스트·lint 및 집계 성공을
확인했다. 두 CI의 job/step metadata 성공과 새 원 ZIP 감사를 구분하며, 이 결과는 이후
successor·용량 수정이나 실제 게임·공개 배포의 근거가 아니다.

후속 successor 구현은 원 operation의 Observe 권한과 실제 새 completed pairing의 읽기
권한을 연결한다. 원 query/Invocation/context pin은 유지하며 같은 game/world·다른 epoch와
전체 scope를 검사한다. 실제 원 route가 여전히 유효하면 원 source/intent/권한을 확인한 뒤
기존 경로를 유지하고, 필요한 새 pairing 부재나 무효인 bootstrap을 None으로 우회하지 않는다.
host 응답은 후검사보다 먼저 원 operation CAS에 보존한다. 공개 JSON이나 digest만으로
새 pairing·ADMIN·capsule을 발급하지 않는다.

Java는 실제 Accepted에서만 최대 8개 Attempt를 만들고 원 result/failure·reload future를
reload route 밖에 보존한다. 실제 completion frame·nonce·ready·EOF·child exit 0·stderr
drain 이후에만 새 route의 private 완료 사실을 기록한다. 이 경계는 같은 server instance의
수명에 한정되고 실제 ADMIN·95개 scope·현재 generation을 전후 재검사한다. 현재 loaded
47개와 cache 상태 94개를 읽지만 pack은 unknown으로 남기고 95번째 가짜 image/SHA는
만들지 않는다. root identity 연속성과 loaded 함수 source 인과가 미입증이므로 원 effect를
보존하면서 settled=false·빈 direct_changes를 반환한다. 원 ProviderResult가 없으면 poll도
이를 합성하지 않아 원 작업의 finished·성공·fence 해제를 만들지 않는다.

독립 추적에서 기존 AnonymousBridge가 bootstrap 승인 purpose를 거절하던 P1을 발견했다.
실제 exchange의 닫힌 gate를 numeric/bootstrap 두 purpose만 허용하도록 교정하고 기존
HostInspectionControlTest에 허용·거절 회귀를 추가했다. 원 nonce·ACK/EOF·기한·exit/drain
검사는 바꾸지 않았다. 이전 `502`의 412개에는 이 회귀가 없었으며 새 JVM 검증은 대기 중이다.

Rust 9개·Java 5개의 독립 source 리뷰는 미해결 P1/P2가 없었다. `504`의 명시 Rust format
뒤 `505`에서 Application 7개·Coordinator 4개 집중 검사가 통과했다. 입력 306개·
7,720,034 bytes의 전후 SHA는
`04e2d845a07240a09fd3b0b7fe8d6b4081d373a637515cc09cde807df783dc29`로 같았다.
command 0·96,646 ms·Job commit peak 1,592,094,720 bytes·6 process·최대 gap 150 ms이며
owned-tail 정리 뒤 drain·완전한 출력·export·scratch 정리·lease 해제다. 실제 새 pairing이나
게임 관측을 만든 fixture는 없다. 후속 `506` strict는 조건식 두 곳의 lint로 exit 101이며
11,599 ms·정상 drain/export/정리를 보존했다. 동치 조건식/let-chain으로 교정한 뒤
`507` format과 `508` Application·Coordinator·CLI all-target strict 검사가 통과했다.
`508`은 command 0·21,498 ms·Job commit peak 967,041,024 bytes·7 process·최대 gap
118 ms이며 자연 종료·drain·완전한 출력·export·scratch 정리·lease 해제다.
`505`의 원 입력 목록은 별도 source binding 43,501 bytes·SHA
`7efe22bbe3e92101b8ccfb761082dab5449c890c457b340a75081ee430d68940`로 보존했다.
이는 당시 캡처한 입력을 뒤에 보존한 기록이며 원 managed 영수증을 수정하지 않았다.

후속 용량 검토에서 raw target 192 KiB 한도만으로 실제 response 256 KiB 한도를
보장할 수 없음을 확인했다. 실제 wire 구조를 사용한 순수 fixture를 확장하되 대표 NBT
크기를 실제 게임 관측으로 해석하지 않는다. Java Throwable emitter의 depth/cycle
절단 노드도 32개 출력 예산에 포함하도록 고쳤고 기존 테스트에서 실제 emitter를
검사한다. 실제 target 쌍의 candidate 직렬화에 전체 frame 예산과 오류 16 KiB·256 node 및
종료 tick 길이 여유를 검사하는 교정을 완료하고 독립 source 검토를 통과했다. 초과한
이번 쌍만 철회하여 실제 prefix와 unknown/LIMIT를 보존하며, 예상 밖의 오류와 후검사
실패를 부분 성공으로 바꾸지 않는다. raw 192 KiB와 최종 256 KiB·4,096 node·depth 64
한도는 유지한다. Java 후속 변경은 `505`/`508`의 성공 범위에 포함하지 않으며 실제 JVM
검사는 대기 중이다.

Rust capacity fixture는 `509` format 뒤 `510`에서 1개 통과했다. 입력 306개·7,729,705
bytes의 전후 pin은
`4beadb83f23adadd4d21434402e220235a03f71fbcc9684dce6558709c357681`로 같았다.
별도 source binding 43,368 bytes·SHA
`2d8e42b9db9731a93cf3876853e2eae3bc7bbc014cf9eb60b8fbf392ee525b98`와 원 관리 기록을
보존했다. command 0·70,670 ms·Job commit peak 1,592,999,936 bytes·6 process·최대 gap
146 ms이며 owned-tail 정리 뒤 drain·완전한 출력·export·scratch 정리·lease 해제다.
이 fixture는 실제 Java emitter 실행·NBT 크기·게임 및 ADMIN 관측의 근거가 아니다.

고정 `bef4a37e54b437545e8311f1908a87ad2a70af60`의 실제 Windows JVM `512`는
7모듈 417개·원 XML 36개·필수 11 task가 모두 실행·통과했고 failure/error/skip은 0이다.
host-core 97·Fabric 130개에는 새 purpose gate·Throwable·실제 frame prefix helper 회귀가
포함된다. 입력 203개의 전후 pin은
`83260dc61ce46c6a89fd94017a8cee2f548eceeb522e768b9e23c802b692d6a2`로 같았다.
원 XML과 summary 12,595 bytes·SHA
`cdfcc1498ddf9dd2fb7343bbc53b405a99d5cf177dfe41e10702ca2b0d25f4b6`를 보존했다.
command 0·69,478 ms·Job commit peak 1,387,356,160 bytes·6 process·최대 gap 148 ms,
자연 종료·drain·완전한 출력·export·scratch 정리·lease 해제다. 실제 ADMIN·게임·reload
source 인과·pack root 연속성과 settled readback은 계속 미입증이다.

## 개발 도구 이미지와 후보 생산자의 수명 준비

회수 코드의 읽기 전용 검토에서 실행 중 supervisor가 든 완료 slot도 예산 회수 대상이
될 수 있음을 확인했다. 별도 purpose만으로 실행 이미지의 존속을 보장하지 않으며,
Windows의 EXE 잠금을 보존 정책으로 취급하지 않는다. 실제 image/slot 보호 교정을
구현하고 아래 Windows 단위 검사를 확인했다. [D076](DECISIONS.md)의 외부 고정 tools 경로에 기존 bootstrap 이미지
3,073,024 bytes·SHA
`1550b1921fd45ba67500a2f00e934111c78d57fa333209632146da4df9e83d2b`를 별도 보존했다.
원 source owner·catalog lease 부재를 전후 대조하고 source held 두 pass와 목적지
재열기의 전체 SHA가 같음을 확인했다. 이 전후 관측을 catalog 독점 lease 취득이나
native inode·hostile rename 원자성 증명으로 기록하지 않았다.

첫 시도는 owner의 전체 checkout digest를 짧은 slot prefix와 비교해 복사 전에 거절됐다.
교정한 복사는 검증까지 완료됐으나 마지막 PowerShell generic 배열 비교가 실패해 별도
tools lease를 보존했다. 종료된 원 생성 process·같은 owner/lease·원 copy 영수증·원본과
사본의 bytes/pin을 다시 검사해 해당 lease만 해제하고 복구 영수증을 CreateNew로 남겼다.
원 copy 기록과 실패를 덮지 않았고 다른 cache·제품 자료를 삭제하지 않았다. `513`은
이 사본을 실제 Windows 관리 child로 실행해 repository 검사를 통과했다. 사본 보존과
실제 실행을 구분하고 이후 tool 교체 전까지 이 고정 이미지를 사용한다.

development CLI 후보 생산자는 실제 source·dependency·tool images와 고정 target 및
archive를 연결한다. 실행별 대형 target을 만들지 않고 같은 fixed target과 scratch source를
사용한다. 이전 actual source/dependency/tool/선택 환경/고정 인자·전체 workproduct·원
build stdout·archive·binding 및 실제 finish/complete가 일치할 때만 재사용에 입장한다.
알 수 없거나 불일치한 preflight cache는 finish를 호출하지 않고 실제 자식 시작·drain·
export 상태 및 보존 단계의 미변경을 별도 기록하여 owner/lease와 자료를 보존한다.
획득 단계의 owner/lease 쓰기는 이 보존 단계와 구분한다. 명시적 소유 수명 처리 없이
재시도하거나 pointer를 합성하지 않는다. 입장 뒤 정리는 현재 CLI package의 고정 clean만
사용하며 실제 새 executable의 원 Cargo completion을 검사한다. 전체 제품 bundle과 FN36
생산자·신뢰된 결과 index·82개 인수 및 공개 배포 완료와 구분한다.

`514`의 format 뒤 실제 Windows `515`는 새 fixed tools slot에서 xtask library 241개
통과·기존 1 ignored와 binary 8개 통과를 확인했다. supervisor 보호 회귀와 candidate의
네 pure 검사가 포함된다. `516` all-target strict도 통과했다. 두 실행 전후 로컬 Rust 입력
324개·8,834,422 bytes의 pin은
`94ba3c9b0c5055c7a008f646af4cd008e0e770c6806b1e9d60ab7a968f46fcbc`로 같았다.
별도 binding 45,961 bytes·SHA
`ab50a26a43d54a56e48a406a457e600499fc58218745f9021865fc5aec1c122c`를 보존했다.
`515`는 command 0·104,766 ms·Job peak 549,343,232 bytes·10 process·gap 141 ms·
owned-tail 정리이며 완료된 원 bootstrap cache 1개 회수를 기록했다. `516`은 command 0·
14,154 ms·Job peak 364,433,408 bytes·7 process·gap 132 ms·자연 종료다. 모두 실제
drain·완전한 출력·export·scratch 정리·lease 해제·감독/정리 오류 0이다. source 독립
cross-OS 검토의 확정 P1/P2·타입 지적은 0이며 실제 Unix/macOS 실행과 구분한다.

[D077](DECISIONS.md)의 입력 예산을 채택했다. 아직 실제 후보 실행 전이므로 Cargo worker
초기값 한 곳을 2에서 기존 Windows 검사와 같은 1로 고정했다. 앞선 `515`/`516`의 원 pin을
새 소스의 pin으로 바꾸지 않으며, 이 단일 설정 변경 뒤 실제 도구 빌드와 후보 생산을
진행한다. 새 producer의 실제 archive 생성·dependency fetch/target 상태는 아직 미실행이다.

## 첫 공개 배포 인수

- [ ] 최종 고정 SHA와 정확한 게임 및 호스트 target profile을 식별한다.
- [ ] Windows x64, Linux x64와 macOS ARM64 배포 후보를 만들고 파일 digest를 고정한다.
- [ ] 배포할 동일 파일로 3개 OS의 실제 서버 검사를 수행한다.
- [ ] 각 OS의 클라이언트 기본 검증을 수행하고 Windows에서 전체 시각, 상호작용 및 필요한 다중 사용자 검증을 수행한다.
- [ ] 생성된 결과물을 vanilla 환경에서 검증한다.
- [ ] 필수 인수 항목의 결과, 미검증 범위와 원본 증거를 연결한다.
- [ ] 미해결 쓰기, 부분 완료, 결과 불명과 필수 미실행을 해결한다.
- [ ] 배포 파일, SDK, digest, SBOM과 필요한 라이선스 및 고지를 대조한다.
- [ ] 실제 `release.evaluate` 판정과 소유 및 provenance 리뷰를 기록한다.
- [ ] 인수한 동일 파일을 `v0.1.0` tag와 공개 GitHub Release에 연결한다.
- [ ] 임시 artifact 만료와 별도로 릴리스 증거를 보존한다.

서명 없는 배포 아카이브를 기준으로 한다. 배포 후보 생성, CI 요청과 판정 통과를
공개 게시 완료로 표시하지 않는다. 실제 게시 결과와 digest를 확인해 보고한다.
