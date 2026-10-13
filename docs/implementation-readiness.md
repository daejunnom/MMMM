# MMMM 구현 착수 조건

저장소 규약은 제품 구현 전에 적용한다. 실제 기능 구현과 인수는 원본 계약,
검증된 도구와 결과 근거를 연결해 진행한다. 현재 범위는 G0부터 G4와 공개
`v0.1.0` 배포까지이며 G5와 G6은 후속이다.

## 현재 기준

현재 구성은 작업 규약, 구현 및 수명 기준, PR 템플릿, 선언 구조 정책, 원본 계약과
Rust 구현 기반이다. 원격 `main`, `develop`과 기능 브랜치에 기준선을 반영했고,
제품 구현은 Draft PR #1에서 진행한다. 원격 보호 설정은 아직 완료되지 않았다.
Windows의 빌드 관리 도구 bootstrap은 실제로 통과했으며, 제품 인수와 CI는 미완료다.

## G0 선행 조건

- [x] 원본 `contracts/mmmm.schema.json`, `contracts/function-index.json`과 예제 패키지를 확보한다.
- [ ] 원본의 버전, provenance, digest와 문서 의미를 확인하고 저장 및 wire 계약 `0.2.0`을 도입한다.
- [x] 현재 배정에 Git 구성이 포함되면 빈 원격 상태를 확인하고 bootstrap을 수행한다.
- [ ] 첫 Rust와 JVM 빌드로 실제 toolchain, feature, JDK, Gradle 및 의존성을 고정한다.
- [ ] 관리 도구 bootstrap부터 모든 대형 빌드 및 테스트 출력을 외부 소유 슬롯에 둔다.
- [ ] Windows, Linux와 macOS에서 성공, 실패, timeout, 취소 및 자식 종료 확인을 검증한다.
- [ ] lease, 한도, 경로 이탈, cache 회수와 증거 내보내기 실패를 검증한다.
- [ ] Rust 구조 검사기를 도입하고 metadata만 읽는 범위와 거절 경로를 검증한다.
- [ ] 원격 구성이 배정되면 실제 검사 등록과 `main` 및 `develop` 보호 설정을 확인한다.
- [ ] 담당자와 리뷰 구성을 확인하고 필요한 CODEOWNERS를 등록한다.

원본 70개 파일의 SHA-256 무결성을 확인했고 선택 도입한 61개 파일은
`contracts/handoff-input.json`에 기록했다. 계약의 의미, DTO와 공식 JCS 검증은
별도로 진행한다. 관리 도구와 구조 검사를 검증하기 전 실행 명령 또는 자동 정리의
완료를 보고하지 않는다.

## 2026-10-14 로컬 구현 검증

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
