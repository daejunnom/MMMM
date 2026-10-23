# MMMM 빌드와 파일 수명주기

빌드 실행은 소유권, 고정 슬롯, 유한한 자원과 종료 확인을 기준으로 관리한다.
이 문서는 빌드 및 테스트 생성물의 보관과 회수를 소유한다. 제품의 영속 데이터와
사용자 자료는 별도의 소유 및 보존 수명을 갖는다.

아래 절차는 채택한 구현 요구다. `tools/mmmm-xtask`와 플랫폼 bootstrap에
관리 실행과 회수 구현이 있으며 Windows에서 실제 검증을 진행했다. 다른 OS,
CI와 제품의 검증 완료 여부는 [구현 착수 조건](implementation-readiness.md)에 기록한다.

## 생성물 분류

| 분류 | 자료 | 수명 |
|---|---|---|
| 재생성 빌드 | Cargo target, JVM 빌드, 의존성 및 compiler cache | 소유 확인된 비활성 cache만 예산에 따라 회수 |
| 임시 작업 | compiler scratch, private staging, 일회성 테스트 서버와 월드 복사본 | 필요한 증거 보존 후 자식 종료를 확인해 회수 |
| 보존 기록 | 원시 로그, 인수 결과, 재현 입력과 실패 진단 | 기록별 보존 정책 적용. cache 정리에서 제외 |
| 배포 파일 | 아카이브, JAR, SDK, hash, SBOM과 고지 | 배포 후보 및 릴리스 식별자로 보존 |
| 제품 영속 자료 | SQLite, CAS, operation journal, 변경 전후 상태와 복구 자료 | 제품의 참조와 복구 계약으로 관리 |
| 사용자 원본 | 맵, 스크립트, 프로젝트와 외부 도구 자료 | 소유 사용자와 승인된 변경 계약으로 관리 |

`.gitattributes`로 고정한 원본 snapshot과 소스 fixture는 Git에서 bytes를 보존한다.
큰 생성물과 원시 로그를 소스 fixture로 옮겨 수명 규칙을 우회하지 않는다.

## 플랫폼 출력 루트

| 환경 | 개발 생성물 루트 | 관리 빌드 위치 |
|---|---|---|
| Windows | `%APPDATA%/MMMM` | `build/managed-v1` |
| Linux | `${XDG_CACHE_HOME:-$HOME/.cache}/mmmm` | `build/managed-v1` |
| macOS | `~/Library/Caches/MMMM` | `build/managed-v1` |
| CI | `$RUNNER_TEMP/MMMM` | `build/managed-v1` |

표의 기호는 플랫폼 경로를 설명한다. 아직 제공되지 않은 도구 옵션이나 환경변수
인터페이스를 의미하지 않는다. 실제 구현은 OS가 제공하는 경로를 조회하고
사용자 이름을 포함한 절대 경로를 소스에 하드코딩하지 않는다.

개발 루트 아래의 `build`, `cache`, `tmp`, `runs`와 `reports`는 용도별로 구분한다.
macOS와 Linux의 보존 기록은 cache 디렉터리 밖의 명시적 보존 위치로 내보낸다.
Windows에서도 관리 빌드 하위 트리와 보존 기록의 정리 범위를 분리한다.
CI의 임시 호스트가 끝나기 전에 필요한 자료를 artifact 또는 릴리스 보존 위치로 회수한다.

제품 영속 루트는 기본적으로 Windows의 로컬 사용자 데이터 영역,
Linux의 XDG data 및 state 영역, macOS의 사용자 Application Support 영역에 둔다.
정확한 제품 디렉터리 배치는 runtime 구현 때 등록한다. SQLite WAL은 로컬 파일시스템을
사용하며 네트워크 공유와 빌드 cache 디렉터리를 영속 DB 위치로 사용하지 않는다.

## 고정 슬롯과 소유 기록

관리 빌드는 OS, 아키텍처, 실제 checkout 경로의 digest와 용도로 슬롯을 선택한다.
commit SHA, PID, GUID 또는 시각마다 새 대형 빌드 트리를 만들지 않는다.
식별 token은 lease 검증에 사용할 수 있지만 출력 디렉터리의 무제한 누적 기준으로 사용하지 않는다.

실행할 개발 도구를 cache 밖에 보존할 때는 [D076](DECISIONS.md)의 별도 고정 이미지
소유권과 유한한 수명을 적용한다. 초기 Windows bootstrap/candidate 도구는 최대 2개,
각 32 MiB·합계 64 MiB이고 실행 중 교체하거나 자동 회수하지 않는다. source와 사본의
전체 bytes·SHA, 원 owner와 완료/drain/export, 목적지 재읽기 및 별도 완료 영수증을
확인한다. copy 성공과 실제 실행 성공, 원 도구의 빌드 revision은 각각 다른 사실이다.
원 catalog lease를 이 보존물의 lease로 승계하지 않으며 partial·unknown 경로는 보존한다.
새 도구를 관리 slot에서 컴파일할 때 필요한 이미지는 finish의 cache 회수 전에 별도
보존을 완료해야 한다. 새 도구가 자체 관리 lease를 얻는 명령은 부모 관리 run의 lease가
해제된 뒤 직접 호출한다. 보호한 실행 slot도 원 예산 계산에서 제외하지 않는다.

슬롯에는 소유 schema, checkout 식별, 용도, 소유 token, 프로세스 식별,
상태와 마지막 완료 시각을 기록한다. 원자적 기록 교체와 flush를 사용한다.
개인 절대 경로가 필요한 소유 기록은 로컬 내부에 두고 공유 영수증에서는 제거한다.

한 관리 카탈로그의 소유 lease가 입장, 재사용과 회수를 직렬화한다.
동일 카탈로그에서 동시에 관리하는 빌드는 하나다. busy 상태는 명시적으로 반환하며
상한 없이 기다리지 않는다. 빌드 내부의 worker와 서로 다른 CI runner는 별도 자원 범위에서 병렬 실행할 수 있다.

활성 또는 중단 lease를 자동으로 훔치지 않는다. PID가 없거나 시간이 지났다는 사실만으로
삭제하지 않는다. 수동 복구는 이전 소유 실행의 종료, 정확한 경로, token과 기록을
대조한 뒤 배정된 소유 범위에서 수행한다.

슬롯의 `cache` 최상위는 `cargo-target`, `cargo-home`, `gradle-build`,
`gradle-project-cache`, `gradle-user-home` 디렉터리만 허용한다. 직접 실행한
`rustc`의 EXE와 동반 PDB도 `cargo-target` 아래에 명시적으로 출력한다.
생성이 끝난 뒤에는 주 파일뿐 아니라 같은 실행의 동반 출력까지 확인한다.
알 수 없는 cache 항목을 정리 허용으로 바꾸지 않는다. 정확한 소유와 종료를
대조한 수동 복구에서도 원 export 실패와 별도 로그 보존·복구 결과를 구분한다.

## 초기 예산

| 항목 | 초기 값과 적용 범위 |
|---|---|
| checkout 슬롯 크기 | 8 GiB |
| 관리 카탈로그 크기 | 활성 및 완료 빌드 슬롯 합계 12 GiB |
| 완료 cache 슬롯 보존 | 최대 4개. 활성 슬롯은 byte 예산에 포함하며 동시 최대 1개 |
| 일반 명령 timeout | 1200초. 명시적으로 선택할 수 있는 범위는 1~3600초 |
| 실행 중 크기 관측 | 5초 간격 |
| 관리 트리 순회 | 루트 기준 최대 깊이 64, entry 최대 100000개 |
| 소유 기록 크기 | 기록 하나당 최대 8 KiB |
| 구조 정책 파일 크기 | 64 KiB |
| 예외 없는 추적 파일 크기 | 10 MiB |

빌드 크기 값은 초기 예산이다. 첫 Rust 및 JVM 빌드의 실제 크기와 완료 시간을 확인해
필요한 조정을 결정 기록에 남긴다. OOM 또는 초과 후 worker, 예산이나 timeout을 조용히 바꾸지 않는다.
큰 별도 검증에는 목적과 유한한 예산을 명시한다.

크기는 제한된 깊이와 entry 수 안에서 관측한 파일 길이 합계로 검사한다.
관측 사이 증가가 가능하므로 커널 disk quota나 실제 물리 할당량의 보장을 주장하지 않는다.
활성 슬롯의 고정 cache와 scratch 아래에서 이미 열거한 임시 항목이 삭제된 경우에는
남아 있는 상위 경로와 고정 루트의 소유 및 물리 경계를 확인한 뒤 누락을 허용한다.
고정 루트, 소유 기록, 완료 슬롯과 정리 단계의 누락은 허용하지 않는다. 관측 전후에
소유 기록과 고정 루트를 검증하며, 이 순회는 원자적인 파일시스템 snapshot이 아니다.
보존 기록과 제품 영속 자료는 이 cache 예산으로 삭제하지 않는다.

## 관리 실행 절차

1. 최종 루트와 checkout 경로를 확인한다. 루트와 checkout의 포함 관계, 비밀 경로,
   외부 link/junction과 알 수 없는 소유 기록을 거절한다.
2. 카탈로그 lease를 획득하고 소유 완료 슬롯만 대상으로 예산을 확인한다.
   기존 중단 슬롯이나 외부 트리를 자동 채택하지 않는다.
3. 해당 슬롯의 Cargo, JVM, 의존성 cache와 scratch를 지정한다.
   충돌하는 target 또는 임시 경로 override를 거절한다.
4. 유한한 timeout과 worker 예산으로 소유 실행을 시작하고 크기를 관측한다.
   Cargo incremental은 초기 관리 profile에서 끈다.
5. 성공, 실패, 취소 또는 초과 시 필요한 진단과 인수 자료를 보존 위치로 내보낸다.
   명령 결과와 supervisor 오류를 별도로 기록한다.
6. 소유 자식 트리의 종료와 파일 사용 해제를 확인한 뒤 scratch를 회수한다.
7. 슬롯 한도를 넘은 재생성 cache를 회수한다. 전체 한도와 완료 슬롯 수를 넘으면
   오래된 완료 및 소유 확인 슬롯부터 회수한다.
8. 마지막 실행 영수증을 갱신하고 검증된 lease를 해제한다.

명령 실패를 정리 성공으로 덮지 않는다. 정리 실패도 원래 명령의 실패와 별도로 남긴다.
프로세스 종료, 소유권 또는 자료 보존을 확인하지 못하면 슬롯과 lease를 보존하고 오류를 반환한다.

## OS별 실행과 JVM 수명

Windows에서는 소유 프로세스를 시작부터 Job Object 등 확인 가능한 경계에 둔다.
Linux에서는 소유 process group의 취소와 종료를 확인한다. macOS에는 지원되는
프로세스 관찰과 종료 경계를 별도로 구현한다. Linux 전용 관찰 경로를 macOS에 적용하지 않는다.
종료 확인 범위와 이탈 가능한 프로세스의 한계를 문서화하고 시험한다.

Gradle build와 project cache, Gradle user home, Java 임시 파일과 테스트 서버 작업
공간은 소유 경로로 지정한다. 관리 실행은 공유 daemon이 정리 대상 파일을 계속
잡지 않도록 구성한다. 재사용 가능한 daemon을 도입하려면 소유자, 종료 조건과
파일 수명을 먼저 정의한다. 다른 프로젝트 또는 사용자 전역 cache와 daemon을 정리하지 않는다.

JVM CI launcher와 Gradle build VM에는 동일한 고정 인자 19개를 사용한다. heap 1 GiB,
metaspace 384 MiB, encoding·locale·필수 module open/export 및 Gradle이 요구하는
인자를 일치시키고 launcher에만 실제 선택된 instrumentation agent를 연결한다.
agent 파일의 물리 경로·크기·수정 정보와 SHA-256을 실행 전후 확인한다. 이는 선택한
파일의 관측이며 별도 upstream digest나 전체 Gradle/JDK image 인증은 아니다.
고정 인자와 heap 일치만으로 같은 VM 사용을 추정하지 않고, 실제 build VM의 유한한
fact record를 검사한다. Windows Job의 2 GiB·32 process 및 기존 출력·시간·저장
상한은 유지한다. 이 launcher 변경은 과거 Linux 감독 실패의 원인이나 해결을 입증한
것이 아니며 현재 실행의 결과는 구현 착수 조건에 별도로 기록한다.

[MMMM-D025](DECISIONS.md)의 소유 JVM helper에는 Rust 관리 route가 native spawn 전에
`DOTNET_EnableDiagnostics=0`을 고정 child environment override로 넣는다. 부모의
설정을 조회해 선택하거나 전역 환경을 변경하지 않는다. helper 안에서 시작 후 이 값을
대입하는 방법은 CLR의 시작 시점 debugger FIFO 생성을 예방하지 못하므로 사용하지 않는다.
helper의 runtime probe에는 해당 process 설정이 `0`인지 나타내는 boolean만 기록하고,
불일치는 정적 오류로 실패한다. 원래 환경 값이나 환경 전체는 기록하지 않는다.

이 정책은 해당 관리 helper의 .NET debugging, profiling과 diagnostic port 사용을 끈다.
[Microsoft의 .NET 환경 변수 정의](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-environment-variables#dotnet_enablediagnostics)
CoreCLR의 공식 설명도 이 설정이 Linux·macOS의 debugging pipe와 semaphore 생성을
예방한다고 명시한다.
[CoreCLR managed debugging 비활성화](https://github.com/dotnet/runtime/blob/main/docs/workflow/debugging/coreclr/debugging-runtime.md#disabling-managed-attachdebugging)
stdout·stderr, native 자원 관측과 종료·export 증거는 계속 수집한다. JVM/JVMTI의 게임
정의 관측 설정이나 .NET 설치·이미지를 바꾸는 정책은 아니다. `purpose=jvm` 밖의
bootstrap, 일반 Rust 검사, 전역 PowerShell과 제품 게임 프로세스에는 이 override를
적용하지 않는다. 이미 발견한 FIFO·socket을 이름으로 무시하거나 삭제하지 않고,
알 수 없거나 중단된 소유 lease를 그대로 보존한다. 새 정책의 실제 3개 OS 실행은
미검증이며 이전 실패 관측과 소스 변경을 구분한다.

일반 읽기 전용 Git metadata, 문서 검토와 짧은 formatting 검사는 관리 프로세스
접점을 요구하지 않는다. 빌드 도구 자체의 최초 컴파일에도 저장소 밖의 고정 bootstrap
슬롯과 확인 가능한 소유 실행을 사용한다. 실제 bootstrap 및 관리 명령은 구현 후 등록한다.

### 빌드 명령 종료 뒤 소유 자식 정리

기본 `owned-tail-policy`는 `reject`다. 명령 leader가 종료한 뒤 2초의 유한한
종료 여유를 주고도 소유 자식이 남으면 supervisor 오류로 기록한다.
이번 Windows 최초 컴파일 검사에서는 Cargo 종료 뒤 소유 Job에 MSVC의
`VCTIP`가 남는 경로를 관측했다. MSVC가 만들 수 있는 잔여 telemetry 자식이라는
설명은 [Microsoft의 MSVC 도구 정의](https://github.com/microsoft/BuildXL/blob/main/Public/Sdk/Experimental/Msvc/VisualCpp/visualCpp.dsc)에서도 확인할 수 있다.

Cargo 최초 컴파일과 CI의 Cargo test 및 Clippy에는 명시적 `terminate-build`
정책을 선택한다. leader의 실제 종료 code를 확보한 뒤 2초가 지나도 자식이
남으면, Windows는 해당 실행의 Job만, Unix는 예약한 해당 실행의 process
group만 종료한다. 이름을 기준으로 프로세스를 무시하거나 소유 범위 밖으로
이탈시키지 않고, 전역 Visual Studio 설정이나 다른 사용자의 프로세스를 바꾸지 않는다.

이 경로는 원래 Cargo 종료 code를 보존하며 `owned_tail_terminated: true`와
`CompletedAfterOwnedTailCleanup`을 별도로 기록한다. 전체 native 종료와 출력
pipe의 끝, 완전한 capture 및 export를 확인해야 정리를 완료로 기록할 수 있다.
원래 code가 실패이면 전체 명령도 실패다. timeout, 취소, 출력 한도와 관측 실패는
성공으로 바꾸지 않는다. 최초 컴파일의 strict adoption proof에는
`owned_tail_terminated`를 명시하고, Unix의 종료 이유를 포함한 감독 결과는
`bootstrap-supervision.json`에도 기록한다.

이 선택은 재생성 빌드 도구의 수명을 위한 것이다. 제품의 쓰기 operation,
게임 적용, 결과 불명 상태와 복구에는 적용하지 않는다. 명령을 다시 실행하거나
불확실한 효과를 retry 가능으로 바꾸는 정책도 아니다. 정책 및 formatting 검사와
Rust 최초 인계 control 명령은 기본 strict 정책을 사용한다. 실제 OS별 fixture와
native 실행 결과를 확인하기 전에는 이 소스 선택을 3개 OS 검증 성공으로 표시하지 않는다.

### 게임 검증 자료와 정상 종료 입력

[MMMM-D050](DECISIONS.md)의 retained game storage는 build slot의 scratch나 cache가
아닌 명시 root를 사용한다. 현재 `ManagedBuild`를 borrow한 handle만 root/game의
열린 directory identity, 현재 build 소유권과 closed owner/lease를 검사한다. 새 root는
이 호출이 직접 생성한 경우만 초기화하고, 기존 빈 디렉터리·제품 DB/CAS·unknown
entry·중단 lease를 자동 채택하지 않는다. 기존 root는 정확히 일치하는 complete owner가
있을 때만 재사용한다. raw path나 token은 공개 Debug 및 완료 영수증에 넣지 않는다.

game tree는 내용·hash 없이 실제 파일 길이를 관측한다. 두 lexical secret guard를
parent와 leaf의 metadata보다 먼저 적용하고, 깊이 64·100000 entries와 원 checkpoint를
유지한다. 내부 link·reparse·hardlink도 거절하며 missing·I/O 오류를 0으로 채우지 않는다.
owner/lease를 포함한 선택 retained root의 크기를 현재 build slot/catalog와 checked
합산하여 기존 8/12 GiB에 대조한다. 다른 retained roots 전체의 quota나 관측 사이의
증가 방지는 보장하지 않는다. 초과 자료를 자동 삭제하지 않는다.

storage 완료와 실행 성공은 별도다. `complete`는 drain/export를 확인한 자료를 보존하고
known lease를 반납하는 API이며, 반환한 최종 `observed_before_release.within_budget`가
false일 수도 있다. 실행 소비자는 이 실제 최종 관측을 성공 gate에 반영해야 한다.
완료 owner 기록의 크기 증가로 넘은 경우도 `released_over_budget`와 실제 lease 해제
사실을 함께 남기고 전체 실행을 실패로 판정한다. 알려진 정리 완료를 결과 불명으로
바꾸거나 상한 초과 자료를 삭제하지 않는다.

실패한 명령도 실제 native drain과 증거 export를 확인하면 owner를 complete로 기록하고
해당 lease만 해제할 수 있다. world/config와 실패 진단은 보존하며 Drop·build finish·
cache eviction이 game root를 회수하지 않는다. 마지막 ownership 검증 뒤 path unlink는
기존 관리 catalog와 같은 cooperative filesystem 경계다. hostile 동일 UID가 그 사이
namespace를 바꾸는 경우의 atomic compare-inode-and-unlink 보장으로 해석하지 않는다.

`ProcessSpec.minecraft_stop`은 기본 None이며 기존 null stdin을 유지한다. opt-in
`MinecraftStopHandle`은 한 supervision에만 bind하고 writer나 임의 입력 bytes를 공개하지
않는다. 요청은 private `stop\n` 5 bytes만 전송한다. Windows는 실제 pipe capacity와
독점 writer를 확인한 cooperative 동기 write이며 Unix는 nonblocking/CLOEXEC writer다.
partial bytes·WouldBlock·실제 native error·close 불확실성을 보존한다. WouldBlock은
원 loop와 기한 안에서만 다시 검사하며 새 timeout이나 별도 무한 retry를 만들지 않는다.

정상 요청 뒤에도 자원·disk·capture·취소·기한·tail·drain 감독을 계속한다. 전송 실패는
기존 supervisor failure와 소유 scope 종료로 연결한다. pipe에 쓴 5 bytes와 close는 게임의
명령 처리·월드 저장·정상 stop acknowledgement가 아니며 결과도 `not_observed`다.
실제 CLI 연결, 동의한 EULA, final game cwd·launcher·ordinary host JAR origin 및 실제
게임 결과는 [구현 착수 조건](implementation-readiness.md)의 별도 관측으로 확인한다.

관리 CLI의 `run --retained-game-root <절대 경로>`는 `purpose=jvm`과 기본 tail
정책 `reject`를 요구한다. 직접 자식의 cwd와 `MMMM_RETAINED_GAME_DIR`를 검증한 game
디렉터리로 지정한다. 선택한 `--minecraft-stop-after-seconds`는 1~3600초이면서 전체
timeout보다 작아야 한다. stop 시계는 retained 입장 전의 요청 시점부터 시작하며,
원래 5초 관측과 저장량 검사 뒤 Running에서 한 번 요청하므로 정확한 spawn 시각이나
초 단위 전송 시각을 보장하지 않는다. 일반 run은 기존 null stdin과 cwd를 유지한다.

`--retained-game-launch-directory <절대 경로>`는 같은 game 디렉터리의 실행 경로
표현을 명시적으로 선택한다. 비밀·상대·상위 경로와 link/reparse 경계를 먼저
거절하고, 현재 소유 기록 및 held game handle과 native volume/file identity가
일치하는 경로만 허용한다. 원 retained root, owner digest와 lease는 바꾸지 않는다.
자동 별칭 검색·중단 소유권 채택·자료 이동이나 복사는 포함하지 않는다. 명시하지
않으면 기존 cwd를 사용한다. 실행자는 `-jar`와 게임에서 파생하는 입력도 같은 검증된
표현으로 고정해야 하며, 이 옵션이 Java argv를 재작성하거나 classpath를 승인하지는
않는다. 검사는 원 실행 기한의 협력 checkpoint를 따르며 hostile 동일 UID의 원자적
namespace 고정을 보장하지 않는다. 실제 경로 분리와 실행 결과는 별도 증거로 남긴다.

확인된 native drain 결과를 받은 뒤에는 실행과 별개인 단일 30초 보존 기한을 시작한다.
retained 측정, 64 KiB 단위 원시 로그 복사와 sync, complete 및 완료 receipt 기록은
같은 남은 기한을 소비한다. 원 timeout·취소와 native 결과는 유지하며 게임 실행을
재개하지 않는다. I/O 앞뒤의 협력 checkpoint이며 OS 호출 자체의 선점을 보장하지
않는다. 미확인 drain은 로그 복사와 retained 완료를 허용하지 않는다. 증거 기록이나
정리가 실패하면 원 실패와 구분해 보존하며 build lease를 자동 복구하지 않는다.

## 정리 경계와 복구

정리는 소유 루트의 정확한 대상만 수행한다. 최종 절대 경로, 포함 관계,
파일 종류, 소유 기록과 비활성을 작업 직전에 확인한다. junction과 링크 대상은
따라가 삭제하지 않는다. 알려진 소유 내부 링크는 대상 검증 후 링크 자체만 회수한다.
경로 또는 소유 identity가 바뀌면 보존하고 실패한다.

SQLite, CAS, operation journal, 복구 token, snapshot과 사용자 원본은 빌드 정리에서 제외한다.
`COMMIT_UNCERTAIN`, 부분 완료, readback 불일치 또는 복구 대기 operation이 참조하는
자료는 제품 GC도 보존한다. 실제 참조가 없는 orphan의 회수는 별도의 제품 GC 계약으로 수행한다.

기존 자료의 발견은 이동이나 삭제 권한을 의미하지 않는다. 알려지지 않은 디렉터리를
정책 파일에 등록해 자동 채택하지 않는다. 큰 정리에는 대상, 소유권, 활동 상태,
보존 근거와 실제 결과를 기록한다.

WSL의 파일 삭제와 가상 디스크의 물리 공간 반환은 다른 결과다. 일반 빌드와 테스트에서
전역 WSL 종료, 다른 배포판 종료 또는 디스크 압축을 수행하지 않는다.

## WSL과 독립 실행 환경

WSL Ubuntu의 사용은 Windows에서 가능한 실행 경로를 먼저 시도했으나 SAC/WDAC
차단으로 진행할 수 없는 경우로 한정한다. 원래 Windows 실행의 차단 오류와 시도한
경로·결과를 외부 증거에 보존하고, 대체할 작업의 범위를 정한다. 무한 재시도,
보호 기능 해제나 차단 우회는 Windows 경로의 시도에 포함하지 않는다.
Windows에서 정상 실행할 수 있으면 그 경로를 사용한다. 일반 빌드 오류나 편의는
Ubuntu 전환 근거가 아니다. Ubuntu 결과는 원래 Windows 실패와 별도로 기록하며
Windows 검사·게임 인수 또는 배포 후보의 성공으로 바꾸지 않는다.

전환 전에 현재 Git·worktree와 소유 경로, 적용 규약, OS·아키텍처, 생성물 루트와
lease를 확인한다. 비밀 파일 접근 금지, 소유 범위, 유한한 시간·자원·출력,
취소 후 자식 종료 확인과 제품 DB·CAS·복구 및 증거 자료 보존 규칙은 그대로 적용한다.
WSL의 재생성 Linux cache는 Linux 출력 루트를 사용한다. 보존 자료는 실제 호스트의
Windows 생성물 루트를 확인하고 변환해 내보낸다. 경로 확인 및 변환 실패는 오류로
반환하며 임의 루트로 대체하지 않는다. OS별 바이너리와 cache는 공유하지 않는다.

독립 Linux 또는 macOS 환경은 자신의 외부 출력 루트와 보존 위치를 사용한다.
Windows 경로나 WSL 변환을 요구하지 않는다. 임시 호스트에는 소유자, 목적,
보존 기간과 회수 위치를 등록하고 종료 전에 필요한 근거를 회수한다.

## CI 수명과 증거 보존

일회성 CI는 종료 조건이 있는 조사 및 실험 workflow다. 수동 실행이라는 이유만으로
상시 검증을 임시로 분류하지 않는다. 같은 목표는 공동 작업 전체에서 workflow 하나와
동시 run 하나를 재사용한다. 한 run 내부의 독립 job은 자원 예산 안에서 병렬 실행할 수 있다.

새 임시 workflow에는 목적, 실제 작성자와 공동작업자, 관련 PR, 종료 조건,
실행 횟수, 시간, worker, 메모리, 출력 예산과 정리 책임을 기록한다.
대기 또는 실행 중인 같은 목표의 run이 있으면 중복 dispatch하지 않는다.
다른 목표의 run을 취소해 실행 자리를 만들지 않는다.

목표가 끝나면 필요한 증거를 보존하고 임시 파일 제거를 PR로 처리한다.
workflow 파일, run, 로그와 artifact는 별도 정리 대상이다. 파일 제거가 기록 삭제를 의미하지 않는다.

원격 정리가 배정 범위에 포함된 경우 일반 종료 run은 목표당 최근 5개를 기본 보존한다.
run ID로 세고 re-run attempt는 별도 run으로 세지 않는다. 새 임시 artifact는 기본
14일로 설정하되 실제 허용 기간을 확인한다. run 및 로그 수명과 artifact 만료를 구분한다.

열린 PR의 필수 근거, 미해결 실패, 복구 자료와 릴리스 원본은 개수나 나이만으로 삭제하지 않는다.
만료 전 source SHA, run과 attempt, 결과, 한계, artifact digest와 회수 위치를 보존한다.
릴리스 증거는 배포 파일과 함께 장기 보존하며 만료될 링크만 남기지 않는다.

## 관리 도구 인수

G0에서 3개 OS의 정상 종료, 명령 실패, timeout, 취소, 남은 자식, hard kill,
중단 lease, busy lease, 소유 기록 변경과 경로 이탈을 시험한다. 한도 초과,
cache miss, 오래된 완료 슬롯 회수와 보존 위치 내보내기 실패도 확인한다.

symlink, Windows junction, 경로 충돌과 알 수 없는 파일의 정리를 확인한다.
사용자 원본, 영속 DB, CAS, 복구 자료, 다른 checkout 및 릴리스 증거가 정리 대상에
포함되지 않음을 검증한다. macOS의 자식 종료 확인은 별도 필수 항목이다.

## Rust 기반 CI 소스와 최초 컴파일

`.github/workflows/foundation.yml`은 Rust 기반 검사 workflow의 소스다.
Windows x64, Linux x64와 macOS ARM64를 각각 독립 job에서 실행하도록 구성한다.
현재 파일의 존재는 workflow 실행 또는 성공 근거가 아니다. 실제 run, attempt,
checkout SHA와 OS 및 architecture를 확인한 뒤 관측 결과를 기록한다.
3개 job을 모두 실행하고 집계하는 `foundation-result`는 실패, 취소와 미실행을
성공으로 처리하지 않는다. 실제 성공을 확인하기 전에는 필수 상태 검사로 등록하지 않는다.

runner는 `windows-2025`, `ubuntu-24.04`, `macos-15`로 명시하며 시작 시 실제 OS와
process architecture를 검사한다. macOS runner 이름과 architecture 대응은
[GitHub runner 문서](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)를
기준으로 선택했고, 이미지 버전은 매 run의 `ci-context.json`에 별도로 기록한다.
Rust `1.96.0`과 rustfmt 및 Clippy를 CI 임시 출력 루트의 `toolchain`에 설치한다.
설치 단계는 5분으로 제한하며 관리 build cache와 수명을 구분한다.
cache를 원격 복원하거나 다른 run의 성공 근거를 재사용하는 기능은 현재 workflow에 없다.
CI는 source의 `Cargo.lock`을 요구하고 routine 최초 컴파일에도 locked resolution을
사용한다. 승인한 의존성 변경을 반영하는 개발 최초 컴파일에는 Windows의
`-UpdateLock` 또는 Unix의 `--update-lock`을 명시적으로 선택할 수 있다.
이 선택은 lock 갱신을 허용하며, CI가 자동으로 재시도하거나 선택하지 않는다.

개발·검사 빌드의 `sha2`는 package별 `opt-level=3`으로 컴파일한다. 전체 실행 파일과
선택 입력의 SHA-256, 원래 request 기한·입력 한도·전후 pin 검사는 유지한다.
이는 Linux startup에서 관측한 부모 image hash 비용에 대응하는 명시적 build 입력이며,
child 지연 원인 확정이나 실제 Unix 성공을 뜻하지 않는다. 의존성 버전과 알고리즘,
release profile 및 나머지 crate의 debug·overflow 검사를 바꾸지 않는다.
설정은 [Cargo profile override](https://doc.rust-lang.org/cargo/reference/profiles.html#overrides)를
따르며 실제 native 실행과 digest 검사를 별도로 확인한다.

최초 Cargo 실행은 Windows의 `tools/bootstrap/bootstrap.ps1` 또는 Unix의
`tools/bootstrap/bootstrap-unix.py`가 맡는다. Unix launcher의 Python 코드는
첫 Rust 도구를 만들기 위한 build infrastructure에만 사용한다. 제품 계약 처리,
Coordinator와 변환 구현은 Rust 책임을 유지한다. Unix에는 Python 3.10 이상,
Linux procfs 또는 macOS libproc의 native process 관찰이 필요하다.
관찰 API, 출력 루트나 소유 기록이 유효하지 않으면 빌드를 시작하지 않거나 실패를 반환한다.

Windows launcher는 소유 lease를 획득하기 전에 Cargo 실행 파일을 확인한다.
CI가 설정한 `MMMM_CARGO`가 있으면 하나의 절대 일반 파일 경로여야 한다.
설정이 없으면 첫 번째 application 경로를 선택하고, 정상 rustup proxy가 링크인
경우에는 검증한 rustup의 `which cargo`가 반환하는 실제 toolchain 파일을 사용한다.
복수 경로를 하나의 명령 문자열로 합치거나 executable 링크를 그대로 실행하지 않는다.
실행 파일 사전 검사 실패는 native process scope나 lease를 생성하지 않는다.
native 시작 실패의 진단은 작업 이름, 캡처한 Win32 오류 번호와 해당 시스템 메시지를
최대 512자로 보존하며 명령 인수와 환경 값은 포함하지 않는다.
Windows script의 실패는 예외와 native receipt로 판정한다. `$LASTEXITCODE`는
가장 최근 native 명령의 상태이므로 PowerShell script 호출의 완료 판정으로 사용하지 않는다.
Unix launcher의 실패 진단은 고정 단계명과 native operation, errno를 기록하며
파일명·명령 인수·환경 값은 포함하지 않는다. 원래 오류를 보존하고 유효한 evidence
root가 확보된 경우 작은 `bootstrap-failure.json`을 저장한다.

Unix launcher는 별도 session의 leader를 먼저 만들고, 부모가 native identity를
확인한 뒤 보내는 시작 신호가 있어야 Cargo를 실행한다. leader는 자식 종료 이후에도
살아 있거나 unreaped 상태로 남아 SID와 process group identity를 예약한다.
native group에 실행 중인 자식이 없다는 두 관측과 출력 pipe EOF를 확인한 뒤 leader를 회수한다.
부모가 종료되어 제어 pipe에 EOF가 오면 wrapper는 자신의 group을 종료한다.
wrapper 자체에도 유한한 watchdog 기한을 둔다. Linux와 macOS의 관찰 코드는 각각 다르다.
record와 log는 no-follow directory descriptor를 따라 열고, 연 부모 directory의
device와 inode를 소유 시점의 identity와 비교한다.

처음 선택한 자원 한도는 Cargo worker 2개, 1200초, 합계 출력 128 MiB,
slot 8 GiB, catalog 12 GiB이며 크기는 5초마다 관측한다. Windows bootstrap은
Job Object의 2 GiB memory와 32개 process 한도를 사용한다. Linux bootstrap의
`RLIMIT_AS`는 process마다 2 GiB의 주소 공간 상한을 물려주며, 실행 중인 group
구성원은 wrapper를 제외하고 32개를 관측 한도로 검사한다. Unix의 이 한도는
Job Object 전체 memory 상한이나 커널 process quota와 같은 보장이 아니다.

Darwin의 2 GiB `RLIMIT_AS`는 실제 runner에서 기존 VM 예약보다 작아
Cargo 시작 전 `EINVAL`을 반환했다. `managed-darwin-resources/1`은 512 GiB
VM 한도의 설정과 readback, 각 소유 process의 관측 VM 한도를 적용하고,
전체 live 소유 그룹의 RSS와 physical footprint 합계를 각각 2 GiB로 검사한다.
Python bootstrap의 wrapper도 memory 합계에 포함하며 worker는 32개까지 허용한다. 목표 관측 주기는
100 ms이고 마지막 완전한 성공 관측으로부터 1초를 넘으면 실패한다. native 오류,
짧은 구조체 응답, identity 교체와 SID/PGID 이탈을 0으로 대체하지 않는다.
policy, API flavor, sample 수, peak와 최대 관측 간격을 증거에 남긴다.
Python bootstrap은 wrapper를 memory 합계에 포함한다. Rust 관리 명령은
해당 명령의 소유 그룹을 관측하며 supervisor wrapper는 합계에서 제외한다.

디렉터리 목록과 metadata 순회 및 유한한 출력 배치 사이에도 fallible native
체크포인트를 수행한다. 실제 전체 소유 범위의 identity와 자원 관측에 성공한
경우에만 마지막 표본 시각을 갱신한다. 저장 크기 검사 콜백이 native 오류를
다른 문자열로 감싸거나 무시해도 최초 오류와 종료 원인을 보존한다. 단일 OS 호출이
1초 이상 막히는 경우에는 관측 제한 초과를 그대로 반환한다.

이는 kernel resident memory quota가 아니며 관측 사이의 초과와 fork/exec의
일시적 사용을 완전히 막는 보장은 없다. Python bootstrap은 부모의 native 확인을
마친 뒤 worker를 허용한다. Rust 감독기는 시작 전 native self preflight와
async-signal-safe 설정을 하고 exec 직후 첫 소유 process 관측을 수행하므로,
첫 관측 전에 명령이 실행될 수 있다. 첫 관측 실패도 해당 소유 범위 종료와 drain을
거치며 lease를 보존한다. 실제 macOS 기반 CI에서 이 정책의 실행과 전체 기반 검사
성공을 확인했으며, 새 제품 입력의 성공과 JVM 적합성은 별도로 검증한다.

Rust 관리 명령의 `ResourcePolicy`는 현재 OS와 목적에 일치해야 한다. Windows는
자식 시작 전에 Job의 kill-on-close, commit 2 GiB와 process 32개 설정을 readback으로
대조한다. 실행 중 같은 Job의 실제 peak commit과 process 수를 관측한다. Linux는
자식의 async-signal-safe 시작 경로에서 `RLIMIT_AS` soft 및 hard 각각 2 GiB를
설정·대조하며, 실행 중 원래 SID와 PGID의 소유 그룹을 32개까지 관측한다. 그룹
리더는 포함하고 supervisor wrapper는 제외한다. Linux의 설정은 process별 VM
상한이며 그룹 전체 memory, kernel resident memory나 kernel process quota가 아니다.
두 정책은 100 ms 목표로 관측하고 설정·readback·표본 수·peak·최대 표본 간격을
`resource_limits`에 보존한다. 일반 Linux process 수 검사에는 별도의 1초 표본 간격
실패 조건을 추가하지 않는다. 아래의 좁은 JVM Pending은 별도 조건이다.
실제 Windows 자식의 설정 및 readback 검사는 통과했으며, 다른 OS의 새
일반 정책과 JVM의 주소 공간 요구는 실제 후속 실행으로 확인한다. 이전 bootstrap
또는 이전 감독 도구의 성공을 새 일반 명령 정책의 완료 근거로 사용하지 않는다.

정확한 `purpose=jvm`은 Linux에서만 `managed-linux-jvm-resources/1`을 선택한다.
이 정책은 process별 `RLIMIT_AS` soft 및 hard를 고정 512 GiB로 설정하고 정확한
readback을 확인한다. 소유 그룹의 `smaps_rollup` `Rss` 합계를 2 GiB, live process를
32개까지 관측한다. PowerShell launcher와 Java·Gradle·test 자식을 포함하고 Rust
supervisor는 제외한다. 일반 `checks`와 다른 목적의 Linux 주소 공간 2 GiB,
Windows Job과 Darwin의 기존 설정은 유지한다. 숫자 상한 옵션, 프로그램 이름에
따른 추정, 실패 뒤 fallback·상한 확대·자동 재시도는 제공하지 않는다.

Linux의 일반 process 수 검사와 JVM 자원 검사는 고정 procfs root FD, 그 FD를
기준으로 연 숫자 PID directory 및 원래 `stat` FD를 사용한다. 원래 leader의
PID·starttime·SID·PGID를 확보하고 unreaped child reservation을 유지한다. member의
RSS 전후에도 같은 identity를 대조한다. `stat`은 8 KiB, `smaps_rollup`은 32 KiB,
directory 순회는 100000 entry로 제한하며 읽기 횟수와 interruption에도 상한을 둔다.
`Z`·`X` 상태라도 thread가 남으면 종료로 제외하지 않는다. 살아 있는 process의
permission·malformed 자료·identity 오류를 0 또는 이전 값으로 바꾸지 않는다.
RSS의 `ENOENT`·`ESRCH`만으로 종료를 판정하지 않고 원래 stat의 실제 종료를 확인한다.
이미 성공적으로 읽은 RSS와 VM은 바로 뒤의 종료로 없애지 않고 관측 사실로 보존한다.
초기 leader identity를 확보하지 못하거나 reservation을 잃으면 group signal과 drain
완료를 허용하지 않으며 lease와 진단을 보존한다.

D046의 Linux JVM Pending은 실제로 확인한 예약 leader의 좁은 RSS 미완료 전이에만
적용한다. 원 anchor와 미회수 Child 예약이 유효하고, RSS 전후 PID·start·group·session이
원 identity와 같으며 모두 Zombie·threads 2여야 한다. 실제 RSS open ESRCH와 이미
검증한 whole-group pidfd의 실제 TerminalPoll/NotReady·errno 없음도 함께 요구한다.
같은 관측 안에서 reader를 다시 부르지 않는다. 기존 100 ms 관측 시도를 마지막 완전
표본 시각과 분리하고, 이전 완전 표본부터 1,000 ms 안에서만 Pending을 허용한다.
이전 완전 표본이 없거나 창이 만료되면 원 오류와 새 종료 이유를 보존해 실패한다.
늦은 Complete도 peak·sample 수·완료 시각을 갱신하기 전에 같은 창을 검사한다.

Pending leader의 RSS는 미관측으로 두고 다른 member의 실제 RSS·VM·live lower bound로
기존 상한을 계속 검사한다. Pending은 완전 표본·peak·마지막 성공 시각·RSS 0·empty나
drain이 아니다. count-only empty만으로 미해결 Pending의 정상 reap을 허용하지 않으며,
다음 정규 관측이나 유한한 실패를 기다린다. hard failure 후의 실제 물리 drain은 별도로
확인한다. 원 오류와 닫힌 stat/pidfd 사실의 first·last·count를 후속 실패에도 보존한다.
새 native 조회·poll·sleep·자동 한도 확대를 추가하지 않고, 일반 Linux 또는 Pending이 없는
JVM에 전역 1초 gap 제한을 적용하지 않는다. 이는 새 조건부 관측 유예 정책이며 이전
Linux 실행에 이미 존재한 보장으로 해석하지 않는다.

D062와 D071은 이미 열거해 원 leader에 묶인 owned member의 정확한 전이에도 같은
Pending 수명을 적용한다. member는 전후 stable Zombie·threads 2 또는 4, reserved leader는
기존 2 또는 3만 허용한다. 원 full identity·실제 RSS open ESRCH·validated whole-group
pidfd의 flags 0 및 실제 TerminalPoll/NotReady/errno 없음·held original leader와 순회 말미의
leader 검사가 모두 필요하다. count 변화, member 3·leader 4와 다른 오류는 계속 실패한다.
member의 Z4를 종료나 RSS 0으로 바꾸지 않으며 prior Complete·1000ms·부분 상한·late
Complete와 reap fence를 그대로 적용한다. 새 조회·retry·sleep·상한 변경은 없다. 이 조건의
소스·순수 검사와 실제 Linux Pending 진입/회복은 실행별 근거로 구분한다.

[D078](DECISIONS.md)의 count-only 경로는 이전 RSS Pending과 별개다. 실제 원
directory/stat와 flags 0 PIDFD를 lifetime마다 한 번 묶고 nonleader occupied 슬롯을
최대 32개로 보존한다. 실패·unavailable·retired도 슬롯을 차지하며 원 stat의 실제
ESRCH 전에는 임의 eviction·재bind하지 않는다. 96 FD는 이 member 보존 상한이고
별도 leader/root·유한 namespace와 enumeration 임시 FD를 포함한 전체 peak가 아니다.
정확한 OwnedMember Z2→X0·동일 PID/start·후행 group/session -1/-1·유효한 원 leader
reservation에서 같은 PIDFD의 실제 poll(0) Ready로 발급된 private proof만 소비한다.
leader·다른 전이·실제 Ready 부재는 원 오류로 남긴다. 이 결과는 member 하나의 역사적
퇴출이며 RSS 0·기존 Pending 해소·전체 group drain을 발급하지 않는다. 전체 scan과
마지막 leader 검사, 기존 empty·출력 EOF·reap 조건은 계속 필요하다.

Linux native 관측 control은 호출마다 원 취소·command/absolute deadline을 빌린다.
hard-stop 뒤에는 이미 고정한 stopping_at+drain_timeout에서 기존 FD 관측과 close만
허용하며 새 bind를 막는다. close는 원 기한·취소 실패도 보존하면서 실제 소유 FD를
한 번씩 소비하고 후행 오류를 함께 기록한다. Linux close/EINTR에 같은 숫자 FD를
재시도하지 않는다. first/last/count/peak와 실제 before/after·poll·query/close 진단은
보존 자료이며 identity나 종료 권한으로 다시 입력하지 않는다.

RSS 합계는 각 process를 순서대로 읽은 관측이다. 공유 페이지를 process마다 포함하며
그룹 전체의 동시 snapshot, 유일한 물리 메모리 사용량이나 kernel resident quota가
아니다. `kernel_resident_quota=false`, `kernel_process_quota=false`,
`group_snapshot_atomic=false`, `sampling_may_overshoot=true`를 기록한다. 100 ms는 목표이고
실제 sample 수, peak RSS·VM·process 수, 최대 sample 간격과 미완성 memory sample을
보존한다. process 상한 초과로 RSS 전체를 읽지 않은 sample은 완전한 memory sample로
기록하지 않는다. 관측 위반과 오류는 소유 종료·출력 수집·drain 경로로 전달한다.
실제 Linux 정책과 Gradle 결과는 구현 착수 조건의 실행별 기록으로 확인한다.
정책 소스나 이전 성공만으로 현재 실행의 적합성을 선언하지 않는다.

Linux native metadata 실패는 process 역할(reserved leader, 열거한 candidate,
owned member), 고정 file 역할(pid directory, stat, RSS rollup), open·rewind·read
단계 및 OS error kind/code를 유한하게 기록한다. 원시 proc 토큰, comm과 개인 경로를
진단에 넣지 않는다. missing pathname 또는 open 단계의 ENOENT·ESRCH를 자동으로
종료 증거로 승격하지 않으며, kernel의 실제 종료와 접근 실패를 구분할 후속 관측이
필요하다.

`definition-startup`은 Windows x64, Linux x64와 macOS ARM64의 개발용
JNI/JVMTI fixture 관측 명령이다.
기존 고정 JDK archive·modules·명시적 native library와 실제 Java executable·observer
library·JAR·build source manifest를 최대 32개, 합계 512 MiB로 선택한다. archive
role은 192 MiB로 제한한다. Windows의 선택 파일과 조상 디렉터리는 실제 핸들을,
Unix는 root부터 열린 directory FD와 그 상대 경로 관계를 유지하며 size·identity·SHA를
실행 전후 대조한다. secret 이름과 플랫폼별 link·특수 파일·경로 alias를 거절한다.
Unix의 관측은 다른 writer나 JVM의 pathname 재개방을 원자적으로 배제하지 않는다.
이 선택과 hash는 JDK 전체 image나 agent roster의 source admission을 발급하지 않는다.

준비·native 실행·같은 stdout 핸들 판독·입력 재검사·ABI2 decode와 hash는 원래
60초 절대 기한을 공유한다. 남은 프로세스 시간이 1초 미만이면 올림하지 않고
실행을 거절한다. 원래 native drain 15초와 bounded evidence export 5초를 별도로
기록한다. 고정 fixture heap 256 MiB·metaspace 256 MiB·code cache 64 MiB,
일반 Windows 2 GiB Job·process 32, raw ABI2 18 MiB·combined log 64 MiB를
사용한다. Windows의 Java injector 환경 네 개는 원래 값을 읽거나 출력하지 않고
빈 값으로 override한다. Unix의 이 route는 환경 상속을 제거하고 owned scratch의
`java.io.tmpdir`와 `UsePerfData` 비활성화를 고정한다. Linux는 D028의 고정 JVM
VM/RSS 정책, Darwin은 관리 도구의 별도 VM/RSS/footprint 정책을 적용한다.
실제 3개 OS 실행과 C header ABI의 근거는 구현 착수 조건의 해당 source SHA와
run 기록에 연결하며, 별도 stdio worker 정책이나 게임 인수의 근거로 확대하지 않는다.
JVM unified logging의 기본 warning·error 선택은 stderr로 다시 구성하여 원래
bounded 진단에 보존한다. stdout은 단일 바이너리 프레임으로 엄격히 검사하며,
추가 문자열을 찾거나 잘라낸 뒤 성공으로 처리하지 않는다.

process outcome 존재만으로 시작을 선언하지 않는다. supervisor의 private capture
receipt가 실제 spawn 뒤 true, 생성 전 취소·만료에 false를 기록하며, outcome 없는
오류는 미확정으로 남긴다. 일반 `run`의 기존 JSON과 기본 상대 기한은 유지한다.
성공과 실패의 원래 outcome, 선택 입력 pin, raw frame 또는 candidate, 후속 검사
오류를 보존한 뒤 기존 export·finish 수명을 따른다. 이 관측은 실제 게임 target
profile, 쓰기 허가, SAM·참조 전체 closure 또는 제품 인수 완료를 의미하지 않는다.

후보 생산자의 raw stdout·stderr 보존은 supervisor가 실제 생성한 두 원 capture
핸들에서 수행한다. Windows의 원 쓰기 핸들이 열린 동안 같은 경로를 더 좁은 share
mode로 다시 열거나, export를 위해 writer 보호를 완화하지 않는다. native drain 뒤
원 stream의 기록된 길이·regular file·EOF·전후 크기를 검사하고 최대 64 MiB,
64 KiB chunk와 5초의 로컬 판독 예산 및 원 요청의 소유·취소·기한 검사를 적용한다.
이 진단용 판독은 nonzero·취소·불완전 출력의 원 outcome을 보존한다. 성공한 stdout의
strict 소비자 gate를 충족한 것으로 바꾸지 않으며, export 실패에는 stream과 단계를
남긴다. 명령·strict 판독·export·finalization 실패는 함께 남겨 최초 원인을 덮지 않는다.

Cargo metadata와 compiler-artifact의 경로는 Windows에서 일반 drive와 verbatim drive
표기를 섞어 반환할 수 있다. 후보의 경로 검사는 기존 `Path` 비교가 실패한 경우에만
정확한 두 drive 표기의 native UTF-16을 대응시킨다. drive와 나머지 경로의 대소문자 및
component 경계를 그대로 비교하고, prefix strip은 원 reported 경로의 tail을 빌린다.
UNC·device namespace·상대 경로·dot/parent component·중복 separator·slash 차이·ADS·
후행 dot/space와 DOS 장치 이름은 이 추가 분기에서 거절한다. 허용 경로에 case folding·
trim·파일시스템 resolve를 적용하지 않고 실제 파일을 읽는 대상도 바꾸지 않는다.
Unix와 일반 비밀 경로 guard는 유지한다. 이는 Cargo의 경로 표현을 비교하는 경계이며
파일 identity, source provenance나 전체 toolchain closure의 별도 증명을 대체하지 않는다.

HEAD source의 `crates/mmmm-coordinator/src/credential.rs`와 `credential_owner.rs`는
Cargo에 등록된 Rust 구현 모듈이며 비밀 저장 자료가 아니다. 실제 Git HEAD 목록과
그 byte 검증된 source snapshot에서 이 두 정확한 저장소 상대 경로만 구분한다.
일반 파일·image·registry dependency·cache의 비밀 이름 차단에는 예외를 적용하지
않으며 `.json`, 임의 `.rs`, 다른 경로·접미어·대소문자나 separator 정규화로 확대하지
않는다. source 목록은 archive가 내용을 읽기 전에 전체 검사하고 snapshot은 source
루트 기준의 경로를 다시 검사한다. 이 두 모듈의 경로·역할이 바뀌면 소스 등록과 검사
경계를 다시 검토하며 다른 비밀 파일을 읽어 예외 여부를 판단하지 않는다.

Linux JVM native VM probe는 일반 `checks`의 이미 낮아진 hard limit 안에서 실행하지
않는다. 고정 `jvm` 소유 실행에서만 명시적으로 선택하는 ignored 검사이며, inherited
512 GiB readback과 8 GiB의 유한한 VM 예약을 확인한다. 실제 resident allocation은
소량으로 제한한다. 이 probe나 pure parser·tracker 검사를 실제 전체 JVM 인수로
보고하지 않는다.

저장 크기 관측의 native 실패에는 단계, 소유 생성물 루트 기준 경로, 시도 횟수와
OS 오류를 유한하게 남긴다. 개인 절대 경로와 보호된 이름은 진단에 넣지 않는다.
접근 거부를 무시하거나 이전 크기로 대체하지 않는다.
크기와 process 수는 관측 사이 증가할 수 있다. 독립 session으로 의도적으로 이탈하는
프로그램을 격리하는 보안 sandbox를 제공한다는 주장도 하지 않는다.

빌드가 성공하면 export한 `bootstrap-process.json`의 종료와 보존 근거를 새 Rust
도구의 `bootstrap-complete`가 검사하고, 동일한 소유 slot 및 lease만 인계한다.
Unix 최초 컴파일이 실패하면 현재 구현은 소유 lease와 cache를 보존한다.
과거 실패 또는 중단 lease를 자동 채택하거나 삭제하는 옵션은 제공하지 않는다.
Rust 인계 이후에는 `mmmm-xtask run`을 통해 index 정책, formatting, workspace
tests와 Clippy를 실행한다. 일반 명령 출력 한도는 Rust runner의 64 MiB를 사용한다.
같은 `ci-checks` slot을 재사용하여 각 명령마다 대형 Cargo 트리를 만들지 않는다.

각 OS job은 최대 75분, matrix는 최대 3개 job을 병렬 실행한다. artifact에는
source 및 runner 식별, bootstrap proof, 관리 실행 영수증과 원시 로그만 포함하고
build cache와 제품 data를 넣지 않는다. artifact 보존 기간은 14일이다.
입력 checkout은 credential을 지속 저장하지 않고 workflow 권한은 `contents: read`다.
공식 checkout과 artifact action은 확인한 commit SHA로 고정한다.

이 구성은 Rust 기반 구현 검증을 위한 것이다. 실제 3개 OS bootstrap의 정상,
실패, timeout, 취소, 남은 자식, 부모 강제 종료와 path 및 lease 경합 검증은
각 OS에서 수행한 결과로 연결해야 한다. 이 workflow 소스만으로 G0 인수,
게임 서버 및 클라이언트 인수 또는 `v0.1.0` 배포를 완료로 표시하지 않는다.
