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

슬롯에는 소유 schema, checkout 식별, 용도, 소유 token, 프로세스 식별,
상태와 마지막 완료 시각을 기록한다. 원자적 기록 교체와 flush를 사용한다.
개인 절대 경로가 필요한 소유 기록은 로컬 내부에 두고 공유 영수증에서는 제거한다.

한 관리 카탈로그의 소유 lease가 입장, 재사용과 회수를 직렬화한다.
동일 카탈로그에서 동시에 관리하는 빌드는 하나다. busy 상태는 명시적으로 반환하며
상한 없이 기다리지 않는다. 빌드 내부의 worker와 서로 다른 CI runner는 별도 자원 범위에서 병렬 실행할 수 있다.

활성 또는 중단 lease를 자동으로 훔치지 않는다. PID가 없거나 시간이 지났다는 사실만으로
삭제하지 않는다. 수동 복구는 이전 소유 실행의 종료, 정확한 경로, token과 기록을
대조한 뒤 배정된 소유 범위에서 수행한다.

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

일반 Rust 관리 명령의 `ResourcePolicy`는 현재 OS와 일치해야 한다. Windows는
자식 시작 전에 Job의 kill-on-close, commit 2 GiB와 process 32개 설정을 readback으로
대조한다. 실행 중 같은 Job의 실제 peak commit과 process 수를 관측한다. Linux는
자식의 async-signal-safe 시작 경로에서 `RLIMIT_AS` soft 및 hard 각각 2 GiB를
설정·대조하며, 실행 중 원래 SID와 PGID의 소유 그룹을 32개까지 관측한다. 그룹
리더는 포함하고 supervisor wrapper는 제외한다. Linux의 설정은 process별 VM
상한이며 그룹 전체 memory, kernel resident memory나 kernel process quota가 아니다.
두 정책은 100 ms 목표로 관측하고 설정·readback·표본 수·peak·최대 표본 간격을
`resource_limits`에 보존한다. Linux에 별도의 1초 표본 간격 실패 조건을 추가하지
않는다. 실제 Windows 자식의 설정 및 readback 검사는 통과했으며, 다른 OS의 새
일반 정책과 JVM의 주소 공간 요구는 실제 후속 실행으로 확인한다. 이전 bootstrap
또는 이전 감독 도구의 성공을 새 일반 명령 정책의 완료 근거로 사용하지 않는다.

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
