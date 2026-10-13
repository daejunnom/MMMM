# JVM CI 검증 기반

`.github/workflows/jvm.yml`은 Windows x64 (`windows-2025`), Linux x64
(`ubuntu-24.04`), macOS ARM64 (`macos-15`)에서 같은 후보 source SHA를 확인하고
Java SDK, 호스트 core 및 public Java adapter 테스트와 Fabric 호스트 컴파일·테스트를
실행하도록 작성한 기반이다. 후보 `1498ea14f253b03bf97a72323feddad934118b03`의
[실제 첫 실행](https://github.com/daejunnom/MMMM/actions/runs/38462192682)은 세 runner 모두 실패했다.
Windows는 Rust bootstrap 생성물 관측에서, macOS는 JVM helper의 읽기 전용 PowerShell
자동 변수 대입에서, Linux는 제한된 PowerShell의 helper 시작 전 ICU 초기화에서 멈췄다.
이 문서와 workflow 소스는 3개 OS 인수 성공을 의미하지 않는다.

후보 `43fc99447942b83c3ad9b76d8a748cf7ee528d93`의
[다섯 번째 실제 JVM 실행](https://github.com/daejunnom/MMMM/actions/runs/38472862594)은
Windows 검증이 성공하고 macOS와 Linux가 실패했다. 두 Unix 실행의 원본 관리 증거에서는
`native_kind=unix_fifo`, `generated_relative=scratch/clr-debug-pipe-<pid>-<start>-in`을
관측했다. 해당 특수 파일 때문에 측정과 evidence export가 실패했으며 소유 슬롯과 lease를
보존했다. 이 관측을 근거로 채택한 D025의 새 설정은 아래와 같고 아직 실제 실행하지 않았다.

PR은 merge commit 대신 `pull_request.head.sha`를 checkout한다. event SHA,
PR head/base SHA, repository, workflow, run, attempt 및 실제 runner image를
외부 `ci-context.json`에 기록한다. 빌드 전후 Git HEAD 및 관련 추적 소스의 bytes를
확인하며, JVM 소스·Gradle 설정·계약·예제·검증 helper와 공유 runtime probe의 SHA를
별도 manifest에 둔다.
원격 cache 또는 이전 성공 증거를 가져오는 기능은 없다.

## 도구와 입력

Rust `1.96.0`의 기존 플랫폼 bootstrap으로 해당 OS의 관리 실행 도구를 만든다.
다른 OS에서 생성한 executable을 전달하지 않는다. 그다음 `mmmm-xtask run`의
고정 `jvm` 슬롯 안에서 `tools/bootstrap/jvm-ci.ps1`을 실행한다.
JDK와 Gradle 다운로드 및 압축 해제도 이 소유 실행의 시간·출력·disk 관측 범위에 있다.

JDK 배포 tag는 Eclipse Temurin `25.0.4.1+1`, Gradle 배포는 `9.6.0`으로 고정한다.
검사한 SHA와 다르면 중단하며 다른 버전이나 `latest`로 바꾸지 않는다.

| 배포물 | SHA-256 |
|---|---|
| `OpenJDK25U-jdk_x64_windows_hotspot_25.0.4.1_1.zip` | `00c847d804f4a78e9f04f2683faf14fed898535b177b7fc704486cb0284e9283` |
| `OpenJDK25U-jdk_x64_linux_hotspot_25.0.4.1_1.tar.gz` | `dbb698396d478e7fa2b1e50f4103324b2a99b90569ee27c33f2261f9215cf41e` |
| `OpenJDK25U-jdk_aarch64_mac_hotspot_25.0.4.1_1.tar.gz` | `61979887f7506a24a57439ff99adb8b3a7fc89977d9cfe3b8984f58a981b7b9d` |
| `gradle-9.6.0-bin.zip` | `bbaeb2fef8710818cf0e261201dab964c572f92b942812df0c3620d62a529a01` |

출처는 [Temurin 고정 release assets](https://github.com/adoptium/temurin25-binaries/releases/expanded_assets/jdk-25.0.4.1%2B1)와
[Gradle 공식 checksum 목록](https://gradle.org/release-checksums/)이다.
checkout 및 artifact action도 기존 기반에서 사용한 공식 repository의 고정 commit을
사용한다. 사용한 SHA는 [checkout commit](https://github.com/actions/checkout/commit/fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09)과
[upload-artifact commit](https://github.com/actions/upload-artifact/commit/ea165f8d65b6e75b540449e92b4886f43607fa02)에서 확인할 수 있다.

`jvm-archive.py`는 Python 표준 라이브러리를 사용하는 빌드 infrastructure다.
제품 도메인·변환·Coordinator 책임을 옮기지 않는다. archive SHA를 확인한 같은
파일 handle에서 해제하고, 고정 archive root, 물리 staging 경계, portable path,
Unicode 및 대소문자 충돌, 파일과 디렉터리 충돌을 검사한다. ZIP64, hardlink,
sparse 및 특수 파일은 거절한다. 내부 symlink는 archive member graph에서
최대 16단계로 해석하고 regular member에 도달할 때만 bytes를 복사한다.
symlink 객체를 만들지 않는다. Unix 파일은 소유자의 읽기·쓰기와 필요한 실행 권한을 둔다.

archive는 하나당 512 MiB, member는 10000개, 파일은 256 MiB,
해제된 bytes는 archive당 2 GiB로 제한한다. JDK root는 `jdk-25.0.4.1+1`,
macOS Java 경로는 그 root의 `Contents/Home/bin/java`라는 계약으로 검사한다.
이 예상 배치를 실제 3개 OS archive 해제 결과와 대조하는 검증은 아직 미실행이다.
이전 또는 실패한 extraction을 덮어쓰거나 자동 채택하지 않는다.

## 실행과 결과

Gradle 사용자 홈, 프로젝트 cache, 모든 module build와 임시 파일은 관리 슬롯에 둔다.
Windows는 검증한 동일 물리 경로의 DOS 표기를 native Java에 전달하며 UNC와 device 경로,
248자 이상의 native 경로를 거절한다. Java `GradleMain`을 직접 실행하고, 자동 JDK
검색·다운로드, shared build cache, configuration cache와 parallel project 실행을 끈다.
현재 설정의 worker 2개, test fork 1개, test heap 512 MiB를 사용한다.
launcher heap은 256 MiB, 단일 사용 Gradle daemon heap은 1 GiB다.
`--no-daemon`에서도 JVM 설정이 다르면 단일 사용 daemon이 생길 수 있으며 해당
소유 process scope 안에서 종료를 확인한다.

필수 task는 `:provider-sdk:test`, `:host-core:test`, `:public-java-adapter:test`,
`:fabric-host:compileJava`, `:fabric-host:test`다. `--rerun-tasks`로 이번 실행을 요구하고 `--continue`로
독립 task의 결과도 보존한다. task의 `executed`, `failed`, `up_to_date`, `skipped`,
`no_source`와 `no_work`를 구분한다. 이 profile에서는 필수 task의 실제 실행만 성공으로
받으며 이전 XML이나 cache hit를 현재 실행의 통과로 채택하지 않는다.

각 테스트 module의 이번 XML을 유한한 개수와 bytes 안에서 읽고, suite count와 실제
testcase count를 대조한다. 원본 XML SHA, 테스트·실패·오류·skip 수를 외부 요약에
남긴다. 최소 한 테스트의 실제 통과와 실패·오류 0을 요구한다. Gradle의 실제 종료
코드 0, 다섯 필수 task 실행, 네 module 결과, source 불변 확인 및 evidence export를
함께 충족해야 `jvm-result.json`의 상태를 `passed`로 둔다. Rust 감독기의 drain,
export와 lease 해제도 성공한 경우에만 CI verify step이 성공한다.

필수 task의 실제 classpath JAR는 원래 index, 파일명, bytes와 SHA를 기록한다.
source 입력과 Gradle/JDK archive를 함께 식별하지만, classpath의 directory output,
모든 plugin의 전이 입력 또는 OS 간 동일 JAR bytes를 완전히 증명하는 자료는 아니다.
Hermetic build, 게임 profile 검증과 릴리스 artifact 동등성은 별도 검증이 필요하다.

일반 명령의 1200초, 실제 Rust 관리 출력 상한 64 MiB, slot 8 GiB, catalog 12 GiB와
5초 disk 관측을 사용한다. bootstrap 출력 상한 128 MiB와 일반 명령 상한을 구분한다.
이 heap 및 관측 설정은 전체 JVM kernel memory quota를 의미하지 않는다. Windows는
기존 Job commit 2 GiB와 process 32개 설정을 유지한다. Darwin도 기존 VM 512 GiB,
소유 그룹 RSS 및 physical footprint 각각 2 GiB, worker 32개와 관측 조건을 유지한다.
실제 검증 상태는 [빌드 수명](build-system.md)과
[구현 착수 조건](implementation-readiness.md)을 따른다. 실패 또는 초과 뒤 상한을
바꾸거나 자동 재시도하지 않는다.

[MMMM-D024](DECISIONS.md)는 정확한 `purpose=jvm`에만 Linux의
`managed-linux-jvm-resources/1`을 선택한다. 이 정책은 process별 `RLIMIT_AS` soft 및
hard를 고정 512 GiB로 설정하고 정확한 readback을 확인한다. 원래 leader의 native
identity와 unreaped child reservation을 유지한 소유 그룹에서 `smaps_rollup`의 `Rss`
합계를 2 GiB, live process를 32개까지 100 ms 목표로 관측한다. PowerShell launcher,
Java·Gradle·test 자식을 포함하고 Rust supervisor는 제외한다. 일반 `checks`와 다른
목적의 Linux 주소 공간 2 GiB는 유지하며 시간·출력·disk 예산도 변경하지 않는다.

Linux 관측은 고정 procfs root FD와 그 FD를 기준으로 연 숫자 PID directory 및 원래
stat FD를 사용한다. RSS 전후의 PID·starttime·SID·PGID를 확인하고 유한하게 자료를
읽는다. 살아 있는 원래 process의 permission·malformed 자료·identity 오류는 실패로
보존한다. RSS 오류만으로 종료나 0 RSS를 판정하지 않으며 성공적으로 읽은 RSS와 VM은
직후 실제 종료에도 관측 사실로 남긴다. 초기 leader identity 확보 실패나 reservation
상실은 group signal과 drain 완료를 허용하지 않고 lease와 진단을 보존한다.

RSS 합계는 process들을 순서대로 읽은 관측이고 공유 페이지를 process마다 포함한다.
그룹 전체의 동시 snapshot이나 kernel RSS·process quota가 아니며 관측 사이 초과가
가능하다. receipt에는 `kernel_resident_quota=false`, `kernel_process_quota=false`,
`group_snapshot_atomic=false`, `sampling_may_overshoot=true`, 실제 sample 수·peak·최대
sample 간격과 미완성 memory sample을 보존한다. 새 session으로 의도적으로 이탈한
process를 모두 포괄하는 sandbox 보장을 제공하지 않는다. 새 정책의 실제 Linux native
실행과 PowerShell·Gradle 적합성은 아직 미검증이며 소스 및 순수 검사 결과와 구분한다.

JVM helper는 관리 경로를 `managedGradleHome`에 보관한다. PowerShell의 `$HOME`과
겹치는 변수 이름을 사용하지 않는다. 실패 record에는 원래 exception chain의 타입과
HResult, ErrorRecord category와 안전한 error ID, 고정 작업 단계, helper의 저장소 상대
경로와 줄을 보존한다. chain은 최대 8개, 타입은 192자, error ID는 256자로 제한한다.
예외 메시지는 최대 128자의 정적 대문자 오류 코드일 때만 기록한다. 실제 메시지의 개인
경로, target object와 stack trace는 요약에 넣지 않는다. 테스트 report export 실패도
같은 방식으로 원인을 남기며 성공으로 바꾸지 않는다.

[MMMM-D025](DECISIONS.md)에 따라 Rust의 소유 `purpose=jvm` route는 PowerShell helper를
spawn하기 전에 `ProcessSpec.env`에 `DOTNET_EnableDiagnostics=0`을 고정으로 넣는다.
native 환경 구성은 이 explicit override를 child에 전달하며 부모의 원래 설정을 기록하지
않는다. `jvm-ci.ps1`에서 시작 후 환경을 대입하는 방법으로 대체하지 않는다. 이 설정은
해당 helper의 .NET debugging, profiling과 diagnostic port를 끄며 다른 진단 설정으로
다시 활성화하지 못한다.
[Microsoft의 공식 환경 변수 정의](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-environment-variables#dotnet_enablediagnostics)
CoreCLR의 공식 문서는 이 설정이 Linux·macOS debugging pipe와 semaphore의 생성을
예방한다고 명시한다.
[CoreCLR managed debugging 비활성화](https://github.com/dotnet/runtime/blob/main/docs/workflow/debugging/coreclr/debugging-runtime.md#disabling-managed-attachdebugging)

helper는 `jvm-runtime-inside.json`에 `managed_helper_diagnostics_disabled` boolean만
추가한다. 이 값은 현재 process의 고정 설정 readback이며 원래 환경 문자열을 export하지
않는다. 값이 false이면 `MANAGED_JVM_DIAGNOSTICS_POLICY_REQUIRED`로 실패한다.
boolean이 true인 것만으로 FIFO 부재나 전체 native 실행 성공을 증명하지는 않는다.
정책 적용 후 실제 3개 OS의 helper 시작, FIFO 생성 예방, 원래 로그 export, Gradle·XML
검증과 종료·lease 해제를 별도로 확인해야 한다. stdout·stderr, 기존 native 감독 및
runtime probe는 유지하며 특수 파일 무시·이름 기반 삭제와 중단 lease 자동 채택은 추가하지
않는다. bootstrap, 일반 Rust 관리 검사, 전역 PowerShell, .NET 설치·이미지와 제품 게임
프로세스의 환경은 변경하지 않는다. JVM/JVMTI 게임 정의 관측의 권한이나 설정도 바꾸지 않는다.

`jvm-runtime-probe.ps1`은 관리 제한 밖의 기존 CI PowerShell과 같은 executable로 실행한
helper 안에서 각각 `jvm-runtime-outside.json`, `jvm-runtime-inside.json`을 만든다.
record는 최대 16 KiB이며 PowerShell 및 .NET 버전, 실제 `en-US` 정렬 연산과 GC의
정해진 숫자 설정만 보존한다. Linux에서는 자기 프로세스의 `VmSize`, `VmRSS`, address
space soft/hard limit과 이미 로드된 ICU 라이브러리의 파일명만 기록한다. 고정된
`/proc/self/status`, `limits`는 각각 64 KiB, `maps`는 1 MiB까지 읽고 ICU 파일명은 최대
16개로 제한한다. 메모리 주소, 전체 maps, 절대 경로와 환경 변수 전체는 내보내지 않는다.
helper가 시작 전에 종료하면 내부 record는 없으며 감독기의 실제 종료 signal과 구분한다.
이 probe는 새 프로세스나 설치를 만들지 않고 globalization 설정 및 상한을 변경하지 않는다.

첫 Linux 실행의 실제 `RLIMIT_AS` soft/hard readback은 각각 2 GiB였고 자식은 signal 6으로
종료했다. ICU 오류 메시지만으로 패키지 부재를 확정하지 않는다. Linux의 `RLIMIT_AS`는
가상 주소 공간을 제한하고 `mmap` 등이 상한에 닿으면 `ENOMEM`으로 실패할 수 있다.
[Linux getrlimit 문서](https://man7.org/linux/man-pages/man2/getrlimit.2.html)
.NET은 GC 시작 시 commit과 별도로 가상 주소 구간을 예약하며 기본 region range는
큰 값일 수 있다. [공식 GC 설정 문서](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/garbage-collector)
이전 JVM helper와 공유 probe 변경은 Linux 상한을 유지한 진단 범위였다. 이후 D024로
채택한 목적별 정책은 위에 별도로 기록한 명시적 변경이며, 원래 실패의 원인을 확정한
결과는 아니다. 관리 범위 전후 probe도 환경과 관측값을 비교하는 자료이며 패키지 부재나
주소 공간이 signal 6의 원인이었다고 단독으로 확정하지 않는다. ICU 설치, invariant
globalization, silent fallback 또는 실패 뒤 상한 확대 재시도는 추가하지 않는다.

세 runner job 모두 성공해야 `jvm-result` 집계가 성공한다. workflow는 path filter로
필수 상태를 생략하지 않는다. `always()` 기록과 artifact export에 실제 step outcome,
source 및 toolchain 식별, 개별 task·XML 요약과 관리 종료 기록을 남기고 14일 보존한다.
빌드 cache·게임 데이터·개인 경로를 요약 record에 넣지 않는다. 일시 다운로드 redirect
URL과 환경 변수 전체도 기록하지 않는다. 원시 native 로그는 외부 CI artifact에 두며
개인 개발 경로가 포함된 로그를 저장소 문서로 복사하지 않는다.

새 D025 정책은 소스 작성 및 정적 검토 범위다. 정책 적용 후 실제 3개 OS CI 성공,
Minecraft 서버·수동 클라이언트·멀티플레이·vanilla 생성물 검증과 공개 `v0.1.0`
배포는 미완료이며 이 workflow의 SDK 테스트나 Fabric 컴파일로 대체하지 않는다.
