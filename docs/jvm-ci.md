# JVM CI 검증 기반

`.github/workflows/jvm.yml`은 Windows x64 (`windows-2025`), Linux x64
(`ubuntu-24.04`), macOS ARM64 (`macos-15`)에서 같은 후보 source SHA를 확인하고
Java SDK, 호스트 core 및 public Java adapter 테스트와 Fabric 호스트 컴파일·테스트를
실행하도록 작성한 기반이다. 현재 이 신규 workflow의 실제 실행 결과는 미관측이다.
이 문서와 workflow 소스는 3개 OS 인수 성공을 의미하지 않는다.

PR은 merge commit 대신 `pull_request.head.sha`를 checkout한다. event SHA,
PR head/base SHA, repository, workflow, run, attempt 및 실제 runner image를
외부 `ci-context.json`에 기록한다. 빌드 전후 Git HEAD 및 관련 추적 소스의 bytes를
확인하며, JVM 소스·Gradle 설정·계약·예제·검증 helper의 SHA를 별도 manifest에 둔다.
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
이 heap 및 관측 설정은 전체 JVM kernel memory quota를 의미하지 않는다. Windows와
Linux의 일반 관리 명령 resource quota 연결, Darwin 감독 정책의 실제 검증 상태는
[빌드 수명](build-system.md)과 [구현 착수 조건](implementation-readiness.md)을 따른다.
실패 또는 초과 뒤 상한을 바꾸거나 자동 재시도하지 않는다.

세 runner job 모두 성공해야 `jvm-result` 집계가 성공한다. workflow는 path filter로
필수 상태를 생략하지 않는다. `always()` 기록과 artifact export에 실제 step outcome,
source 및 toolchain 식별, 개별 task·XML 요약과 관리 종료 기록을 남기고 14일 보존한다.
빌드 cache·게임 데이터·개인 경로를 요약 record에 넣지 않는다. 일시 다운로드 redirect
URL과 환경 변수 전체도 기록하지 않는다. 원시 native 로그는 외부 CI artifact에 두며
개인 개발 경로가 포함된 로그를 저장소 문서로 복사하지 않는다.

현재 문서는 소스 작성 및 정적 검토 범위를 기록한다. 실제 3개 OS CI 성공,
Minecraft 서버·수동 클라이언트·멀티플레이·vanilla 생성물 검증과 공개 `v0.1.0`
배포는 미완료이며 이 workflow의 SDK 테스트나 Fabric 컴파일로 대체하지 않는다.
