# MMMM 저장소 결정 기록

이 기록은 저장소 규약, 구현 범위와 생성물 수명의 채택한 결정을 관리한다.
변경에는 이유, 소비자 영향, 보완 검증과 재검토 조건을 남긴다.
문서의 채택과 실제 도구, 원격 설정 및 제품 인수 완료를 구분한다.

## 채택한 결정

기준일은 2026-10-14이다.

| ID | 결정 | 적용 및 재검토 조건 |
|---|---|---|
| MMMM-D001 | 현재 구현 범위는 MVP와 공개 GitHub `v0.1.0`까지다. | 이후 v0 확장과 G5 및 G6의 v1 전환은 후속이다. 범위 변경은 별도로 기록한다. |
| MMMM-D002 | 새 도메인, Coordinator, CLI, MCP, 정보와 변환 코드는 Rust다. Java는 게임 호스트와 SDK의 플랫폼 접점이다. | 책임 이동 시 계약, 의존 방향과 소비자 검증을 함께 검토한다. |
| MMMM-D003 | 자체 코드, 계약, SDK와 자체 fixture는 MIT다. | 외부 코드 및 자산은 별도 분류, 출처와 재배포 조건을 유지한다. |
| MMMM-D004 | 제품 `0.1.0`과 초기 저장 및 wire 계약 `0.2.0`을 분리한다. | 확보한 원본 schema, function index와 예제를 정본으로 사용한다. 도입 파일의 출처와 bytes digest를 보존한다. |
| MMMM-D005 | 첫 target은 Minecraft Java 26.3과 한 검증된 Fabric 프로필이다. | 실제 게임, loader, JDK, Gradle, Rust와 의존성은 첫 빌드 및 실행 근거로 정확히 고정한다. |
| MMMM-D006 | 배포 대상은 Windows x64, Linux x64와 macOS ARM64다. | 각 OS의 실제 서버 검사와 수동 클라이언트 검증을 포함한다. |
| MMMM-D007 | 첫 공개 배포는 서명 없는 아카이브다. | 코드 서명, notarization과 설치 프로그램은 후속 범위다. |
| MMMM-D008 | 일반 흐름은 `develop → feature/* → PR → develop`이며 같은 목표는 브랜치와 Draft PR을 재사용한다. | 빈 원격의 첫 기준 커밋만 CONTRIBUTING의 bootstrap 절차를 따른다. |
| MMMM-D009 | 작은 의미 단위와 실패 및 미완성 WIP를 공유한다. 장기 작업은 15~30분마다 변경을 확인한다. | 원격 반영이 배정 범위에 있을 때 push한다. 커밋 수 상한과 빈 커밋 의무는 없다. 병합 조건은 별도다. |
| MMMM-D010 | 생성물은 저장소 밖에 두고 OS, 아키텍처, checkout과 용도별 고정 슬롯을 사용한다. | 소유 lease, 유한한 실행과 자식 종료 확인 후 회수한다. 중단 또는 불명 lease는 자동 채택하지 않는다. |
| MMMM-D011 | 초기 빌드 예산은 슬롯 8 GiB, 카탈로그 12 GiB, 완료 cache 슬롯 4개, 동시 활성 슬롯 1개다. | 활성 슬롯도 byte 예산에 포함한다. 첫 Rust 및 JVM 빌드의 실제 크기로 조정 여부를 기록한다. |
| MMMM-D012 | 일반 명령 timeout은 1200초, 선택 범위는 1~3600초, 실행 중 크기 관측은 5초 간격이다. | 별도 큰 검증은 유한한 자원과 시간을 명시한다. disk quota 보장으로 표현하지 않는다. |
| MMMM-D013 | SQLite, CAS, 작업 원장, 사용자 원본과 복구 자료는 빌드 정리에서 제외한다. | 미해결 작업의 참조를 보존하며 제품 GC는 별도 계약으로 구현한다. |
| MMMM-D014 | 구조 검사는 Git index metadata와 stage된 정책 JSON 하나를 사용한다. | 정책 blob 64 KiB, 추적 파일 10 MiB, 정확한 generated 및 size 예외를 적용한다. 파일 내용 보안의 증명은 아니다. |
| MMMM-D015 | 독립 CI는 병렬화하고 호환되는 빌드와 유효한 성공 근거는 재사용할 수 있다. | 영향 입력, 실제 환경, 출처와 digest를 확인하고 원본 실행과 현재 판정을 구분한다. |
| MMMM-D016 | 일회성 CI는 같은 목표당 workflow 하나와 동시 run 하나다. 임시 artifact 기본 14일, 정리 대상 종료 run 기본 최근 5개다. | 열린 근거, 미해결 실패, 복구 및 릴리스 자료는 예외 보존한다. 원격 삭제는 배정 범위와 보존 조건을 확인한다. |
| MMMM-D017 | 최초 `v0.1.0` 인수는 최종 고정 SHA와 실제 배포할 동일 파일로 수행한다. | 3개 OS, 수동 클라이언트, vanilla 결과물과 출시 판정의 필수 실패 및 미실행을 해결한다. |
| MMMM-D018 | `main`과 `develop`은 PR, 실제 필수 검사, force-push 및 삭제 방지를 적용할 대상이다. | 실제 권한, 관리자 적용과 예외를 조회해 확인한다. 리뷰어와 CODEOWNERS는 확인된 팀 구성에 맞춘다. |
| MMMM-D019 | 제공된 원본 핸드오프 ZIP의 계약과 예제를 도입한다. | 문서에서 재구성하는 방법은 원본 확보에 따라 사용하지 않는다. 70개 파일의 무결성 확인과 제품 계약 및 실제 효과 검증을 구분한다. |
| MMMM-D020 | 빌드 자식의 종료 기본 정책은 엄격한 거절이며, Cargo와 CI 빌드에는 명시적인 소유 자식 정리를 선택할 수 있다. | 리더 종료 후 2초의 자연 종료 유예를 거쳐 해당 실행의 전체 native scope만 종료한다. 실제 명령 code, 정리 여부, 완전한 출력 수집과 drain을 보존하며 제품 쓰기에 적용하지 않는다. |
| MMMM-D021 | `CommandContext.rotationDegrees`의 두 값은 `[pitchDegrees, yawDegrees]` 순서로 해석한다. | 원본의 명시되지 않은 순서를 Minecraft native Vec2 의미와 맞춘 구현 결정이다. Rust와 Java 경계에서 같은 순서와 유한 값 검사를 적용한다. |
| MMMM-D022 | Darwin 빌드는 `managed-darwin-resources/1`의 플랫폼별 자원 정책을 적용한다. | 512 GiB의 VM 설정·관측 한도와 소유 그룹 합계 RSS 및 physical footprint 각각 2 GiB를 구분한다. 100 ms 목표 관측, 완전한 성공 관측 사이 1초 상한과 worker 32개를 적용한다. kernel resident quota로 표현하지 않으며 실제 macOS CI로 검증한다. |
| MMMM-D023 | 일반 Rust 관리 명령도 플랫폼별 자원 정책을 명시하고 native 설정과 관측 결과를 보존한다. | Windows는 시작 전 Job의 commit 2 GiB 및 process 32개 상한을 확인한다. Linux는 process마다 주소 공간 2 GiB를 설정·확인하고 소유 그룹 32개를 관측한다. 두 정책의 100 ms 목표 표본 및 최대 간격을 기록하며 Linux에 kernel resident quota나 Darwin의 1초 표본 간격 보장을 주장하지 않는다. Windows의 실제 자식 설정 검사는 통과했으며 다른 OS와 JVM 적합성은 별도 검증한다. |
| MMMM-D024 | 정확한 `purpose=jvm`에만 Linux JVM 자원 정책 `managed-linux-jvm-resources/1`을 선택한다. | Linux JVM의 process별 VM soft/hard를 고정 512 GiB로 설정·대조하고 소유 그룹의 `smaps_rollup` RSS 합계 2 GiB 및 live process 32개를 100 ms 목표로 관측한다. 일반 `checks`의 2 GiB 주소 공간과 Windows·Darwin 기존 정책은 유지한다. kernel RSS/process quota, 그룹의 동시 snapshot이나 새 session 이탈 containment를 주장하지 않는다. 순차 RSS는 공유 페이지를 process마다 포함하고 관측 사이 초과가 가능하다. 실패 후 자동 확대·재시도나 ICU 원인 확정은 하지 않으며 새 정책의 실제 Linux 실행은 별도 검증한다. |

## 구현 전에 확인할 항목

- 원본 계약과 예제 패키지의 내용, 버전 및 digest.
- 실제 빌드한 toolchain, feature, JDK, Gradle, Fabric과 게임 target profile.
- 관리 도구의 bootstrap, 3개 OS 자식 종료 확인과 실제 Rust 및 JVM 출력 크기.
- 원격 구성 배정 시 빈 저장소 여부, 권한, 보호 설정과 실제 필수 상태 검사.
- 실제 담당 GitHub 계정, 리뷰 구성과 필요한 CODEOWNERS 범위.
- 최종 릴리스 증거의 보존 위치, 회수 방법과 배포 파일 목록.

## 변경 기록

| 날짜 | 변경 | 검증 범위 |
|---|---|---|
| 2026-10-13 | 구현 전 저장소 규약과 빌드 및 임시 파일 수명의 기준을 채택했다. | 문서와 선언 정책의 정합성. 도구, CI, 원격 보호와 제품 실행은 별도 인수 대상이다. |
| 2026-10-13 | 원본 패키지의 계약, 예제와 분할 구현 및 인수 자료를 도입했다. | SHA256SUMS의 70개 항목이 일치했다. 선택 도입한 61개 파일의 경로 및 digest를 기록했다. 제품 실행은 별도다. |
