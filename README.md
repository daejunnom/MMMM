# MMMM

MMMM은 Minecraft 맵 제작 자료와 변경 작업을 관리하는 로컬 중심 시스템이다.
CLI, MCP와 제작 도구는 같은 제작 서비스와 Coordinator를 사용한다.

현재 단계는 원본 계약을 도입한 G0 기반 구현이다. 이번 제품 범위는 MVP 구현과
공개 GitHub `v0.1.0` 배포까지이며, 이후 기능 확장과 v1 전환은 후속 범위다.

## 제품 기준

- 자체 도메인, Coordinator, CLI, MCP, 정보 처리와 변환 코드는 Rust로 작성한다.
- Java 호스트와 Provider SDK는 로더, 스레드 전달, 게임 API, 권한, 적용과 readback을 연결한다.
- 첫 게임 대상은 Minecraft Java 26.3과 하나의 검증된 Fabric 프로필이다.
- 배포 대상은 Windows x64, Linux x64와 macOS ARM64다.
- 자체 코드, 계약, SDK와 자체 fixture는 MIT다. 외부 코드와 자산의 조건은 각각 기록한다.
- 제품 버전 `0.1.0`과 초기 저장 및 wire 계약 버전 `0.2.0`을 구분한다.
- 공개 배포는 서명 없는 아카이브를 사용한다. 코드 서명, notarization과 설치 프로그램은 이번 범위에 포함하지 않는다.

## 저장소 문서

| 문서 | 기준으로 삼을 내용 |
|---|---|
| [AGENTS.md](AGENTS.md) | 작업 시작, 지시 우선순위, 접근 제한과 핵심 작업 원칙 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 브랜치, WIP 공유, PR, 리뷰와 정리 절차 |
| [구현 기준](docs/ENGINEERING-STANDARDS.md) | 책임, 계약, 코드 생성, 오류와 검증 근거 |
| [빌드 수명주기](docs/build-system.md) | 출력 루트, 소유 lease, 자원 한도와 정리 절차 |
| [결정 기록](docs/DECISIONS.md) | 채택한 결정과 조정이 필요한 조건 |
| [구현 착수 조건](docs/implementation-readiness.md) | G0 선행 조건과 단계별 인수 연결 |
| [PR 템플릿](.github/PULL_REQUEST_TEMPLATE.md) | 변경, 소비자 영향, 실제 검증과 보존 기록 |
| [저장소 구조 정책](.github/repository-policy.json) | 허용 경로, 생성물과 크기 제한, 정확한 파일 예외 |

상세 규칙은 각 기준 문서에서 관리한다. 규칙이 바뀌면 진입 문서, 템플릿과 정책의
관련 참조도 함께 갱신한다.

## 계약과 구현 준비

저장 및 wire 형식 정본은 원본 `contracts/mmmm.schema.json`이며,
함수 목록은 원본 `contracts/function-index.json`이다. 제공 패키지의 70개 파일을
SHA-256 목록과 대조한 뒤 계약, 예제, 정책 및 인수 자료를 도입했다.
입력 파일과 저장소 경로의 대응은 [입력 출처](contracts/handoff-input.json)에 기록한다.
상세 구현 요구는 [핸드오프](docs/HANDOFF.ko.md),
[함수 계약](docs/FUNCTION_CONTRACTS.ko.md)과 [인수 기준](tests/ACCEPTANCE.ko.md)을 따른다.

빌드 관리 도구와 구조 검사기 소스는 구현 중이며 제품 인수와 CI는 아직 완료되지 않았다.
현재 정책 파일은 자동 검사 통과를 의미하지 않는다. 실제 명령과 toolchain은
첫 구현과 검증 후 이 문서 및 기준 문서에 등록한다.

## 출시 조건

필수 인수 항목에는 실제 결과와 source, target, artifact 식별 근거를 연결한다.
3개 OS의 실제 서버 검사, 수동 클라이언트 검증과 vanilla 결과물 검증은
배포할 동일 파일과 최종 고정 SHA를 기준으로 수행한다.
필수 실패, 결과 불명과 미실행을 성공으로 처리하지 않는다.

배포 파일에는 digest, SBOM, 필요한 라이선스 고지와 인수 증거를 연결한다.
상세 조건은 [구현 착수 조건](docs/implementation-readiness.md)을 따른다.
