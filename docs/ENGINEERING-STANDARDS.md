# MMMM 구현 기준

MMMM의 구현은 계약, 상태 보존, 실제 효과 관찰과 재현 가능한 검증을 기준으로 한다.
이 문서는 코드 책임, 생성 규칙과 인수 근거를 소유한다. Git 절차는
[CONTRIBUTING](../CONTRIBUTING.md), 실행 및 파일 수명은
[build-system](build-system.md)을 따른다.

## 적용 범위

현재 범위는 MVP와 공개 `v0.1.0`까지다. 이후 기능 확장과 v1 도메인 vendor 교체는
후속으로 남긴다. 단, 현재 채택하는 vendor의 분류, 출처, 범위와 교체 책임은 기록한다.

제품, 계약, 호스트 프로토콜, 기능 계약, target profile과 프로젝트 revision은
독립적으로 식별한다. 초기 저장 및 wire 계약 `0.2.0`은 exact match를 기본으로 한다.
Minecraft Java 26.3을 목표로 하며 다른 버전과 로더의 지원은 실제 검증 없이 확대하지 않는다.

## 책임과 의존 방향

| 영역 | 소유 책임 |
|---|---|
| `crates/mmmm-contracts` | DTO, typed ID, 버전, wire codec과 canonical digest |
| `crates/mmmm-domain` | 객체, 참조, 변환, 시간과 상태의 의미 |
| `crates/mmmm-application` | use case, plan과 backend-neutral port |
| `crates/mmmm-reference` | 자료, 출처, coverage, 검색과 형상 질의 의미 |
| `crates/mmmm-exchange` | 중립 장면 및 물리 교환, 손실과 patch 해석 |
| `crates/mmmm-compiler-minecraft` | target에 맞는 명령, 팩, display와 clip 출력 |
| `crates/mmmm-adapters` | Provider 및 Compatibility 정규화와 binding 해석 |
| `crates/mmmm-runtime` | Coordinator, SQLite, CAS, 작업 원장, 락, 정책, 호스트 transport와 runner |
| `crates/mmmm-mcp` 및 `apps/mmmm` | 공개 facade, CLI, daemon 진입점과 구성 주입 |
| `crates/mmmm-testkit` 및 `tests` | 독립 fixture, fault injection과 관찰 oracle |
| `jvm` | 로더, 스레드, 게임 권한 및 API, 적용과 readback, SDK |
| `tools` | Rust 개발 도구, 구조 검사, 빌드 수명, 패키징과 검증 근거 관리 |

표는 구현 시 소유할 책임을 나타낸다. 필요한 구현이 배정될 때 경로를 만들며
미리 빈 crate를 쌓지 않는다. 초기에는 관련 책임을 모듈로 합칠 수 있다.

공통 계약은 게임, DB, MCP 또는 vendor 실행에 역의존하지 않는다. 순수 domain은
파일과 네트워크 I/O를 수행하지 않는다. application은 port를 통해 구현체를 사용하고
facade는 별도 plan/apply 알고리즘을 갖지 않는다. 같은 데이터 루트의 Coordinator는
하나이며 Java 호스트는 제품의 영구 원장을 대체하지 않는다.

vendor는 불변 snapshot과 별도 wrapper에서 사용한다. 도메인과 wire에 upstream 타입을
노출하지 않는다. infrastructure dependency, platform shim, 사용자 외부 도구와
temporary domain vendor를 실제 사용 목적과 의존 그래프로 구분한다.

## 코드 구성과 실행 한도

함수와 파일은 기능, 변경 이유, 소유권과 인터페이스로 구성한다. 관련 구현과 보조
코드는 함께 두고 독립 책임이나 재사용 경계가 생길 때 분리한다. 고정 줄 수, 파일 수와
함수당 assertion 개수를 합격 기준으로 삼지 않는다. 실험별 운영 코드 복제와 책임 없는
공용 폴더를 늘리지 않는다.

제어 흐름과 상태 전이를 명시한다. 재귀는 깊이, 입력 크기와 시간 등 필요한 한도로
제한한다. 반복, retry, queue, buffer, cache, worker와 출력에는 유한한 예산을 둔다.
예산 초과와 취소를 확인하며 자원 부족을 성공 기본값이나 조용한 설정 변경으로 숨기지 않는다.

표준 derive, 필요한 매크로와 `feature/cfg`는 지원 조합과 책임을 명시해 사용한다.
불필요한 복잡한 생성기를 추가하지 않는다. `unsafe`와 FFI는 작은 경계에 한정하고
수명, 소유권, 동시성과 오류 처리 근거를 남긴다. 변경 영역의 compiler, lint와 type
검사를 수행하고 새 경고는 수정하거나 좁은 범위의 근거를 기록한다.

## 계약과 코드 생성

원본 `contracts/mmmm.schema.json`과 `contracts/function-index.json`을 도입한다.
원본 출처와 bytes의 digest는 `contracts/handoff-input.json`에 기록한다. Rust와 Java DTO는 정본에서
생성하거나 공통 양방향 fixture로 일치시킨다. DTO에서 추출한 별도 스키마를 제2 정본으로 두지 않는다.

생성에는 입력 버전과 digest, 생성기 버전과 digest, 옵션, 소유자와 출력 목록을 기록한다.
동일한 입력과 옵션은 동일한 출력을 만들어야 한다. 생성 파일은 생성기를 고쳐 재생성하며
직접 수정하지 않는다. 생성 입력과 소비자 검증을 계약 변경에 함께 포함한다.

source digest와 계약의 canonical digest는 구분한다. JSON 정렬, 수치, 문자열과
도메인별 projection은 실제 계약의 canonical 규칙을 따른다. 줄바꿈 정규화만으로
JCS 또는 Rust와 Java 의미 일치를 통과했다고 표시하지 않는다.

제공된 원본 snapshot과 digest로 고정한 fixture는 bytes를 보존한다.
직접 작성한 소스와 문서는 LF를 기본으로 한다. 계약과 예제의 원본 bytes 보존 규칙은
[.gitattributes](../.gitattributes)에 등록한다.

생성 DTO, SDK 소스 또는 fixture를 추적할 필요가 있으면 재생성 방법, 책임과 정확한
경로를 등록한다. 제품 출력과 원시 실행 자료는 외부 보존 위치에 둔다. 필요하면 소규모
자체 자료만 fixture로 채택하고 권리 및 기존 자료로 부족한 이유를 기록한다.

## 오류와 실제 효과

외부 입력, unknown enum과 field, omitted/null, 수치 범위, ID, 참조와 권한을 계약대로
검증한다. 실패는 실제 유형, 코드, 발생 단계, 원인과 상태를 보존한다. 제품 안내를
간단히 하더라도 개발 진단과 미검증 범위를 유지한다.

순수 실패와 dispatch 이후 결과를 구분한다. 쓰기는 plan, 권한 및 사전 조건 확인,
durable dispatch, 적용과 독립 readback을 따른다. deadline은 대기 한도이며 rollback
보장이 아니다. 결과 불명인 쓰기를 자동 재시도하거나 다른 구현으로 fallback하지 않는다.

`COMMIT_UNCERTAIN`, 부분 완료, readback 불일치와 복구 대기를 성공으로 바꾸지 않는다.
복구는 새 계획과 확인된 현재 상태를 사용한다. 적용과 readback이 같은 잘못된 변환을
공유하지 않게 독립 기대값과 관찰 경로를 사용한다.

## 검사와 fixture 유지비

반복 가능한 중요한 계약과 실패를 지킬 때 검사를 유지한다. 문구 수정 또는 버그 한 건마다
새 테스트와 fixture를 자동 의무화하지 않는다. 영향, 재발 가능성, 기존 검사 누락과
유지비를 보고 기존 검사를 먼저 활용한다.

새 fixture에는 검증하는 계약과 기존 자료로 부족한 이유를 PR에 적는다.
구현 문장만 복제하는 검사, 중복 snapshot, 전체 사용자 맵, 긴 로그와 데이터셋 복사본을
누적하지 않는다. 기존 유효 검사를 일괄 제거하지 않으며 관련 변경에서 중복과 폐기 조건을 검토한다.

필수 인수 항목은 빠짐없이 결과에 연결한다. 검사 하나가 여러 계약을 지킬 수 있고
같은 최소 입력을 재사용할 수 있다. 테스트 개수를 인수 충족의 대체 수치로 사용하지 않는다.

## 구조 검사

[repository-policy.json](../.github/repository-policy.json)은 구조 정책의 정본이다.
검사기는 G0에서 Rust 개발 도구로 도입한다. 내용은 stage된 정책 JSON 하나만 읽고,
다른 파일은 Git index의 stage 0 경로, mode, 객체 종류와 크기로 검사한다.
unmerged index는 거절하며 정책 JSON은 regular blob, 최대 64 KiB로 제한한다.

허용 최상위 경로, 비밀 경로명, 생성물 패턴, 10 MiB 크기 제한, 이식 가능한 경로,
대소문자 및 Unicode 정규화 충돌, 파일과 디렉터리 충돌, symlink와 submodule을 검사한다.
비밀 내용, generated 또는 ignored 폴더, 링크 대상과 submodule 내부를 순회하지 않는다.

예외는 정확한 파일 경로와 이유로 `generated` 또는 `size`만 면제한다.
각 항목은 `{"path":"정확한/상대/경로","allow":["generated"],"reason":"검토 이유"}`
형식을 사용하며 `allow`에는 필요한 면제 종류만 등록한다.
경로 등록, 비밀, 충돌과 비정상 Git mode는 예외로 우회하지 않는다.
넓은 wildcard, 존재하지 않거나 불필요해진 예외는 거절한다. 정책 JSON 변경 자체도 PR 검토 대상이다.

허용 root 이름은 정확히 비교한다. 비밀 이름과 생성물 디렉터리, suffix 및 basename
pattern은 대소문자를 구분하지 않고 비교한다. pattern의 `*`와 `?`는 basename에만
적용하며 디렉터리를 넘지 않는다. 충돌 비교에는 Unicode NFC와 대소문자 정규화를
사용하되 실제 Git 경로를 바꾸지 않는다. 정책의 필드, 타입, 중복과 예외 종류를 검증한다.

이 검사는 stage되지 않은 변경, 파일 내용의 보안과 전체 코드 품질을 증명하지 않는다.
실제 검사 명령은 도구 도입 및 오류 경로 검증 후 등록한다.

## CI 병렬화와 근거 재사용

독립 검사는 job, matrix 또는 shard로 병렬화한다. 실제 선행 산출물이 필요한 작업에만
`needs`를 둔다. runner 수와 job 내부 worker, 스레드, 메모리와 timeout을 함께 계산한다.
shard 집계는 중복, 누락, 실패, 취소와 미실행을 구분한다.

호환되는 빌드는 한 번 생성해 후속 job에 전달한다. 실제 OS, 아키텍처, target,
toolchain 및 ABI, profile, flags, 관련 소스, 전이 의존성, lock, 생성 입력과 fixture를
fingerprint에 포함한다. 생산 repository, workflow, run, attempt, SHA와 파일 digest를 확인한다.

성공 근거 재사용은 해당 검사의 모든 영향 입력, 명령, workflow와 실제 환경 식별자가
동일하고 원본 성공 및 증거가 유효할 때 허용한다. 빠진 입력, 만료, 알 수 없는 성공,
실패, skip과 취소는 재사용하지 않는다. 변경된 입력과 현재 index 또는 외부 상태를
요구하는 검사는 다시 수행한다.

현재 결과에는 원본 실행과 현재 SHA의 재사용 판정을 구분해 남긴다.
cache hit를 직접 실행이나 clean build로 표시하지 않는다. 재생성 cache의 miss,
만료와 불일치는 정상 설치와 빌드로 복구한다. 미확인 출처의 artifact와 cache를
높은 권한의 배포에 사용하지 않는다.

## 인수와 공개 배포

명세 검증, 로컬 검사, CI 요청, 관측한 CI 성공, 실제 서버 및 클라이언트 검증과
공개 배포를 구분한다. 필수 항목의 `passed`, `failed`, `not_run`과 미검증 범위를 기록한다.
reference 자료, mock과 SDK 컴파일을 game verification으로 표시하지 않는다.

최초 `v0.1.0` 출시는 최종 고정 SHA와 실제 배포할 동일 bytes를 기준으로 3개 OS
자동 서버 검사, 수동 클라이언트 검증, vanilla 생성물 검증과 출시 판정을 수행한다.
개발 중의 다른 SHA 성공 재사용으로 이 조건을 대신하지 않는다.

릴리스에는 파일 digest, target profile, 인수 결과, SBOM, 출처와 필요한 고지를 연결한다.
외부 코드와 자산의 조건은 자체 MIT 기준과 별도로 기록한다. 필수 실패, 미해결 쓰기와
미실행을 해결한 뒤 배포하며, 출시 증거는 임시 cache 및 CI artifact 만료와 수명을 분리한다.
