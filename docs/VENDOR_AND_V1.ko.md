# MVP/v0 벤더링 유지와 v1 Rust 인수 기준

## 1. 사용자 결정의 실행 의미

MVP/v0는 기존 구현 언어를 보존해 필요한 기능을 빨리 이용한다. Rust 코어가 그 기능의 입력·출력·수명·부작용을 계약으로 감싼다. **v1 공개 전에 임시 도메인 vendor가 담당했던 기능을 자체 소유 Rust 구현으로 전부 대체한다.** 구현 언어가 이미 Rust여도 판정은 같다.

‘원형 유지’는 결함·취약점·잘못된 출력까지 무조건 유지한다는 뜻이 아니다. 가능한 대응은 외부 wrapper에서 제한, upstream의 검증된 수정판으로 전체 snapshot 교체, 해당 기능 비활성화, 자체 Rust 구현으로 대체다. 꼭 필요한 최소 패치는 separate patch queue·이유·hash·라이선스에 기록한다. vendor 내부를 새 기능 개발 장소로 쓰거나 대규모 1.xx→26.3 포트를 먼저 만드는 것은 금지한다.

## 2. 채택 전 의사결정표

| 상황 | 결정 |
|---|---|
| 언어 무관, 대상 버전과 필요한 계약을 충족 | 임시 도메인 vendor 승인 후보. 원래 언어 유지 |
| 오래된 게임 지원이지만 필요한 부분은 독립 JSON/NBT 처리 | 독립 부분만 시험해 승인 가능. 전체 도구 호환으로 확대하지 않음 |
| Rust 프로젝트지만 26.3 codec/팩/명령 의미가 다름 | Rust라는 이유로 채택 금지. 자체 Rust port에 맞는 최소 구현 |
| 작은 wrapper로 schema·프로세스만 변환 가능 | wrapper 사용. domain semantics는 명시한 port에 유지 |
| 광범위한 vendor 수정이 필요 | 별도 fork 기반을 만들지 않고 직접 Rust 구현 |
| 기능은 맞지만 재배포/변경 권리가 확인되지 않음 | vendor 승인 불가. 허용된 사용자 외부 도구 경로만 별도 검토 |
| 유지보수·전이 의존성·보안 검증이 불가능 | 도입 보류/범위 축소/대체. 자동 허용 없음 |
| 원형 호출이 목표보다 위험하거나 출력이 불명확 | write에 사용하지 않음. 읽기/시험 범위로 제한 가능 |

`언어와 상관없이 유지`는 **이미 채택 가능한 구성요소에 대한 실행 방침**이다. 잘못된 라이선스·버전의 구성요소를 허용하는 예외가 아니다.

## 3. 등록 원장의 단위

`policies/vendor-registry.json`의 초기 entries는 비어 있다. 조사했던 upstream 전체를 이번 문서가 채택한 것으로 만들지 않는다. 실제 lock은 G0/G1에서 검증된 artifact에 대해서만 작성한다.

각 entry의 필수 근거:

- component ID, classification, 원본 저장소·release/commit·archive SHA.
- 원본·각 하위 파일 LICENSE, transitive dependency 목록, provenance record.
- 실제 build/run 언어와 런타임, 고정 실행 명령과 디렉터리, feature 선택.
- 사용 중인 Function ID/contract version, target profile, 지원 범위와 제한.
- baseline input/output fixture, 독립 expected result와 실제 game evidence.
- wrapper location, 허용 workspace·network·effect, 관련 권한.
- owner, replacement Rust crate/port, 인수 시험, retire gate.
- 최종 채택 상태, 변경 history, 알려진 취약점·불일치.

상태: `candidate → admitted → wrapped → characterised → rust_implemented → equivalence_verified → switched → retired`.

도입 거절은 AdmissionDecision과 오류 근거로 기록하고 phase를 승격하지 않는다. `equivalence_verified`는 upstream의 모든 동작 복제를 뜻하지 않고 채택된 공통 계약의 기대 결과를 만족한다는 뜻이다. 오래된 버그와 동일한 결과를 내는 것은 합격 기준이 아니다.

## 4. 호출 경계와 폴더

| 위치 | 역할 |
|---|---|
| `vendor/<component>/<source-id>/` | 불변 원본. 언어 그대로, 원 고지 유지 |
| `vendor/patches/<component>/` | 불가피한 최소 패치와 사유. 숨은 fork 금지 |
| `integrations/legacy-workers/<component>/` | 입출력·프로세스·staging·오류·완료 변환 |
| `crates/mmmm-application/src/ports/` | 제품이 요구하는 backend-neutral 함수 |
| `crates/mmmm-*/src/` | 해당 port의 소유 Rust 구현 |
| `policies/vendor-registry.json` | 채택·변경·철수의 권리와 증거 |

기본 실행은 subprocess와 bounded JSON messages/artifacts로 격리한다. stdin으로 contract envelope, stdout에는 structured result만, stderr 로그는 redaction한다. 네트워크/환경변수 상속·cwd·출력 경로는 승인 범위로 제한한다. vendor worker가 사용자 맵 원본을 임의 열거나 직접 서버에 접속하지 않도록 한다. file/command effect는 host/application 계획을 통한다. unavoidable opaque write를 쓰면 해당 action을 명시적으로 opaque로 표시하고 정밀 undo를 주장하지 않는다.

Rust vendor도 도메인 타입에 upstream type을 그대로 노출하지 않는다. 원본 crate를 직접 link하더라도 port에서 차단하고 철수 원장에 포함한다. 같은 언어이므로 예외적으로 core 깊숙이 import해도 된다는 규칙은 없다.

## 5. v1 준비 트랙의 재작성 절차

1. **범위 고정:** 실제 사용 중인 함수 계약·저장 데이터·생성물을 조사한다. unused upstream 전체는 범위 밖이다.
2. **기대 결과 정리:** 공식 target behavior와 합성 fixture로 기대값을 만든다. 원형 출력은 비교 자료이지 유일한 oracle가 아니다.
3. **Rust 구현:** 기존 port에 새 implementation digest로 등록한다. old vendor의 오류 처리·version assumptions를 복제하지 않는다.
4. **읽기/생성 차등:** 동일 입력으로 두 구현을 격리된 staging에 실행한다. 결과를 정규화해 객체·참조·시간·의미로 비교한다. 파일 순서나 주석 차이를 실패로 만들지 않는다.
5. **실제 target 검증:** 새 출력의 load/readback·클립·사용자 작업·부분 실패를 시험한다. 두 구현을 같은 live scope에 동시 apply하지 않는다.
6. **데이터 migration:** project/manifest/source map·old handle 등 영향을 받는 것을 보고한다. rollback은 원본 backup으로 수행하며 live 작업 history를 번역해 재실행하지 않는다.
7. **기본 구현 전환:** 새 요청은 Rust로 route하고 기존 immutable plan은 재생성한다. 작업 진행 중 old binding을 교체하지 않는다.
8. **철수:** 제품 build/lock/배포/setup/기본 CI에서 vendor 실행 의존성을 제거한다. historical oracle는 권리가 허용하는 별도 test-only archive로 분리한다.

직접 언어 번역이나 구조적 복제는 자동으로 독립 MIT 저작물이 되지 않는다. 해당 코드를 바탕으로 번역했다면 적용되는 원 라이선스와 고지를 유지한다[S15]. 독립 MIT 구현이 필요하면 공개 명세·행동 요구·정당한 테스트 자료를 기반으로 provenance를 기록한다. 모델이 코드 변환을 수행했어도 조건은 같다.

## 6. v1 출시 하드 게이트

다음이 하나라도 남으면 `release.evaluate(v1)`는 failed다.

- `temporary_domain_vendor`가 product 또는 required build path에서 활성 상태다.
- adopted function contract에 replacement와 독립 결과 검증이 없다.
- 자체 Rust 구현 대신 Python/TS/Java worker를 필수 기본 경로로 옮겨 놓았다.
- 구형 Rust product/fork를 `infrastructure_dependency`로 이름만 바꿨다.
- domain logic가 Java platform shim에 남았다.
- 사용자 프로젝트 migration 손실이 미해결이거나 별도 승인 없이 기능을 제거했다.
- 실제 지원 target/game acceptance가 누락됐다.
- 권리·고지·전이 의존성·output template 권리 조건이 미확인이다.
- 기존 vendor 제거 후 출시 artifact/setup이 제대로 실행되는지 검증되지 않았다.

**허용 예외:** 범용 infrastructure dependencies, game platform shim/SDK, 사용자 소유 external tools, Minecraft output formats. 이 예외는 사용 목적과 실제 의존 그래프를 audit한다. Rust native 라이브러리의 C 기반 압축/SQLite 의존성은 별도 component로 기록하며 언어 순도 수치로 숨기지 않는다.

## 7. 필요 범위별 직접 구현 판단

| 기능 | 초기 재사용 가능 범위 | 자체 구현으로 가져올 범위 |
|---|---|---|
| MCP transport | 공식 `rmcp`와 지원 transport | MMMM tool mapping·권한·operation 의미 |
| NBT/JSON/압축 | 검증된 general-purpose library | Minecraft target codec·semantic validation |
| 기존 팩 도구 | pure parse/build의 확인된 부분 | 26.3 command/pack IR·source map·export rules |
| 기존 맵 편집 MCP | 읽기/변환의 독립 사용 부분 | stable object model·plan/apply·recovery |
| 외부 모델러 | 사용자 도구에서 장면 편집/베이크 | neutral manifest·identity/time/loss·output checking |
| 외부 모드 | 실제 설치 기능 그대로 | 공통 Provider/Compatibility·정책·호스트 경계 |

이 표는 특정 upstream 채택 승인표가 아니다. 구현 에이전트는 후보가 실제 port에 맞는지 작은 시험으로 판단한 후 lock을 만든다. 맞지 않으면 재사용하지 않아도 되며, 조사 목록을 채우기 위해 의존성을 추가하지 않는다.

## 8. 기계적 평가와 사람 검토의 경계

`release.evaluate`는 함수 소유권·의존 그래프·원장·증거 파일을 검사한다. 프로젝트의 법적 독립성이나 실제 소스가 수작업으로 복제되지 않았음을 정규식만으로 증명할 수는 없다. v1 gate에는 owner review와 provenance 검토 기록을 포함한다. 검사기가 통과했다는 사실을 변호사 의견이나 모든 취약점 부재로 표현하지 않는다.

사용자 설치 프로그램을 user_external_tool로 분류하려면 사용자가 독립적으로 선택한 외부 제작/실행 기능이어야 한다. MMMM의 임시 domain worker를 별도 설치 패키지로 옮긴 뒤 사용자 도구라고 부르는 방식은 v1 철수 회피로 판정한다.

v0 제품을 완성하기 전에 전면 Rust 포팅부터 시작하지 않는다. v0의 승인된 vendor 기준선을 유지하고 v1 준비 트랙에서 교체를 완주한다. 맞지 않는 upstream 기능은 처음부터 직접 구현하며, 이는 기존 호환 vendor의 불필요한 언어 포팅과 구분한다.
