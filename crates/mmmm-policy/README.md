# MMMM 채택 및 출시 판정

이 crate는 FN35 `dependency.admit`와 FN36 `release.evaluate`의 순수 판정을 소유한다.
원본 wire 스키마와 함수 인덱스를 검증하며 다운로드, 설치, vendor 원장 수정,
파일 조사, worker 실행 또는 공개 배포를 수행하지 않는다.

일반 함수는 증거를 주장하는 입력만 받으므로 채택은 `defer`, 출시는
`eligible: false`를 반환한다. `*_verified` 경로는 신뢰하는 application 또는
xtask 구성에서 주입한 `TrustedEvidenceVerifier`가 인증한 불투명 증거를 요구한다.
이 verifier를 RPC 인자나 vendor callback으로 구성하면 안 된다. SHA 일치와
자기 선언은 인증이 아니다. verifier 구현은 증거 bytes, 생산자와 권한,
정확한 canonical claim digest, 실제 관측·검토 및 시험 범위를 확인해야 한다.
이 순수 crate는 서명 키, 실제 파일 bytes 또는 서버에 접근하지 않는다.

채택 증거는 component/source/implementation digest, 계약과 target 범위를
고정한다. 실제 파일별 LICENSE와 전이 의존성, provenance, 권리 검토, build/run,
독립 기대값, 소유자 및 권한 검토, worker의 유한한 예산과 허용 범위가 필요하다.
임시 도메인 vendor에는 replacement 인수 계획도 필요하다. 언어가 Rust여도
게임 의미가 다르거나 대규모 fork가 필요하면 `rust_own`이다. 확인되지 않은
권리는 허용하지 않는다. `external_only`는 사용자가 독립적으로 선택한
설치 도구의 검토된 사용 범위에 한정하며 복사·재배포 권한을 만들지 않는다.
원본 vendor registry는 비어 있으며 이 구현만으로 어떤 후보도 채택되지 않는다.

출시 증거는 제품 `0.1.0`, 계약 `0.2.0`, 최종 고정 source SHA, 동일 release
bundle bytes, 실제 artifact inventory 및 Java 26.3의 game/loader/host/profile
digest에 모두 묶인다. 원본 A–G 82개 인수 항목을 줄일 수 없다. 세 OS의 실제
서버 및 기본 수동 클라이언트, Windows 전체 시각·상호작용·멀티플레이,
target별 vanilla 출력, SBOM, NOTICE, 전이/native 의존성과 자산의 권리 검토,
함수 소유권 및 실제 의존 그래프, 미해결 쓰기 원장 검토를 요구한다.
실패, 미실행, 범위 제한과 주장·증거 불일치는 각각 진단으로 보존한다.
`specification_only`와 synthetic 증거는 출시를 승인할 수 없다. G5/G6와 v1은
후속 범위이며 이번 evaluator는 deferred로 차단한다.

단위 fixture는 기존 패키지에 없는 부정한 증거·pin·원장·권리 경계와 판정기의
성공 경로를 검증하기 위해 작성했다. fixture verifier가 실제 인증을 모사해
성공 경로를 시험해도 제품 채택, 실제 게임 인수 또는 공개 출시 근거가 아니다.
실제 collector/verifier 연결, 파일 bytes와 서명 검증 및 게임 증거 수집은
application/xtask가 구현하고 검증해야 한다.
