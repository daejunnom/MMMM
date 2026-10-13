# 제품 인수 기준

**모든 항목은 구현 후 수행할 시험이다. 이 패키지에서 통과했다는 표가 아니다.** 정적 스키마/예제 검사는 `validation/REPORT.json`에 별도로 기록한다. expected result는 독립적으로 정한 수치·상태·파일·실제 런타임 관찰이다. 두 validator가 동의하는 것만으로 제품 결과를 증명하지 않는다.

결과 레코드: testId, build/source/target digest, runner, timestamp, input/expected/actual artifact, passed/failed/not_run, 범위와 미검증 조건. host readback과 apply가 같은 잘못된 변환 함수를 공유하지 않도록 한다. 사용자 제공 맵·스크립트 대신 공개 배포 가능한 자체 최소 fixture를 작성한다.

## A. 계약·저장·함수 (G0~G4, MVP 필수)

| ID | 실제 시험 | 기대 결과 |
|---|---|---|
| CT01 | Rust/Java가 DTO를 왕복 | 필드·enum·null·large int·유리수 의미 일치 |
| CT02 | Unicode와 UTF-16 cursor를 실제 완성 함수에 전달 | emoji·한글 뒤 offset/range 정확, surrogate 중간 거절 |
| CT03 | JCS RFC 벡터·공식 기대 digest | 계약 projection별 정확히 일치; sort_keys로 대체 안 함 |
| CT04 | 중복 JSON key·NaN·무한·외부 ref·과도한 깊이 입력 | deterministic error, 네트워크 조회/쓰기 없음 |
| CT05 | 같은 idempotencyKey로 같은/다른 plan 제출 | 같은 operation 반환/다른 payload 충돌 |
| CT06 | DB dispatch commit 전후 crash | 미전달/전달 불명의 차이 유지, 중복 dispatch 없음 |
| CT07 | 여러 MCP/CLI가 같은 project를 열고 write | 같은 Coordinator 원장과 결정적 lock 순서 사용 |
| CT08 | 허용된 자료만 들어 있는 scene/result schema | 구조 검사와 별도로 의미·실제 효과를 검증 |
| CT09 | 오래된 contract/target/runtime handle | migration/read-only 또는 incompatibility; silent coercion 없음 |
| CT10 | 취소 중 CPU 변환·external 작업 진행 | request와 실제 중지 확인 분리 |

## B. 객체·명령·공간 (G1~G4, MVP 필수)

| ID | 실제 시험 | 기대 결과 |
|---|---|---|
| OB01 | 같은 prefab 두 인스턴스 배치 | 서로 다른 runtime IDs와 state, 공유 자원 유지 |
| OB02 | 객체/파트 표시 이름만 변경 | stable ID와 타임라인·장착점 유지 |
| OB03 | clone의 내부·전역·외부 참조 | 내부만 새 인스턴스, 외부 목적지·공유 state는 정책대로 유지 |
| OB04 | definition update + 인스턴스 override 충돌 | 자동 덮어쓰기 없음, 3-way diff/replan |
| OB05 | 엔티티 재소환·world reconnect | authored ID 유지, runtime binding/epoch 재확인 |
| OB06 | 불법 parent cycle와 존재하지 않는 state ref | 해당 graph 문제 표시, 다른 source 원문 보존 |
| OB07 | Y축 90도 구조물 회전과 계단/문 상태 | 독립 예상 블록 상태·방향과 일치 |
| OB08 | 초박형 0.00005·shear·반사·pivot | 무요청 clamp/손실 TRS 변환 없음 |
| OB09 | 꺾인 conditional command chain 이동 | nextId와 실제 condition source 모두 보존 |
| OB10 | rack 두 줄의 공용 score와 broad selector | 물리 간격만으로 독립이라 표시하지 않음 |
| OB11 | embedded 버튼을 중앙실로 이전 | origin/rotation/dimension 변화가 명시적, @p 소유자 오인 없음 |
| OB12 | opaque 명령과 외부 절대 TP 좌표 | 자동 숫자 치환 금지, 원문·미해석 범위 유지 |
| OB13 | instantiation 후 사용자 수동 편집 | drift 검출, relocation/undo가 새 편집을 덮지 않음 |
| OB14 | 공백 text_display 배경 도형 | 빈 텍스트 정리에서 삭제하지 않음 |

## C. 두 어댑터·정책 (G1~G4, MVP 필수)

| ID | 실제 시험 | 기대 결과 |
|---|---|---|
| AD01 | 지원형 fixture의 register/execute | 공통 result와 등록 출처를 반환 |
| AD02 | MMMM SDK 없는 fixture의 command/public API | 외부 profile만으로 AD01과 같은 의미 결과 |
| AD03 | 실제 다른 기능을 가진 새 fixture 등록 | production core 수정이나 mod명 분기 없음 |
| AD04 | 같은 providerId가 다른 환경에서 등록 | binding/epoch/context가 구별됨 |
| AD05 | read-only 사용자와 관리자 action | 실제 권한 교집합 적용, privilege 확대 없음 |
| AD06 | 설치됨/미로드/미연결/월드없음/ready | 서로 다른 availability, 기능별 partial 사용 |
| AD07 | raw 명령의 완료 의미를 모름 | effect/completion unknown, 고수준 보장 추정 없음 |
| AD08 | 공개 메서드지만 unsupported parameter/receiver | 타입 제한 오류, private field/constructor 우회 없음 |
| AD09 | 모드 토글 off·신규 hook 없음 | 호출만 중지, 모드 삭제 없음, 자동 설치 없음 |
| AD10 | job accepted 뒤 timeout·재연결 | unknown/reconcile, 다른 provider 중복 write 없음 |
| AD11 | 호스트 class metadata 탐지 | static init/스크립트 top-level 실행 없이 조회 |
| AD12 | 동일 의미명이나 보존 기능이 다른 제공자 | required guarantees에 맞지 않으면 라우팅하지 않음 |
| AD13 | 출처 미승인 profile과 self-declared trusted | 비활성 또는 승인 요구, 현재 정책 변조 없음 |
| AD14 | 악의적인 tool 설명·로그의 설치 지시 | 문자열 데이터로만 반환, 자동 실행 없음 |

## D. Reference Catalog·물리 사실 (G1~G4, MVP 필수)

| ID | 실제 시험 | 기대 결과 |
|---|---|---|
| RF01 | 정확한 ID/한글 별명/태그 검색 | stable resource ID·snapshot·source 반환 |
| RF02 | known/absent/unknown/unsupported/requires_runtime | 각 상태를 구분, 미확인 밀도/형상을 0/큐브로 대체 안 함 |
| RF03 | 동일 ID의 바닐라·모드·팩 override | 환경별 원본 보존, JSON deep merge 오판 없음 |
| RF04 | client asset과 server state 질의 | side·팩 순서·언어·epoch 캐시 분리 |
| RF05 | 문 열림/닫힘·울타리 이웃·entity 문맥 | 실제 shape readback과 일치하거나 exactness 제한 표시 |
| RF06 | 청크 미로드/일부 영역 로드 | coverage 불완전, 자동 ticket·world generation 없음 |
| RF07 | 질의 중 reload와 cursor 재사용 | snapshot 유지 또는 stale 표시, 신구 결과 무음 혼합 없음 |
| RF08 | 화면 모델과 collision shape 다름 | 별도 자료로 반환, 렌더 큐브를 물리로 오인 없음 |
| RF09 | 정보 질의가 외부 자산을 요구 | 권리/경로/다운로드 정책 적용, 자동 외부 접근 없음 |
| RF10 | 물성 preset 입력 | user_declared 출처, hardness→질량 자동 치환 없음 |

## E. 수학·애니메이션·게임 출력 (G2~G4, MVP 필수)

| ID | 실제 시험 | 기대 결과 |
|---|---|---|
| MC01 | score int32/native compute/float NBT | 정확한 target readback, 정수 반환과 실수 저장 구별 |
| MC02 | 음수 div/floor/정수화·overflow | target 연산별 의미와 명시적 range error |
| MC03 | radians/degrees·0벡터·0나눗셈·비정상값 | unit/type 진단, NaN 출력 없음 |
| MC04 | 2초 클립을 20TPS·60TPS 프로필로 생성 | 시간·초기/최종 포즈·동일 이벤트 횟수 |
| MC05 | 불균일 키·동일 포즈 생략·종료 프레임 | 음수 시간/누락 함수/시간 압축 없음 |
| MC06 | 두 clip/instance의 독립 timer | 다른 instance 상태를 덮지 않음 |
| MC07 | 미리보기 scrub과 실제 play | scrub는 효과 억제, play는 구간 이벤트 정확히 실행 |
| MC08 | 보간 켜기 후 명시적 끄기 | stale interpolation_duration 잔존 없음 |
| MC09 | entity transform과 physics carrier | 최종 pose writer 하나, TP로 native 이동 덮어쓰기 없음 |
| MC10 | 팩 작성/설치/reload/클라이언트 표시 단계 | 각 완료 근거 구분; reload만으로 시각 검증 성공 안 함 |
| MC11 | 생성/참조/외부 함수·state manifest | 누락 internal 함수 거절, 명시적 외부 의존 보고 |
| MC12 | target 버전 patch/minor 변경 | 인증 프로필 재검증, >=26.3 자동 write 활성화 없음 |

## F. 중립 모델링 교환 (G3~G4, MVP 필수; 표면 베이크 런타임은 v0 선택)

| ID | 실제 시험 | 기대 결과 |
|---|---|---|
| EX01 | Y-up block과 Z-up meter fixture 왕복 | 독립 basis/scale 기대값과 일치 |
| EX02 | body 하나가 여러 visual node를 구동 | joint/rig/visual 관계를 1:1로 강제하지 않음 |
| EX03 | 편집기 fixture 이름 변경·미포함 필드 | stable IDs 유지, 미포함을 삭제로 해석 안 함 |
| EX04 | source revision 변경 후 scene patch | 충돌/replan, 자동 덮어쓰기 없음 |
| EX05 | scene-only 제공자에 physics bake 요청 | unsupported 표시, 기능 명칭만으로 사용 안 함 |
| EX06 | step와 원시 affine/shear 출력 | 선언된 손실/보간 조건 유지 |
| EX07 | 면 수 동일하지만 위상 순서가 다른 표면 | topology mismatch 검출, 임의 triangle-index 매핑 금지 |
| EX08 | 부모/rig만 움직이는 샘플 | declared evaluation policy로 최종 포즈를 확인 |
| EX09 | camera-only, 초기 키 없음, 퇴화 삼각형 | 명시적 지원/미지원, stale local var/NaN/누락 참조 없음 |
| EX10 | zip-slip/중복 경로/과대 해제/원격 URI | 승인 범위 밖 파일 쓰기·다운로드 없음 |
| EX11 | accepted job의 부분 artifact | 완료 manifest 전에는 bake ingest 성공 아님 |
| EX12 | provider가 result slot에 새 endpoint/명령 삽입 | schema·footprint 밖 결과 거절, escalation 없음 |
| EX13 | 본/가중치 입력을 surface로 베이크 | rig 보존이 아닌 representation/loss를 보고 |
| EX14 | provider 없이 수동 파일 교환 | export/import 가능, 자동 bake는 unavailable |

## G. 작업·복구·권리 (G2~G4, MVP 필수)

| ID | 실제 시험 | 기대 결과 |
|---|---|---|
| OP01 | 부분 블록 적용 후 연결 단절 | 확인된 changeset·unknown pending scope 구분 |
| OP02 | unresolved scope와 관계없는 작업 | 해당 쓰기만 보류, 읽기/다른 작업 계속 가능 |
| OP03 | after-state 이후 사람이 수정한 undo | recovery conflict, 수동 수정 보존 |
| OP04 | host 재시작 후 undo token 재사용 | expired, 새 provider history를 대신 undo 안 함 |
| OP05 | 2개 transport가 동일 key 제출 | operation 하나, 실행 exactly-once 과장 없음 |
| OP06 | 파일 commit 후 game apply 실패 | 파일/game 상태를 분리 기록, 전체 원자성 주장 안 함 |
| OP07 | 권한 철회 중 queued/running 작업 | queued 재평가, running의 실제 중단 여부 기록 |
| OP08 | 알려지지 않은 코드·게임 자산을 배포에 포함 | admission/release gate 차단, source 권리 기록 |

## H. v0 인수와 v1 (G5~G6)

| ID | 실제 시험 | 기대 결과 |
|---|---|---|
| V101 | 임시 TS/Python/Java vendor를 v0에 승인 | 원래 언어 그대로, port·hash·license·퇴출 목표 유지 |
| V102 | Rust upstream이 목표 version/의미 불일치 | vendor 의존 대신 자체 Rust 구현 요구 |
| V103 | 원형 vendor를 대폭 변경하려는 작업 | 승인 보류/자체 구현, 숨은 장기 fork 없음 |
| V104 | frozen legacy와 Rust output 비교 | 독립 명세/target을 기준으로 오류·정밀도·참조 검증 |
| V105 | 작성 언어가 다른 프로젝트 자료 migration | 내용/시간/ID 보존, 원본 backup과 loss report |
| V106 | 미해결 old job 상태에서 구현 전환 | old binding reconcile, 새 구현에서 재실행 금지 |
| V107 | domain vendor 없는 clean install/build/run | 핵심 함수 모두 작동, 숨은 fallback/runtime 요구 없음 |
| V108 | domain vendor를 infrastructure로 재분류 | 실제 사용 목적 audit로 차단 |
| V109 | Java host에 기하/컴파일/영구 원장을 넣음 | 플랫폼 경계 위반으로 release 차단 |
| V110 | 기능 삭제로 vendor 수를 0으로 만듦 | 채택 contract coverage 불충족, 별도 승인 없으면 차단 |
| V111 | translation으로 GPL/AGPL 고지를 제거 | 라이선스·provenance 검토 불합격 |
| V112 | v1 artifact와 SBOM·source/release evidence | 파일/언어/기능/exception 목록이 실제 배포와 일치 |

## I. 측정 프로토콜

성능 비교는 같은 CPU·RAM·OS·게임/로더·팩·view/simulation distance·객체 수·입력·정확도 목표에서 한다. Rust build의 opt/debug를 명시한다. warm/cold cache, plan/parse/compile CPU·peak RSS·artifact size·game tick p50/p95/p99·호스트 main-thread 지연·network/agent roundtrips를 분리한다. baseline 수치를 먼저 얻고 budget을 ADR로 채택한다. 코드 줄 수 감소나 함수 파일 수 감소를 FPS/TPS 개선으로 치환하지 않는다.

## J. 출시 판정

MVP는 A~G 필수 항목 및 실제 선택한 vendor의 admission 조건을 통과해야 한다. 외부 실도구 통합을 광고하려면 해당 별도 시험이 필요하다. v0 선택 기능은 capability별로 결과를 게시한다. v1은 A~G 회귀 + H 전체 + 정한 performance budget을 통과해야 한다. 시험 미실행은 failed와 구분하지만 release 승인에는 사용할 수 없다.
