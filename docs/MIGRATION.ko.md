# 0.1 계약 → 0.2 통합 계약 → v1 구현 교체

이 파일은 migration 구현 요구다. 실제 migration 프로그램이 제공되는 것은 아니다. 제품이 아직 배포되지 않았다면 .2를 최초 저장 계약으로 시작하며, 존재하지 않는 사용자 데이터를 옮기는 코드를 먼저 만들 필요는 없다.

## 1. 서로 다른 변경을 분리

| 변경 | 관리 단위 | 규칙 |
|---|---|---|
| TS→Rust 구현 | implementation digest | 외부 계약을 몰래 바꾸지 않음 |
| 계약 .1→.2 | contractVersion + migration | 형식·의미 변경과 pending resolution 기록 |
| vendor→Rust owned | component/replacement record | 기능별 독립 결과·실제 target 검증 |
| Minecraft 버전 변경 | target profile | 읽기·쓰기·실행 검증을 별도 수행 |
| 사용자 tool 교체 | binding/profile digest | immutable plan 폐기/재계획, 프로젝트 ID 유지 |

## 2. .1에서 바뀌는 필드

| 대상 | .2 변화 | 기존 자료 처리 |
|---|---|---|
| EnvironmentRef | game/external/offline discriminator | 기존 game 필드는 game으로, 외부 자료의 환경을 추측하지 않음 |
| RationalTime | decimal-string numerator/denominator | 정확히 표현된 안전 정수만 손실 없이 변환; 손실 가능 값은 수동 검토 |
| ActionDescriptor | 구현 digest와 version evidence | 실행본 확인 전엔 unverified; 더미 hash로 ready 활성화 금지 |
| ExecutionContext | contextDigest와 epoch 의존 | 권한 컨텍스트는 다시 발급, old context를 권한 증거로 재사용 안 함 |
| PlanStep | step별 context·implementation pin | 이전 계획은 expired/stale 보관; 자동 재실행 안 함 |
| ExecutionPlan | 다중 context pins, dependency pins | 필요한 새 사실을 확보한 뒤 새 plan |
| InstanceOverride | typed patch | 임의 old JSON patch는 unknown/candidate로 보존 |
| AnimationClip/CommandModule | revision 및 pose/time 의미 강화 | 추출한 source revision 기록, additive 여부 불명은 자동 변환하지 않음 |
| Catalog/Scene/Physics/Bake | 새 정본 DTO | 해당 자료가 없다고 unknown 사실을 확정값으로 채우지 않음 |
| Vendor registry | 분류/함수별 철수/증거 | actual source audit 이후 등록; 빈 registry로 v1 승인하지 않음 |

## 3. 실행 순서

원본 읽기 전용 snapshot/hash → 작업 복사본 → 구조 변환 → 의미 진단 → SourceMap/참조 연결 → 손실·미확인 보고 → 새 프로젝트 리비전 생성 → 사용자 검토 → 원자적 범위 내 commit.

migration은 원본과 pending runtime 상태를 함께 삭제하지 않는다. old operation의 불명 effect·reservation·recovery token은 history로 보존한다. 대상 게임/호스트 epoch가 달라졌다면 새 readback으로 binding을 재구축한다. Minecraft 전체 world upgrade는 이 포맷 migration 작업의 효과가 아니다.

## 4. v1 Rust 전환 시 데이터 불변성

함수 계약의 성공·실패·취소·부분 완료 의미가 유지되어야 한다. 출력 파일의 정렬·공백·주석은 달라질 수 있지만 게임 자원 ID·객체 상태·시간·event·coverage 의미는 보존한다. 생성 결과에서 필요한 수정 원본을 역으로 복원할 수 없으면 손실을 명시한다. v1 직전에 upstream format을 정본으로 정했다가 사용자의 프로젝트 전체 재작성을 요구하지 않는다.

## 5. 소스와 fixture의 위계

현재 예제의 기록 시각·버전·provider는 합성값이다. 예제 plan은 실제 시간이 지나 만료된 상태여도 구조 샘플로 보존한다. 실행 시험에서는 fake Clock 또는 새로 발급한 시간·context를 사용한다. 해시 예제는 동봉 범위만 검사하며 전체 JCS conformance와 runtime 검증은 별도다.
