# 공통 계획·실행 use case

이 crate는 FN01 `project.inspect`, FN09–15의 공통 application 경로를 제공한다.
`Application`에 동일한 `DurableStore`, 인증된 authority, 순수 planner, 고정된
provider port, 독립 target observer, ID source와 clock을 주입한다. CLI와 MCP가
각자 작업 원장이나 apply 알고리즘을 만들지 않는다.

`plan_create`는 원본 입력을 검증하고 project revision, 모든 step context,
action descriptor와 implementation digest, 의존성, 단계 DAG, footprint,
진단·손실·승인·만료를 고정하여 private plan/CAS에 저장한다. 명령이나 월드는
실행하지 않는다. `plan_inspect`는 저장된 bytes의 계약과 digest를 확인하여 같은
계획을 반환한다. 만료된 계획 조회는 route를 새로 고르는 동작이 아니다.

`plan_apply`는 principal·project·key에 원본 plan hash를 예약한다. 같은 key와
hash의 재호출은 기존 operation을 반환한다. 새 dispatch마다 현재 권한, context,
epoch, policy, 구현 및 target precondition을 검사한다. Invocation과 fence는
provider 호출 이전에 SQLite 원장에 commit한다. 응답 손실·잘못된 write 응답은
재전송 허가가 아니다. `operation_reconcile`은 저장된 invocation의 상태와
target만 조회하며, 미실행 후속 단계나 대체 provider를 dispatch하지 않는다.

ProviderResult의 계약·출력 schema 검증과 실제 target readback을 따로 보관한다.
write는 독립 관측이 효과와 추가 진행 가능성을 확인해야 하고, 출력 검증도
확보해야 완료할 수 있다. raw 응답은 private CAS 자료로 보존하고 public report에
유효한 provider envelope만 포함한다. 진단과 관측도 runtime의 기존 CAS·operation
참조를 사용하여 restart 이후 조회할 수 있다. provider port는 승인된 결과만
반환하며, 비밀 파일을 읽거나 credential을 결과에 넣어서는 안 된다.

직접 변경의 before/after bytes를 먼저 CAS에 저장하고 artifact pins로 보존한다.
이 참조를 포함한 독립 관측을 미완료 상태로 기록한 뒤 복구 snapshot을 저장하며,
필요한 출력 검증까지 확보한 다음에만 단계를 완료한다. 관측이 host의 추가 효과가
멈췄음을 증명했어도 로컬 복구 기록이 아직 끝나지 않았다면 그 두 상태를 구분한다.
restart는 관측된 효과를 지우지 않고 후속 dispatch를 보류하여 재조정을 요구한다.

동일 target을 순서대로 바꾸는 단계는 이전 단계의 완전히 검증된 직접
before→after snapshot으로 현재 예상 digest를 이어 간다. 이 private 실행 판정은
원본 계획을 수정하지 않는다. chain의 before가 맞지 않거나 외부 편집이 관측되면
후속 dispatch를 중지한다. 모르는 scope의 fence는 쓰기만 보류하고 읽기를 막지 않는다.

queued 취소는 효과 없이 종료할 수 있다. dispatch 이후 취소는 sticky 요청이며
cooperative acknowledgment만으로 중단이나 rollback 완료를 표시하지 않는다.
복구는 기록된 after bytes와 현재 target이 같음을 확인한 새 계획이다. 동일 target을
여러 번 바꾼 작업은 연속한 snapshot chain의 최초 before와 최종 after를 사용한다.
apply에서도 정확한 after precondition을 다시 검사하므로 이후 수동 편집을 덮어쓰지
않는다. session과 binding이 바뀐 이전 복구 자료를 현재 host에 재사용하지 않는다.

새 dispatch에는 계획의 policy revision과 context digest가 그대로 필요하다. 조회,
취소와 복구는 현재의 별도 권한을 확인하므로 Apply 권한 철회나 policy revision
변경만으로 막히지 않는다. 원래 invocation의 환경과 session 식별은 유지하며,
이전 invocation에 기록된 권한을 현재 조회 권한으로 해석하지 않는다.

포트 구현은 authority의 정책·grant·실제 game principal·host capability 교집합을
검사해야 한다. `authorize_operation`의 기본 구현은 원래 principal만 허용한다.
관리자 정책을 추가하려면 별도 명시적 구현을 제공한다. provider/observer의 실제
게임 API, 인증 transport와 유한한 호출 timeout은 Coordinator와 Java host 연결부의
책임이다. application이 전달하는 dispatch deadline은 만료와 잔여 작업 예산 중 이른 값이다.

현재 result-bound dispatch는 검증된 resolution witness가 연결되기 전까지
`CAPABILITY_UNAVAILABLE`로 거절한다. provider undo는 보관된 epoch-bound token
구현이 없어 `RECOVERY_EXPIRED`로 거절한다. 여러 context를 걸친 direct 복구의 자동
조합과 큰 operation evidence의 paging도 추가 통합이 필요하다. 이 제한은 지원을
추정하거나 다른 write로 우회할 이유가 되지 않는다.

검사는 실제 임시 SQLite/CAS와 별도로 관측하는 stateful target fixture를 사용한다.
원본 echo 예제는 read만 수행하므로 write·unknown·복구 시험을 위해 descriptor와
step을 바꾸고 canonical pins를 다시 계산했다. 이러한 local fixture 검사는 실제
게임 host, 권한, 3개 플랫폼 또는 공개 배포 인수의 근거가 아니다.
