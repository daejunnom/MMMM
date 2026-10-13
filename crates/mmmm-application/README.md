# 공통 계획·실행 use case

이 crate는 FN01 `project.inspect`, FN09–15와 FN33·34의 공통 application 경로를 제공한다.
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
검증된 provider 상태의 summary와 원본 ResourceRef를 포함한다. 진단과 관측도 runtime의 기존 CAS·operation
참조를 사용하여 restart 이후 조회할 수 있다. provider port는 승인된 결과만
반환하며, 비밀 파일을 읽거나 credential을 결과에 넣어서는 안 된다.

직접 복구를 제공하는 쓰기는 dispatch 전에 독립 observer가 실제 before bytes를
캡처해야 한다. 각 target은 해당 step의 고정된 쓰기 footprint와 승인된 scope에
있어야 하며, 현재 단계의 full-target precondition digest와 실제 캡처 digest를
직접 비교한다. 캡처 원문과 원래 invocation 식별자를 operation-owned CAS에
보존한 뒤 권한·만료·target을 다시 검사하고 durable intent를 기록한다. 캡처가
없거나 불일치하면 host를 호출하지 않는다. 실제 native mutation도 atomic
expected-state 검사를 수행해야 한다.

실행 후에는 보존된 before와 새 독립 after bytes를 조합하고 artifact pins로 보존한다.
어댑터의 post-dispatch before 값과 invocation arguments는 복구 자료를 만들지 않는다.
재시작도 원래 operation·invocation pins에 묶인 캡처를 다시 읽는다.
이 참조를 포함한 독립 관측을 미완료 상태로 기록한 뒤 복구 snapshot을 저장하며,
필요한 출력 검증까지 확보한 다음에만 단계를 완료한다. 관측이 host의 추가 효과가
멈췄음을 증명했어도 로컬 복구 기록이 아직 끝나지 않았다면 그 두 상태를 구분한다.
restart는 관측된 효과를 지우지 않고 후속 dispatch를 보류하여 재조정을 요구한다.

상태 판정은 같은 runtime 원장의 작은 summary와 원본 source refs를 사용한다.
큰 ProviderResult body와 진단 원문을 summary에 복제하지 않는다. summary와 원본
CAS 참조는 하나의 transaction으로 연결하며, 이전 원문만 있는 작업도 marker가
추가되었다는 이유로 기존 실패 증거를 생략하지 않는다.

OperationReport는 64 KiB 이하의 preview와 전체 상태·효과·진단 수, 생략 수를
반환한다. 모든 단계 상태와 provider 상태, 원본 payload 참조는 NDJSON 증거 목록의
ResourceRef로 제공하며 FN31 `artifact.read`로 제한된 바이트 범위를 읽는다. 각 읽기는
현재 권한과 실제 digest를 다시 확인한다. 공개 참조나 digest 지식은 읽기 권한이
아니다. 증거 목록 발급이나 저장이 실패해도 이미 알려진 작업 상태를 조회 오류로
바꾸지 않고 `evidenceAccessError`와 불완전한 목록 표시를 반환한다.

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
과거 작업 보고서는 현재 journal grant가 원래 operation의 전체 scope를 포함하면
host가 offline이거나 새 epoch로 재시작해도 조회할 수 있다. 실제 host의 poll,
cancel과 readback에는 원래 invocation의 환경·session 검사를 별도로 적용한다.

포트 구현은 authority의 정책·grant·실제 game principal·host capability 교집합을
검사해야 한다. `authorize_operation`의 기본 구현은 원래 principal만 허용한다.
관리자 정책을 추가하려면 별도 명시적 구현을 제공한다. provider/observer의 실제
게임 API, 인증 transport와 유한한 호출 timeout은 Coordinator와 Java host 연결부의
책임이다. application이 전달하는 dispatch deadline은 만료와 잔여 작업 예산 중 이른 값이다.

저장소가 필요한 planner와 provider/observer composition에는 `*_with_store` 포트로
application이 소유한 유일한 DurableStore를 짧게 빌려준다. 계획은 private CAS만
staging할 수 있고 effectful dispatch는 durable intent 이후에만 이 포트를 호출한다.
별도 원장이나 공유 raw pointer로 저장소 소유권을 우회하지 않는다.

단계 결과 연결은 원본 6개 필드의 binding으로 frozen DAG ancestor의 실제 완료
결과만 읽는다. 서버에 등록된 순수 `JsonIdentityV1` codec, exact action data slot,
원본 출력 schema와 실제 consumer input·footprint를 검사하고 실제 arguments hash를
기록한다. 출력 schema digest는 계획을 저장하기 전에 source의 exact descriptor와
대조하여 실행 불가능한 binding 때문에 선행 쓰기를 먼저 하지 않는다.
runtime은 동일 dispatch transaction에서 registered descriptor·codec,
원본 Invocation·완료 결과·summary source association과 기존 template 밖 변경이
없음을 독립 검증하고 resolution witness를 pin한다. placeholder는 host에 보내지
않는다. codec이나 verifier가 없는 구성은 `CAPABILITY_UNAVAILABLE`로 거절한다.
원문을 저장한 뒤 typed marker를 쓰기 전에 중단되어도 정본 envelope의 failed
상태는 보존한다. raw marker의 작은 metadata는 출력 data 검증이나 성공 권한이
아니다. metadata가 없는 legacy 결과는 32MiB 누적 예산 안에서 실제 원문을
검사하며, 미검사 이력이 있으면 후속 dispatch를 막고 보고서에 표시한다.
private 증거 형식과 등록 경계는 [RESULT_BINDING_WITNESS](RESULT_BINDING_WITNESS.ko.md)를 따른다.

provider undo는 보관된 epoch-bound token
구현이 없어 `RECOVERY_EXPIRED`로 거절한다. 여러 context를 걸친 direct 복구의 자동
조합도 추가 통합이 필요하다. 이 제한은 지원을
추정하거나 다른 write로 우회할 이유가 되지 않는다.

검사는 실제 임시 SQLite/CAS와 별도로 관측하는 stateful target fixture를 사용한다.
원본 echo 예제는 read만 수행하므로 write·unknown·복구 시험을 위해 descriptor와
step을 바꾸고 canonical pins를 다시 계산했다. 이러한 local fixture 검사는 실제
게임 host, 권한, 3개 플랫폼 또는 공개 배포 인수의 근거가 아니다.

`action.read`는 실제 등록된 read action에만 별도의 현재 ReadAction 권한과
고정된 input/output schema를 적용한다. dedicated read 포트가 없으면 거부하며
write Invocation이나 새 operation을 만들어 대신 호출하지 않는다. 결과 반환
직전에도 현재 권한과 context를 다시 확인한다. `action.plan`은 server context의
project와 실제 revision을 읽고 같은 `external.action` planner로 고정된 계획을
만든다. provider preview나 target mutation은 수행하지 않는다.

멱등 apply의 기존 작업 조회도 현재 ObserveOperation 권한을 확인한다. Apply
권한이 철회되어도 별도 Observe grant로 조회할 수 있지만, ReadPlan 권한만으로
작업 결과나 증거 접근 권한을 생성하지 않는다.
