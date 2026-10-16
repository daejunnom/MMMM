# MMMM Coordinator 경계

이 crate는 같은 제품 data root를 여는 `ApplicationService` 하나와 인증된
`127.0.0.1` HTTP JSON-RPC 2.0 listener를 연결한다. `DurableStore::open`이
실제 SQLite 원장과 native root lock을 확보한 뒤에만 `runtime/`에 endpoint를
공개한다. CLI와 MCP는 이 endpoint에 연결하며 별도 원장이나 apply 경로를 만들지 않는다.

endpoint에는 주소, 계약 버전, Coordinator epoch와 native credential reference만
있다. capability는 OS 난수로 생성하고 OS peer authentication을 확인한 Unix socket 또는
Windows 사용자 전용 named pipe에서 메모리로 전달한다. native credential API는 명시적으로
검증한 배치의 선택 경로이며 기본 CLI는 unsigned macOS Keychain이나 headless Linux
keyring의 가용성에 의존하지 않는다. HTTP header,
capability와 OS credential 내용은 진단, plan, hello 또는 공개 DTO에 넣지 않는다.
재시작은 새 epoch와 메모리 인증 표를 만들며 이전 capability를 채택하지 않는다.
Windows credential session, Linux user kernel keyring과 macOS Keychain의 실제 지원과
가용성은 각각 검증해야 한다. native store 실패에 plaintext 또는 mock fallback은 없다.

HTTP는 `POST /rpc HTTP/1.1`, 정확한 loopback `Host`, `Authorization: Bearer`,
`X-MMMM-Epoch`, `application/json`, 단일 `Content-Length`와 연결 종료만 받는다. 브라우저 origin,
chunking, 압축, upgrade, redirect, duplicate header, JSON batch와 notification은
거절한다. header 16 KiB/32개, JSON 1 MiB/깊이 64/노드 4096, 전체 ingress 5초,
response delivery 5초와 서비스 요청 30초를 기본 경계로 사용한다.

서비스 호출은 trusted composition이 만든 principal을 사용한다. request body의
principal, authority 또는 policy revision은 인증을 만들지 않는다. context ID는 paired
locator 범위만 확인하며 실제 context와 현재 grant는 application 및 host port가 다시
로드한다. bearer 인증은 world 쓰기 승인과 다르다. 현재 pure domain 함수와 application의
10개 공통 use case를 연결하고 나머지 함수는 내부 service 확장으로 같은 경계에
등록한다. 미등록 함수는 구현 unavailable을 반환한다.

`ApplicationPorts`의 실제 authority, planner, provider와 independent observer 구현은
제품 composition이 공급한다. synchronous port는 request budget와 frozen operation
deadline을 협력적으로 지켜야 한다. transport는 진행 중인 쓰기를 강제 preempt하거나
timeout을 rollback 완료로 바꾸지 않는다. CLI는 첫 socket write 이후 실패를
`DeliveryUnknown`으로 보고하고 자동 재전송하지 않는다. durable operation 조회 및
reconcile 경로가 실제 결과를 확정한다.

shutdown은 명시적으로 현재 epoch의 endpoint와 credential만 정리하고 오류를 반환한다.
stale 정상 record는 singleton lock 확보 후 정확한 epoch/reference로 정리할 수 있지만,
malformed record와 안전하지 않은 runtime directory는 보존하고 시작을 거절한다.

Windows named pipe는 overlapped I/O를 유한한 deadline으로 취소하고 별도 drain 한도에서
terminal completion을 확인한다. OS가 targeted cancellation 뒤에도 완료를 확인해 주지
않으면 pending native buffer를 안전하지 않게 해제하거나 cleanup 성공을 주장하지 않는다.
이 예외 경로는 고정 크기의 pending buffer와 handle을 process 수명 동안 보존하며
새 인증 및 제품 요청을 차단한다. 진행 중인 application 호출은 실제 결과와 미확정 상태를
원장에 기록한 뒤 listener가 종료하며, endpoint는 정리 실패의 발견 기록으로 보존한다.
일반 timeout과 확인된 취소는 정상 오류를 반환한다. 제품 SQLite, CAS와 복구 자료는
삭제하지 않는다. 이는 bootstrap native I/O의 예외 처리이며 작업 rollback 보장이 아니다.

새 테스트는 원본 JSON fixture만으로 표현할 수 없는 인증 선행 순서, principal 주입,
stale generation, native endpoint 권한 및 transport deadline 실패 경계를 검증한다.
작성된 테스트, 실제 OS 실행 결과와 게임 인수 결과는 별도로 기록한다.

호스트 연결 관리 교환은 같은 OS peer listener에서 `MMMMHST1` magic으로 구분한다.
길이 4바이트 big-endian의 공개 JSON offer 뒤에 capability 32바이트를 별도로 전송한다.
authority, installed, complete는 같은 길이 프레임의 공개 JSON이며 capability를 넣지 않는다.
capability의 HTTP 표현은 64자의 소문자 hex 하나다. Java의 anonymous stdio 공개 교환과
Rust 내부 peer의 terminal ACK·EOF 확인을 구분한다. `Finished`와 실제 완료 시각은 내부
채널 관측이며 공개 JSON 필드가 아니다.

네이티브 worker는 용량 1의 관리 채널만 소유한다. Coordinator가 기존 application 호출을
마친 사이에 유일한 Store를 짧게 빌려 등록된 프로젝트·호스트 artifact·범위를 검사한다.
offer 단계의 임시 정책은 모든 프로젝트 접근에서 비활성이다. 실제 호스트 hello/context,
Complete 쓰기, ACK와 EOF를 확인한 뒤에만 정확한 임시 정책을 활성화하고 기존 capability의
principal/context 권한을 교체한다. 실패·취소·기한 만료는 해당 임시 세대와 route만 회수한다.
Complete 이후의 유한한 native 종료 교환 동안 새 HTTP 호출을 잠시 보류할 수 있다.
진행 중인 다른 작업을 취소하거나 완료 상태로 바꾸지 않으며, SQLite·CAS·미확정 작업은
그대로 보존한다. 과거 다른 principal의 원장 기록도 새 페어링에 양도하지 않는다.

현재 실제 독립 observer 소스는 block entity가 없는 단일 block-state subject를 읽는 경로다.
이 범위를 prefab/scene 전체, entity NBT, scoreboard나 간접 engine 효과의 full-target
관측으로 확대하지 않는다. 등록된 target profile·실제 원본 source와 composite native
실행의 관측 및 authored projection 연결은 별도의 제품 integration과 인수 대상이다.
공개 설정 생성, helper 등록 또는 source fixture 통과만으로 실제 게임 연결·MVP 완료나
배포 성공을 보고하지 않는다.
