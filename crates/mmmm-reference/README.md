# 참조 카탈로그

원본 `CatalogQuery`, `RecordQuery`, `SnapshotRequest`와 출력 스키마를 검증하는
FN20–22의 순수 의미 구현이다. 파일, 네트워크와 게임 연결은 직접 열지 않는다.

`Catalog::insert_snapshot`은 신뢰한 source가 만든 `SnapshotInput`을 등록한다.
같은 ID와 같은 내용은 재사용하고, 같은 ID 아래의 다른 내용은 거절한다.
등록 과정에서 record와 snapshot의 source, context별 조회 키, coverage와 메모리
예산을 검증한다. 네 자료층, 출처, pack 배열의 순서와 unknown 상태를 보존하며
서로 다른 환경의 값을 deep merge하지 않는다.

`ReadPrincipal`은 Coordinator의 인증 결과다. wire에 독자적인 인증 필드를 넣지
않는다. `AccessControl`은 snapshot 조회, record 조회와 source 읽기의 현재 권한을
검사한다. 검색 continuation은 호출자가 공급한 메모리의 HMAC 키로 발급하고
snapshot revision, environment fingerprint, query 조건, limit, principal과 현재
보이는 record 집합을 묶는다. 키는 애플리케이션이 무작위로 생성하며 저장이나
출력을 하지 않는다. query digest는 cursor를 제외한 조회 조건의 내부 JCS digest다.
새 canonical projection 또는 새로운 wire 형식을 선언하는 것이 아니다.

검색 별명과 태그는 source에서 얻은 `SearchTerms`로 등록한다. 결과는 원본
`DataRecord`를 반환하므로 unknown density가 0으로 바뀌거나 별명이 resource ID를
대체하지 않는다. `describe`에서 누락 ID를 분류하려면 해당 kind/context의
`MissingRecordClaim`이 필요하다. 완전한 source coverage와 출처가 있어야 `absent`를
반환한다. 자료가 없는 곳에서 provenance를 만들어 내지 않는다.

`SnapshotIdentity`는 registry generation, mod digest, 질의 scope와 실제 관찰 구간을
내부 revision에 포함한다. 원본 `DataSnapshot`에는 이 항목을 직접 내보낼 필드가
없다. 관찰 구간과 원본 source evidence의 영구 보관은 애플리케이션이 담당한다.
`snapshot_pin`은 권한을 확인한 immutable 입력을 제공하며 live target의 현재 상태를
확인한 결과는 아니다.

`SnapshotSource`는 승인한 source root 또는 호스트 연결을 읽는 포트다. FN22는
이 포트를 한 번 호출하고 실제 source bytes의 SHA-256과 반환한 source 참조를
검증한다. caller의 hash와 rights 표기만으로 성공을 인정하지 않는다. 취소되면
실제로 확보한 자료와 구체적인 partial coverage만 등록할 수 있다. 포트에는
deadline/취소 조건이 전달되며 외부 I/O의 강제 종료는 runtime의 책임이다.
source 개수와 bytes 예산도 포트에 전달한다. 요청한 source는 포트 호출 전에
권한을 확인하고, 동적으로 발견한 source에는 전달한 사전 승인 gate를 사용한다.
검색 응답은 개수 제한, bytes, 노드 수와 중첩 예산을 함께 적용하고 실제 페이지 끝의 continuation을
반환한다.

검사는 원본 최소 snapshot/known/unknown 예제를 재사용한다. 기존 예제에는
pagination, 권한 변화, source hash 불일치와 관찰 구간이 없으므로 같은 최소 입력을
변형한 자체 검사로 중요한 실패 경계를 확인한다. 이 검사는 게임 호스트 관찰,
실제 파일 권리 확인, source 추출기와 RF01–10의 실제 게임 인수를 대신하지 않는다.
