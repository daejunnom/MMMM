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

FN23의 `ShapeService`는 원본 `ShapeQueryContext`와 `ShapeResult`를 검증한다.
`ShapeAuthority`는 principal에 묶인 서버 context, immutable snapshot과 현재
호스트 hello를 제공한다. 사용자 query의 context ID는 조회 키이며 권한이나
target pin을 설치하는 입력으로 취급하지 않는다. scope 밖 위치, epoch와 side
불일치, 실제 block state와 neighbor 변경은 조회 전에 거절한다.

`PairedShapeSource`는 `HostShapeTransport`를 통해 exact `0.2.0` 호스트의
`inspect`로 현재 probe를 확인하고, 같은 게임 task에서 expected probe를 다시
확인한 native query를 요청한다. 내부 selector는 `world.shape_probe`와
`world.shape_query`다. Java는 loaded-only native voxel AABB의 실제 bytes를
제공한다. Rust는 `ShapeGeometryStore`에 원문 bytes를 보관하고 SHA-256, size와
media type이 일치하는 `ResourceRef`를 원본 결과에 넣는다. offset과 여러 AABB의
union을 centered box로 바꾸지 않는다. 이 내부 artifact의 media type은
`application/vnd.mmmm.native-voxel-aabbs+json`이며 wire 스키마를 대체하지 않는다.

미지원 또는 알 수 없는 형상은 geometry가 없는 해당 상태로 반환한다. 실제
known empty voxel shape만 `boxes: []`로 보관한다. entity resolver가 없으면
호스트의 명시적 미지원 오류를 보존하고 기본 entity를 대신 넣지 않는다.
readiness, loaded 영역이나 실제 target fingerprint 및 pack hash가 확인되지
않으면 부분 coverage의 unknown 결과를 반환한다. 이 진단의 evidence는 native
형상 bytes와 구분하여 `generated_report`로 기록한다.

캐시에서도 권한, 현재 probe와 geometry ACL을 매번 확인한다. 전체 의존성을
호스트가 증명한 경우에만 캐시하며 arbitrary mod의 의존성이 알 수 없으면
캐시를 사용하지 않는다. 키는 snapshot revision, 권한 범위, context, profile,
host, pack, registry, locale, mode, 실제 state, neighbors, entity와 fluid,
readiness 및 전체 의존성 digest를 포함한다. epoch, region, entity와 principal
무효화는 해당 의존성 범위에 적용하며 알 수 없는 전역 변경은 전체 무효화를
사용한다. 캐시 결과의 원래 관측 구간과 현재 probe 구간을 따로 보존한다.

원본 예제에는 native 관측, probe/query 경쟁과 cache ACL 자료가 없으므로
같은 최소 context와 snapshot을 변형한 자체 입력으로 검사한다. 실제 target
artifact/pack/mod fingerprint 공급, source capture, scoped entity 및 native
support/fluid API의 검증은 호스트와 애플리케이션의 실제 연결에서 확보해야 한다.
이 crate의 포트 검사만으로 게임 인수나 배포 완료를 주장하지 않는다.

FN22의 `VerifiedSnapshotSource`는 승인된 source binding을 읽는 실제 조합이다.
`CatalogCaptureBackend`가 principal에 묶인 context와 새 snapshot ID를 발급하고
source ID를 승인된 파일·archive member·runtime 연결로 해석한다. 사용자 locator를
직접 파일이나 URL로 열지 않는다. 읽기 전 source gate와 읽기 후 rights witness를
확인하며, acquire 전에 byte 상한을 source I/O에 전달한다. link 변경, archive 경로
탈출과 팽창 제한은 source를 여는 backend가 검사해야 한다.

`HostRegistryTransport`는 exact `0.2.0` 호스트의 `inspect/native_registry`를
사용한다. Rust의 닫힌 decoder는 실제 report bytes에서 block/item/entity ID와
blockstate 전체 기본값 및 허용값을 검증한다. 이 열거의 없는 ID는 source-backed
absent 근거가 되지만 NBT·명령·다른 registry·물성·자산·world shape를 안다는
뜻으로 확대하지 않는다. 실제 JSON 자산은 값을 보존하고 binary 자산은 원문 CAS
resource로 참조한다. 같은 이름의 여러 파일을 일반 JSON merge로 합치지 않는다.
effective asset 선택과 archive member 열거는 승인된 resource resolver가 제공한다.

source의 `CatalogLayer`와 provenance를 구분하며 실제로 확보한 자료층만 snapshot에
넣는다. artifact·server pack·client pack·mod source의 역할을 검사하고 각 실제
bytes의 SHA-256을 계산한다. 두 pack 배열은 정렬하거나 뒤집지 않는다. registry
보고서 hash를 게임 JAR hash로 사용하지 않는다. 내부 environment fingerprint는
`mmmm.capture-environment/1` recipe를 사용하고 scope는 별도로 snapshot identity에
묶는다. 요청에서 지정한 hash와 권리 문자열은 실제 확인을 대신하지 않는다.

실제로 확보한 원문은 durable CAS에 source·rights·owner 자료와 함께 보존한 다음
원본 `ResourceRef`의 hash·크기·media type을 다시 검증한다. required version,
locale, mod inventory, ordered pack 정보나 live game artifact가 unknown이면
확보한 evidence는 남기고 canonical snapshot 등록을 거절한다. `None`은 unknown,
`Some([])`는 실제로 확인한 empty stack이다. offline reference의 미검증 game
artifact는 원본의 `null`로 보존하며 실제 게임 검증으로 승격하지 않는다.
완료 직전에 실제 registry witness, epoch, pack selection과 현재 권한을 재검사한다.
취소 시 필수 식별 자료를 이미 확보했다면 확보한 자료만 partial snapshot에 넣고
미확보 source와 생략한 자산 처리를 exclusions에 기록한다. 이때 추가 source나
게임 조회 없이 보존한 과거 관측의 scope와 현재 권한을 재확인한다. 필수 식별
자료가 부족하면 snapshot을 발급하지 않으며 이미 보존한 raw evidence는 남긴다.

현재 native report는 256KiB 상한을 넘으면 명시적으로 실패하며 complete라는
이름으로 잘라 반환하지 않는다. 긴 registry의 pagination, 실제 pack resolver,
command tree와 KO/EN alias의 source 연결은 각 실제 포트에서 같은 identity 및
권한 pin을 유지해야 한다. 취소나 identity 부족으로 snapshot을 발급할 수 없는
경우에도 확보해 보존한 원문 evidence를 성공한 snapshot으로 표시하지 않는다.
