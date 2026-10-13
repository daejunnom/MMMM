# MMMM 중립 장면 교환

이 crate는 원본 계약의 FN24–29에 필요한 bundle, 물리 입력, 결과 검사와
순수 patch 의미를 구현한다. 저장 및 wire 정본은 `contracts/mmmm.schema.json`이며
이 crate의 내부 구조나 Rust DTO에서 별도 스키마를 만들지 않는다.

`exchange_prepare`는 고정된 selection과 physics revision, 실제 승인된 자원 bytes를
검사하고 immutable manifest와 payload를 돌려준다. 호출 composition이 이를 제품 CAS에
staging해야 한다. 원본 사용자 파일, 게임 월드나 빌드 cache를 이 crate가 수정하지 않는다.
`exchange_inspect`는 승인된 ResourceRef를 통해 detached JSON manifest 또는 실제 ZIP을
읽고 raw SHA-256, schema, graph, ID, coordinate, 권리와 source pin을 확인한다.

ZIP codec은 bounded ZIP32 Stored/Deflate를 읽고, 정렬된 member와 고정 timestamp 및 mode로
deterministic Stored ZIP32를 쓴다. header/metadata preflight는 codec의 directory allocation
전에 실행한다. central/local 이름과 flag, CRC, size, 실제 Deflate stream consumption을
대조하고 경로 탈출, 원격 URI, 별칭, 중복, 파일/디렉터리 충돌, symlink와 특수 mode를
거절한다. ZIP64, 다중 disk와 암호화는 이 profile의 미지원 형식이다. 파일 추출과
외부 프로그램 실행 API는 제공하지 않는다. 압축 해제와 인코딩을 요청 수명에 연결할 때
`read_zip_with_cancel`과 `write_zip_with_cancel`에 신뢰된 취소 상태를 주입한다.

default archive 예산은 입력 64 MiB, member 16 MiB, 해제/참조 합계 32 MiB,
member 4096개, ratio 100과 경로 240 bytes다. 구현 hard ceiling 안에서만 trusted
composition이 다른 예산을 선택할 수 있다. 제품 자원 읽기는 `ResourcePort`가 실제
principal/context 권한과 byte 예산을 검사하며, bundle의 권리 문자열은 권한을 부여하지
않는다. reference-only 또는 unknown-rights 자원을 embedding하지 않는다.

`CoordinateSystem`은 단위 scale이 없는 직교 basis와 handedness를 검증한다. 위치와
affine 변환을 한 정규화 경계에서만 변환하고, SI vector와 axial vector, normal과 winding의
규칙을 각각 적용한다. `PhysicsDefinition`은 모델링 재질의 출처, body/collider/joint와
qualified visual binding을 보존한다. 한 body가 여러 visual node를 구동할 수 있으며
동일 `(instanceId,nodeId)`에 여러 최종 writer를 지정하면 거절한다. 모델 값 검사는
원본 게임 물성 관측이나 solver 실행 성공을 의미하지 않는다.

`mmmm:canonical_selection_external_affine_v1` 중립 profile은 원본 스키마의 기존
payload 종류만 사용한다. Minecraft Y-up·block 선택은 `opaque_source`에 보존하고,
외부 작업용 선택은 `selection`, 두 값의 qualified stable ID 관계는 `source_map`에
둔다. 바뀐 node/port/override/placement의 실제 affine를 변환하고 prefab revision을
재계산한 다음 instance의 prefabRevision과 revision을 재계산한다. projectRevision은
원본 authoring base pin으로 유지한다. inspector는 보존 원본과 manifest 좌표에서 작업용
선택과 map을 독립적으로 다시 계산하여 대조한다. 권한과 world 범위는 원본 선택으로만
검사하며 외부 좌표의 placement를 권한 근거로 사용하지 않는다.

`exchange_prepare_with_canonical_bytes`는 호출자가 이미 소유한 원래 selection JSON
bytes를 받아 request DTO와 대조한 뒤 정확한 raw hash와 bytes를 보존한다. 기본 Value API는
DTO를 직렬화한 bytes를 보관하므로 이를 원래 사용자 파일의 raw bytes라고 표시하지 않는다.
참조 asset의 원래 ResourceRef와 raw bytes는 별도 자원 pin으로 유지한다. BlockGeometry의
정수 cell/bounds, display payload와 opaque extension의 intrinsic geometry는 원래 Minecraft
계약을 유지한다. 이를 임의의 meter·basis geometry로 재표시하지 않는다. 자동 bake의 외부
action은 이 중립 profile의 실제 geometry decode 경계를 지원하는 guarantee가 있어야 한다.
그 runtime profile과 독립 관측이 없으면 외부 geometry/bake 인수는 미완료다.

가져온 원본 BakeArtifact는 외부 좌표, tool 정보와 raw hash를 그대로 유지한다.
검증된 `IngestedBake`의 `canonical_clips`, `canonical_clip_resources`와
`normalization_digest`는 같은 공간 변환으로 만든 별도 Minecraft clip의 내용, CAS pin과
파생 digest를 제공한다. 공통 planner의 SceneSource는 이 sealed ingestion에서 변환 clip을
staging하고 digest를 계획에 고정하여 native projection에서 소비해야 한다. ScenePatch의
sourceArtifact/sourceMap은 원본 provenance를 가리키며 attach_clip은 변환 clip ID를 사용한다.
단순 raw artifact의 clip ID lookup으로 native 설치를 처리해서는 안 된다. 비균일 scale과
임의 basis가 만드는 shear는 matrix로 유지하며 linear_trs가 표현할 수 없으면 거절한다.
공간 변환으로 rational time, source FPS, loop, event나 sampling 계약을 변경하지 않는다.

물리 입력은 자체 declared coordinates를 가진다. 같으면 원본을 정확히 유지하고,
다르면 `mmmm:declared_physics_coordinate_variant_v1`로 원본 DTO와 변환 physics를
별도 보관하여 inspector가 재계산한다. COM·body/collider/visual affine과 primitive
geometry의 거리는 한 번만 변환한다. SI 중력·선속도는 기저만, 각속도는 det(R)·R을
적용하며 kg·m² 주관성, 질량, 재질 출처와 joint SI limits는 보존한다. box/capsule 축은
정확한 signed-axis permutation, sphere는 직교 basis를 지원한다. Mesh의 실제 변환,
joint의 basis 변경과 반사된 주관성 방향은 명시적인 codec이 없으므로 거절한다.
새 BakeRequest는 bundle 안의 변환 physics revision을 고정해야 한다.

`bake_ingest`는 artifact의 실제 bytes를 먼저 검사한다. 이후 정확한 source bundle,
request, physics, 시간, 표현과 output 예산을 대조한다. `BakeVerifierPort`에는 원래 작업의
완료 manifest와 독립 평가/codec 관측을 연결해야 한다. job accepted/부분 출력,
caller boolean, 같은 triangle 수나 주장한 topology digest로 완료를 대체할 수 없다.
part sample coverage는 clip/node별 실제 요청 시각 관측을 요구하고, surface는 실제
mesh hash·topology·vertex/triangle 수와 identity-map codec 관측을 요구한다.
연결된 독립 verifier가 없으면 자동 가져오기를 unavailable로 처리한다. 원본 false
verification flag나 estimate를 조용히 true 또는 measured로 변경하지 않는다.

수동 파일 교환은 Provider가 없어도 prepare/inspect와 typed `SceneEdit`의 순수 diff로
진행할 수 있다. 이름은 identity로 사용하지 않고, 미포함 transform/display는 유지하며
삭제는 명시적 delta만 허용한다. create/delete와 transform/display update의 결과 variant도 기존 domain의 prefab 의미 검사를
재사용한다. `scene_diff`는 검증된 `IngestedBake`, 정확한 base selection과 qualified
SourceMap을 받아 clip loss까지 `ScenePatch`에 보존한다. 내부 `DeltaPolicy`는 순수 제안의
허용 범위를 표현하며 게임 grant가 아니다. 원본 wire에 `allowedDeltas` 필드는 추가하지 않는다.

`bake_plan`과 `scene_plan`은 공통 `Application::plan_create`를 호출한다. 별도 dispatch,
apply 알고리즘이나 작업 원장을 만들지 않는다. bake는 외부 workspace 권한과 독립 artifact
readback을 가진 runtime-verified action을 고정하며, 기본 facade는 한 solver semantic action을
지원한다. 복수 기능은 호출할 정확한 action의 결합 지원을 입증하는 profile이 마련될 때
확장한다. scene-only action이나 Provider 이름으로 solver 능력을 판단하지 않는다.
외부 bake 승인과 이후 game install 승인은 서로 다른 계획의 권한으로 검사한다.
surface의 game 설치는 검증된 compiler/runtime profile이 없으면 미지원으로 반환한다.

추가 dependency는 ZIP envelope와 compression/CRC, portable Unicode 경로 검사의
infrastructure 용도로만 사용한다. wire/domain에 해당 라이브러리 타입을 노출하지 않는다.
API 선택은 [zip 6.0.0 source](https://docs.rs/crate/zip/6.0.0/source/Cargo.toml),
[flate2 releases](https://github.com/rust-lang/flate2-rs/releases)와
[Decompress 문서](https://docs.rs/flate2/1.1.10/flate2/struct.Decompress.html)를 확인했다.

원본 예제와 소규모 파생 fixture는 좌표/physics, ZIP의 실제 envelope 경계, hash/권리,
부분 완료, 포즈/위상, source revision, omission와 명시적 patch를 검사하도록 작성했다.
fixture observer는 component 검사만 위한 것이며 실제 solver, 게임 또는 배포 증거로 사용하지
않는다. 실제 컴파일·테스트와 플랫폼 결과는 저장소의 구현 착수 기록에 별도로 연결해야 한다.
