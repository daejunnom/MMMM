# Public Java 호환 실행기

이 모듈은 Rust의 승인된 `CompatibilityProfile`과 실제 JVM 경계를 연결한다.
프로젝트 계획, policy, operation 원장과 객체 변환은 Rust가 소유한다.
공개 클래스나 메서드가 존재한다는 사실은 권한이나 안전성 승인이 아니다.

`ApprovedArtifact.open`은 승인된 루트의 정확한 regular JAR 하나만 유한하게 읽고
실제 bytes의 SHA-256을 계산한다. trusted source approval은 digest와 출처 및 권리 조건을
정책에서 확인한다. 선언 문자열이나 descriptor에 적힌 digest를 실제 관찰로 채택하지 않는다.
JAR은 32 MiB, 전체 해제는 64 MiB, entry는 512개, class는 256개이며 한 class는
2 MiB까지다. traversal, Unicode 및 대소문자 충돌과 multi-release 선택은 거절한다.

fixture/tool의 명시적 `fixtureLoader`는 스냅샷에서 보관한 bytes만 정의하고 platform
loader를 parent로 사용한다. SDK가 없는 자체 fixture도 이 loader에서 실제 호출할 수 있다.
이미 로드된 모드는 실제 `Class` 및 `ClassLoader` identity, `CodeSource`와 class resource
bytes를 확인한 후 플랫폼의 `LoadedClassApproval`을 추가로 요구한다. class resource만으로
instrumentation 뒤의 실제 정의 bytes를 증명하지 못한다. 플랫폼에서 변환 여부와 정의의
출처를 확인할 수 없는 loader는 승인하지 않는다. 이 모듈은 JVM 악성 코드 sandbox가 아니다.

`PublicJavaAdapter.detect`는 정본 schema, exact game/mod/loader/side, profile digest,
artifact digest와 승인 policy를 확인한다. `Class.forName(..., false, loader)`와 public lookup은
탐지 중 초기화를 강제하지 않는다. 승인한 클래스에 직접 선언된 정확한 signature 하나만
선택한다. overload 이름 추정, private lookup, field 접근, constructor 호출과 임의 POJO
생성은 없다. 실제 invocation에서 일어나는 초기화와 쓰기는 호출 효과에 속한다.

`Candidate`가 반환하는 action descriptor, profile digest, artifact/class digest와
`observedSupport`는 등록 후보다. trusted host는 provider provenance와 매 action의 실제
descriptor digest를 승인한 후 `Candidate.register(Registrar)`를 호출한다. 후보 자체가
자신의 신뢰나 readiness를 높이지 않는다. 실제 호출 앞에서도 source policy를 다시 확인한다.

값은 string, bool, int32, finite float/double, JSON list/map와 host가 등록한 scoped handle만
지원한다. argument는 32개, JSON은 256 KiB, 깊이는 16, node는 4096개까지다. 순환, POJO,
큰 정수와 비유한 값은 거절한다. `scalar`와 list 결과는 `data.value`, map 결과는 `data`
object, registered handle 결과는 `data.handle`과 `data.handleType`으로 표현하며 승인된
output schema를 검증한다. 이 닫힌 codec 선택은 별도 output mapping 언어를 만들지 않는다.

등록 receiver는 trusted host의 exact `Class` 및 source 승인을 거친 정책에서 가져온다.
receiver handle을 읽을 JSON Pointer는 private reviewed registration에 고정하고 wire에
새 필드를 추가하지 않는다. 실제 `LocalContext.resolveHandle`은 binding, epoch, principal과
type을 검사한다. 승인된 public factory는 별도 action으로만 호출할 수 있으며, factory
반환을 위한 registered handle codec은 같은 guarded queue 안에서만 handle을 발급한다.

호스트 큐와 `beginMutation`을 거친 뒤 API를 호출한다. read는 `effects=none`, write 또는
unknown은 반환이나 예외 이후에도 `effects=unknown`을 유지한다. Java의 정상 반환은
독립 readback이나 rollback 완료를 뜻하지 않는다. 실제 native effect 관찰은 호스트와
Coordinator의 별도 검증 책임이다.

`CompletionStage`는 block하지 않는다. 최초 original Invocation만 API를 호출하고 최대
64개의 scoped job을 한 candidate generation의 수명 동안 보관한다. 완료 결과도 원본
invocation의 중복 실행 방지를 위해 보존하며 한도에 도달하면 명시적인 `JOB_LIMIT`으로
거절한다. 동시 실행 64개만의 한도라고 표현하지 않는다. binding, invocation, operation/step, action/implementation/
arguments/context digest와 principal/epoch를 고정한다. 중복 요청은 같은 job으로 돌아가며
poll은 새 호출을 만들지 않는다. 완료 값과 예외는 bounded `ProviderResult`로 보존한다.
기능별 prepare/cancel/recover를 추정하지 않는다. 기본값은 미지원이고, 명시적으로 승인한
mapping-only prepare는 API를 호출하지 않은 opaque 계획 정보만 반환한다. synchronous read
콜백은 실제 동일 signature를 읽기 권한 문맥에서 호출한다.

호스트의 poll 경계는 원래 `invocationId`로 immutable Running을 조회하고 그 작업의
previous job handle만 콜백에 전달한다. public caller가 다른 job token을 넣는 통로는 없다.
candidate 종료는 foreign 작업의 중지나 rollback 완료를 주장하지 않으며 Rust의 durable
operation에 보존된 불확실성을 대신하지 않는다. 완료 및 미완료 자료를 일반 캐시처럼
지우지 않는 호스트 generation 보존과 교체 정책이 필요하다.

Fabric의 실제 transformer/class definition 증거 수집과 Rust의 승인된 profile/source
resolver 연결은 별도 호스트 구성 작업이다. strict bootstrap config 또는 profile 자신의
필드를 authority로 바꾸지 않는다. `LoadedClassApproval`에 실제 증거가 없으면 사용을
거절한다. 독립 fixture 호출과 production HostRuntime 등록 시험은 이 연결의 게임 인수를
대체하지 않는다.

자체 fixture `LegacyApi`와 `ReceiverApi`는 SDK import가 없으며 MIT 자체 코드다.
원본 JSON 예제로는 실제 class 초기화, public lookup, concrete invocation, scoped receiver,
비동기 작업과 class loader 경계를 검사할 수 없어 이 작은 소스 fixture를 추가했다.
현재 모듈의 소스와 검사는 작성 상태이며, 실제 Gradle compile/test와 게임 인수는 루트의
관리 빌드 및 인수 기록에서 별도로 확인한다.
