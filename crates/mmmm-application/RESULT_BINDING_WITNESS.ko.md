# 단계 결과 해석의 내부 증거

이 문서는 원본 `StepResultBinding`과 `Invocation`을 바꾸지 않고 EX11·EX12를
구현하기 위한 application/runtime의 private 저장 계약을 정한다. 원본 wire에
새 권한 필드를 추가하지 않는다. 공개 요청이나 CAS digest 지식은 registry 등록,
읽기 권한 또는 dispatch 권한이 아니다.

`outputPointer`의 root는 계약을 검증한 `ProviderResult.data`다.
`expectedSchemaDigest`는 해당 원본 source action의 전체 `outputSchema`를 JCS로
hash한 값이다. fragment schema hash로 해석하지 않는다. 이 선택은 원본의
명시되지 않은 pointer/schema 조합을 처리하는 구현 결정이다.

Runtime은 인증된 server composition만 호출하는 두 등록 API를 제공한다.
공개 RPC나 facade JSON에 등록 경로를 노출하지 않는다.

- `register_result_action(bindingId, ActionDescriptor)`는 실제 immutable registry에서
  읽은 descriptor를 검증하고 전체 action digest, implementation digest와 출력
  schema를 보관한다. Application은 기존의 live descriptor 검사 경로에서 등록한다.
  원본 source Invocation의 binding/action/actionDigest/implementationDigest가 이
  서버 등록과 원래 frozen source step에 일치해야 한다. witness가 제출한 schema
  blob만으로 등록을 대체하지 않는다.
- `register_result_codec(RegisteredResultCodec)`은 봉인된 Rust 구현 `JsonIdentityV1`,
  input/output schemas와 허용된 exact `(actionDigest, argumentPointer)` 슬롯을
  등록한다. digest는 정확한 metadata의 JCS hash다. 이미 등록된 ID/digest는
  내용이 다르면 갱신하지 않는다. 초기 codec은 선택한 JSON 값을 그대로 옮기는
  순수 변환이며 파일, 네트워크, 호스트 호출이나 임의 코드를 실행하지 않는다.

허용 슬롯은 기존 consumer arguments에 실제로 존재하는 데이터 슬롯이다.
권한, context, endpoint, binding, action, 최종 대상, scope, command, executor,
runtime 설정이나 비용 예산을 선택하는 슬롯은 등록과 dispatch 양쪽에서 거부한다.
한 binding의 슬롯이 다른 binding 슬롯의 부모이거나 같은 경로이면 거부한다.
문자열 prefix가 아닌 RFC 6901 토큰과 배열 index 규칙으로 pointer를 검사한다.
Compatibility의 argument mapping이나 result codec 이름은 이 등록을 대신하지 않는다.

각 dispatch의 private CAS witness는 다음 형태를 사용한다. `BlobRef`는 기존
runtime의 실제 digest/byteLength 참조이며, 모든 참조는 같은 operation에 pin된다.

```text
kind: result_resolution_witness
version: 1
operationId, planHash, stepId
templateArgumentsDigest
argumentsBlob, argumentsDigest
contextDigest, actionDigest, implementationDigest
resolvedFootprint: { resourcesRead, resourcesWritten }
bindings: [
  {
    binding: 원본 StepResultBinding의 6개 필드,
    sourceInvocationId,
    sourceInvocationDigest,
    sourceResult: BlobRef,
    sourceResultSummary: BlobRef,
    sourceAction: 서버 등록된 descriptor BlobRef,
    codec: 서버 등록된 metadata BlobRef,
    selectedValueDigest,
    resolvedValueDigest
  }
]
```

sourceResultSummary는 기존 작은 `provider_result` marker다. marker에는
`invocationId`, `stepId`, `actionDigest`, `outputSchemaDigest`, `resultBlob`,
`outputValidated`, 검증된 provider 상태와 `sourceRefs`가 있다. Runtime은 이
marker와 sourceResult가 원래 operation의 `application_summary` source association에
실제로 연결돼 있는지 확인한다. marker의 JSON 주장만 확인하고 넘어가지 않는다.
typed marker 이전에 저장하는 `unvalidated_provider_result`는 엄격한 원본 envelope
검사로 얻은 `envelopeValidated`와 `envelopeStatus`, 작은 `envelopeSummary`를
보존한다. 이 summary의 `outputValidated`는 false이며 성공 권한이 아니다.
중단 구간에 남은 정본 failed 원문은 이후 complete marker가 있어도 실패 이력으로
남는다. Runtime은 metadata 주장 대신 실제 retained 원문과 source association을
독립 확인한다. metadata가 없는 legacy 원문은 application에서 처음 읽는 경로부터
32MiB 누적 예산을 적용하며, 미검사 이력은 원 refs를 보존한 채 후속 dispatch를
차단한다.

원본 source step은 consumer의 frozen DAG ancestor여야 하며 실제 durable step이
완료·검증돼 있고 provider failure가 없어야 한다. source Invocation bytes/digest와
등록된 descriptor를 원본 계획에 대조한다. 원본 ProviderResult의 계약, complete
상태, data의 등록된 output schema를 다시 검증한다. 선택한 값과 codec input/output
schemas도 검사한다. `JsonIdentityV1`에서는 선택값과 resolved 값이 정확히 같다.

Application은 resolved arguments 전체를 consumer의 pinned input schema와 실제
frozen footprint에 대조한다. Runtime도 원본 template의 허용 슬롯만 바뀌었음을
독립적으로 재구성하고 확인한다. scope나 target이 늘면 재계획이 필요하다.

`dispatch_intent`는 resultBindings가 없는 기존 경로를 그대로 검증한다.
`dispatch_resolved_intent(operation, step, Invocation, witness)`는 이 검증을 통과한
동일 intent transaction에서 Invocation, witness와 그 참조를 pin하고 기존 fence와
event를 commit한다. 별도 원장이나 취소 권위를 만들지 않는다. transaction을
commit한 다음에만 provider를 호출한다. 소비자 invocation의 실제 arguments hash를
저장하며, placeholder arguments를 dispatch하지 않는다. 재시작 후 witness와 원본
source/codec/args가 원래 operation·invocation으로 조회돼야 한다.

codec 등록이나 source 증거가 없고, schema·digest·DAG·슬롯·footprint·권한 검사 중
하나라도 실패하면 새 consumer dispatch를 차단한다. 이미 일어난 source 효과는
그대로 보고한다. 조회와 재조정은 미실행 consumer를 자동 실행하지 않는다.

검사는 실제 임시 SQLite/CAS와 stateful fixture에서 성공한 producer→consumer,
미완료·실패 source, schema/codec 불일치, 허용되지 않은 또는 겹치는 pointer,
target/scope 확대, witness/source association 위조 및 재시작 보존을 확인한다.
이 결과는 실제 게임이나 외부 bake 도구의 인수 근거가 아니다.
