# MMMM 컴파일러

`math_compile`은 정본 `MathCompileRequest`를 검사하고 Java 26.3 native provider와
score/NBT를 사용하는 메모리 내 `CompileFragment` 초안을 만든다. `pack_build`는
이 컴파일러가 만든 함수 IR의 의존 관계, 생성 파일과 source map을 검사한 뒤
`ExportManifest`와 실제 bytes를 반환한다. CAS 등록과 private staging 파일 저장은
호출하는 application/runtime이 소유한다. 게임 실행, 팩 설치와 reload는 수행하지 않는다.

대상은 이름으로 활성화하지 않는다. `VerifiedTarget::verify`는 원본 profile의
정확한 버전, artifact와 profile digest를 확인하고, 인증된 registry의
`TargetEvidenceVerifier`가 실제 parse·수치 오류·readback 및 pack codec 증거를
검사해야 capability를 만든다. 원본 `reference_only` 예제는 거절한다. 테스트의
`AuthoredEvidence`는 순수 생성기 검사에만 사용하는 내부 fixture다.

`ResolvedSymbols`는 원본에 없는 wire schema를 추가하지 않는 내부 port다.
원본 resource bytes와 digest를 비교한 뒤 `SymbolTableVerifier`가 현재 읽기 권한,
bytes의 해석 및 typed binding을 검증한다. storage binding은 해당 invocation의
정확한 int/float NBT tag를 호스트가 게임 스레드에서 다시 확인해야 한다.
context origin은 같은 invocation에서 준비한 float NBT binding을 요구한다.
문서에서 발견하지 못한 origin numeric provider를 임의로 출력하지 않는다.

각 DAG node는 한 번 계산해 새 scratch 슬롯에 넣고 성공 score로 다음 계산을
제어한다. 누락 state는 기본 0으로 대체하지 않고 오류 fallback을 쓴다.
NaN/Infinity는 저장한 f32 결과에 `from_float(value * 0)` native 검사를 적용해
최종 출력을 차단한다. 정수 `div`는 overflow를 검사하는 `floor_div`를 먼저
평가한 뒤 truncating `div`를 사용한다. float NBT 저장과 `/compute float`의
정수 반환을 혼용하지 않고 score 출력의 floor/trunc를 명시한다. 원본 연산을
host f64 상수로 접지 않는다. 정확한 target에서 이 경로의 parse 및 상태
readback을 확인하기 전에는 MC01–03의 실제 인수 통과를 주장할 수 없다.

생성 source의 input pin은 strict JSON의 실제 숫자 표현을 hash한다. JCS에서
동일하게 식별하는 `+0.0`과 `-0.0`이 서로 다른 native literal bytes와 f32
의미를 가질 수 있으므로 이 생성물 identity를 semantic JCS pin과 혼용하지 않는다.
계약 자체의 canonical digest 규칙은 바꾸지 않는다.

단위 검사는 더하기와 비교의 동형 차원, 제한된 `*`·`/`·정수 지수의 symbolic
단위 곱과 나눗셈, 짝수 차원의 제곱근, radians 삼각함수와 명시적 float→int를
지원한다. `degrees`와 `radians`, `seconds`와 `ticks`는 별도 차원으로 유지하고
자동 변환하지 않는다. 미지원 단위 문법, float `floor_div`, 순서를 증명할 수
없는 clamp bounds는 거절한다. clamp는
`min(max(value, lower), upper)`로 낮춘다. 모든 생성 함수는 입력, 출력,
읽기/쓰기 state, 실행 context, 재진입 조건과 cleanup 계약을 추적한다.
공유 scratch는 직렬 invocation 및 명시적 lifecycle 소유권을 요구한다.

`scene_lower`는 canonical Project와 실제 소유 Prefab·Instance·CommandModule·Asset,
동일 revision의 resource bytes를 받는다. native codec이 명령을 생성하고 별도
registry verifier가 정확한 대상의 display payload, block state 회전, command parser,
media codec·권한 및 각 출력 명령을 검사한다. 정적 display의 world affine과
빈 text display의 배경 기하를 유지하며 command block은 비활성 배치·NBT 입력과
명시적 활성화를 분리한다. 생성 display에는 결정적인 UUID를 지정한다.
Live display UUID와 보존 상태의 native 주소는 authoring revision과 compiler 버전에서
분리해 안정적으로 유지한다. `SceneDraft::native_steps`는 stage·activate·cleanup별
객체·node·instance 출처, 실제 native instruction과 검증된 원래 명령을 함께 제공한다.
Matrix와 float 상태의 projection은 실제 f32 값이며 source f64 및 변환 손실과 구분한다.
Coordinator는 이 자료에서 승인된 before/after 차이와 실제 관측 대상 집합을 별도로
고정해야 한다. 전체 project export를 특정 clone·patch의 전체 월드 쓰기로 해석하지 않는다.

`animation_compile`은 exact rational time을 프로젝트 TPS의 tick으로 양자화하고
인스턴스·클립에 종속된 timer와 제어 함수를 만든다. parent-local 절대 pose를
동일 world frame으로 합성한다. step/baked matrix는 interpolation을 0으로 재설정하고,
linear TRS는 독립 verifier가 전체 구간의 성분·회전 오차를 증명한 경우만 낮춘다.
순서가 같은 시각의 event는 authored sequence를 유지하며 scrub은 event를 실행하지
않는다. event 함수는 정확한 bytes, 계약과 명시적 성공 반환을 별도로 증명해야 한다.
불확실하거나 실패한 event는 timer를 tainted 상태로 보존하고 재생·scrub·cleanup을
차단한다. 실제 게임에서의 MC04–09 인수는 별도 관측이 필요하다.

절대 elapsed tick을 받는 `catch_up`은 여러 loop를 건너뛸 수 있으며 승인된 tick·event
상한 안에서만 유한하게 실행한다. 이전 elapsed·iteration·cursor, score overflow와
최악의 event 수를 효과 전에 검사한다. step/baked loop의 양 끝 pose가 다르면 exact
target의 endpoint hold와 client update coalescing 증거를 요구하고, old endpoint 뒤
명시적 pose 0 reset과 새 iteration의 시작 event를 출력한다. 이 증거를 source
명령만으로 대신하지 않는다.

`PackBuildInputs::with_scene`와 반복 가능한 `with_animation`은 위 생성기가 만든
봉인된 초안만 받는다. 소유 객체의 종류·ID·revision 합집합, 인스턴스별 클립 배치,
prefab·parent·rest pose·world frame·display UUID·origin 및 프로젝트 TPS를 대조한다.
호출자가 제공한 coverage ID 목록만으로 미구현 객체를 누락할 수 없다. 생성 함수
호출 그래프와 immutable 외부 함수 bytes pin을 검사하고, wrapper에도 실제 callee의
state와 요구 조건을 기록한다. 함수 호출 깊이·확장 명령량, source map·계약 metadata와
파일 bytes를 복제 전에 합산 제한한다.

리소스팩 content가 있는 경우 출력은 `data-pack/`와 `resource-pack/` 루트를 사용하며
각각 정확한 target format의 `pack.mcmeta`를 갖는다. 외부 함수는 manifest와 별도
dependency pin 파일에 남긴다. 설치·reload와 런타임 검증을 수행했다고 보고하지
않으며 validation stage는 `statically_checked`다. 실제 profile 증거, 권한·원본 bytes,
codec이나 표현 변환의 증명이 없는 입력은 차단한다. 이 정적 생성 코드와 authored
fixture는 FN30 및 MC01–12의 실제 제품 인수, 공개 배포 증거를 대체하지 않는다.

native grammar와 수치 의미의 조사 근거는
[Java 26.3 공식 릴리스](https://www.minecraft.net/en-us/article/minecraft-java-edition-26-3)다.
조사 근거와 runtime 검증 capability는 서로 다른 자료다.
