# 동봉 파일 검사

실행 환경은 Python 3.10+와 jsonschema 4.x다. `python tests/check_spec.py --report validation/REPORT.json`으로 동봉 형식·예제·일부 의미 조건·자원 bytes hash·현재 예제 범위의 자기 digest·함수 입출력 연결·문서 파일 존재를 확인한다.

이 코드는 handoff 자체를 확인하는 보조 도구이며 MMMM의 실제 domain validator/런타임을 구현한 것이 아니다. 제품에서는 같은 기대 예제를 Rust xtask 및 실제 game/host fixture에 이식한다. 이 Python 도구를 v1 도메인 runtime 의존성으로 추가하지 않는다.

음수 사례는 스키마와 일부 예제 불변조건의 오류 검출만 확인한다. tests/ACCEPTANCE의 제품 시험을 통과했다는 의미가 아니다. canonicalization은 현재 예제에 있는 안전한 정수와 지수 표기가 없는 유한 소수·Unicode subset만 처리하고 그 밖은 거절한다. 생성 시 ECMAScript의 숫자/문자열 직렬화·키 정렬과 같은 결과임을 확인했지만, 이것은 일반 RFC8785 구현의 적합성 시험이 아니다. 제품에서는 고정 JCS 구현과 전체 RFC 벡터를 사용한다.

`examples/operation-report.json` 등의 성공/불명 상태는 합성 계약 예제다. provider/game/외부 도구가 실제로 실행되었다는 증거로 사용하지 않는다. 예제 plan의 timestamp는 고정 자료이므로 실제 apply에 재사용하지 않는다. 정책/제공자 권한을 예제 파일만으로 승인하지 않는다.

## SDK ActionDescriptor 공통 기준값

`jvm/provider-sdk/src/test/resources/action-descriptor-canonical.json`은 Java SDK와 Rust 계약
검사가 함께 읽는 자체 정적 기준값이다. 계약 정본 `0.2.0`의 `examples/provider-supported.json`
(`SHA-256 15cf78688e6a7c9446449ac54fa1598586759534f4470194224d10934dfefb93`)에서
`actions[0]`의 21개 필드를 수작업으로 전개했다. 원 예제와 schema는 변경하지 않는다.
기존 `tests/digest-fixtures.json`에는 이 descriptor 자체의 canonical 기대 바이트가 없어
원 예제의 단순 개별 검증만으로 두 구현이 같은 기준을 사용하는지 확인할 수 없다.

기준값은 UTF-8, BOM 및 끝 개행 없는 897 bytes이며 SHA-256은
`07db749c581337adde03fd0c112bc33a9ae49f8c8ac0dfda0771bb225513ea3a`다. `.gitattributes`에
정확한 파일을 `-text`로 등록해 bytes를 보존한다. 재생성 기준은 버전 `0.1.0`의
`mmmm-contracts::canonical_bytes` 구현(`crates/mmmm-contracts/src/digest.rs`, source SHA-256
`69fabe255373b9903aa1d8ead9796a466b293c12f64a485cd150571c44964e7c`)으로 위 예제의
`actions[0]` 전체를 정본 ActionDescriptor의 빈 제외 목록에 따라 JCS 직렬화하는 것이다.
입력·옵션·소유자는 각각 원 예제와 계약 0.2.0·전체 descriptor·SDK 계약 검사이며 추적 출력은
위 기준값 한 개다. 재생성 결과는 외부 소유 위치에서 원 source·schema digest와 두 구현의
실제 검사 결과를 확인한 뒤 비교한다. 이 기준값은 수작업 후보이며 Rust 생성기를 실제로
실행해 만들었다는 주장이나 양 언어 간 실시간 bytes 교환 증거가 아니다.

현재 Rust `JsonLimits`의 기본 tree 깊이 상한은 64이고 Java `ContractJson`의 tree 검사는
96이다. 이 공통 기준값은 두 한도 안의 작은 예제이며, 정본이 내부를 열어 둔 모든 nested
schema 입력에 대해 Rust와 Java가 같은 깊이까지 수용한다는 뜻은 아니다. 두 경계와 그
사이 입력의 실제 상호 운용성은 별도로 확인해야 한다.
