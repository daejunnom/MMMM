# 동봉 파일 검사

실행 환경은 Python 3.10+와 jsonschema 4.x다. `python tests/check_spec.py --report validation/REPORT.json`으로 동봉 형식·예제·일부 의미 조건·자원 bytes hash·현재 예제 범위의 자기 digest·함수 입출력 연결·문서 파일 존재를 확인한다.

이 코드는 handoff 자체를 확인하는 보조 도구이며 MMMM의 실제 domain validator/런타임을 구현한 것이 아니다. 제품에서는 같은 기대 예제를 Rust xtask 및 실제 game/host fixture에 이식한다. 이 Python 도구를 v1 도메인 runtime 의존성으로 추가하지 않는다.

음수 사례는 스키마와 일부 예제 불변조건의 오류 검출만 확인한다. tests/ACCEPTANCE의 제품 시험을 통과했다는 의미가 아니다. canonicalization은 현재 예제에 있는 안전한 정수와 지수 표기가 없는 유한 소수·Unicode subset만 처리하고 그 밖은 거절한다. 생성 시 ECMAScript의 숫자/문자열 직렬화·키 정렬과 같은 결과임을 확인했지만, 이것은 일반 RFC8785 구현의 적합성 시험이 아니다. 제품에서는 고정 JCS 구현과 전체 RFC 벡터를 사용한다.

`examples/operation-report.json` 등의 성공/불명 상태는 합성 계약 예제다. provider/game/외부 도구가 실제로 실행되었다는 증거로 사용하지 않는다. 예제 plan의 timestamp는 고정 자료이므로 실제 apply에 재사용하지 않는다. 정책/제공자 권한을 예제 파일만으로 승인하지 않는다.
