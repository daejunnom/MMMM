# 출처·변경 우선순위·확인 범위

기준일 2026-10-13. 이 문서의 concrete DTO·함수·기본값·출시 게이트는 MMMM 설계 결정이다. 외부 문서의 API 존재는 우리 제품이 실제 통합됐다는 증거가 아니다. 동적인 main/latest 문서는 출처일 뿐 dependency lock이 아니다.

## 요구와 이전 문서

- 최신 사용자 결정: 새 코어 Rust, MVP/v0 vendor 원래 언어 유지, v1 전 도메인 기능 전면 자체 Rust 인수, Rust upstream도 불일치 시 의존하지 않음.
- F01: `MMMM_IMPLEMENTATION_HANDOFF.ko.md` 0.1.0-draft.1. 공통 객체·Provider/Compatibility·실행 상태의 기준. 이전 TS 선택은 이 통합본으로 대체.
- F02: `MMMM_RUST_REFERENCE_EXCHANGE_REVIEW.ko.md`. Rust/Java 플랫폼 경계, Reference Catalog, 중립 모델링 계약. 이번 통합본이 이를 정본 계약에 반영.
- F03: `MMMM_BNMMVF_ARTICLE_REVIEW_ADDENDUM.ko.md`와 제공된 41248번 글 PDF. 최종 표면 베이크·메타데이터·시간·보간·손실·출력 완결성 요구의 근거. 원문 2쪽은 리깅/물리 결과를 Minecraft에서 재생하는 목적과 Blender4.4를 설명하고, 4~5쪽은 높은 엔티티 비용·보간 제한·미검증을 경고한다.
- F04: 사용자 제공 `mc2bl(1.2.0).py`, `bl2mc(1.4.1).py`. 읽기 전용 참고; 평가 mesh와 import 시 top-level effect 사례. 복사·수정판·번들하지 않는다. 실제 코드 분석에서 나온 경계조건을 합성 fixture의 요구사항으로만 사용한다.

이전 조사 보고서의 명령 수·맵 수치와 최신 API 버전을 이번 handoff에서 다시 측정한 것으로 표시하지 않는다. 네 맵 원본과 사용자의 카페 PDF를 공개 test input으로 복사하지 않는다.

## 외부 1차 자료

| ID | 출처 | 확인에 사용한 범위 |
|---|---|---|
| S01 | https://github.com/modelcontextprotocol/rust-sdk | 공식 Rust SDK, tools/resources·transport 기반 |
| S02 | https://raw.githubusercontent.com/modelcontextprotocol/rust-sdk/main/Cargo.toml | SDK 라이선스 Apache-2.0 표기; 실제 채택 버전은 구현 때 고정 |
| S03 | https://www.minecraft.net/ko-kr/article/minecraft-java-edition-26-3 | 공식 26.3 compute/context number provider와 저장·정수화 구분 |
| S04 | https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html | bounded CPU 작업과 시작된 blocking 작업의 취소 한계 |
| S05 | https://www.rfc-editor.org/rfc/rfc8785 | JSON Canonicalization Scheme |
| S06 | https://www.sqlite.org/transactional.html | SQLite transaction의 보장 범위 |
| S07 | https://www.sqlite.org/wal.html | WAL·동일 호스트/로컬 파일 요구·동기화/체크포인트 |
| S08 | https://modelcontextprotocol.io/specification/2026-07-28/server/tools | 도구 스키마·구조화 결과·annotation을 신뢰 보장과 구분 |
| S09 | https://docs.fabricmc.net/develop/data-generation/block-models | render model과 collision/shape의 별도 구현. 예시 버전의 API를 26.3 통합 검증으로 간주하지 않음 |
| S10 | https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html | node TRS·matrix·animation 제약; MMMM 전체 정본과 별개 |
| S11 | https://openusd.org/release/api/usd_physics_page_front.html | body/collider/joint·물리 단위 설계의 참고 |
| S12 | https://github.com/misode/mcmeta | 버전별 Minecraft 추출 정보. Mojang 공식 제품이나 사용자의 runtime truth가 아님 |
| S13 | https://docs.fabricmc.net/develop/networking | 논리 client/server와 실행 문맥 |
| S14 | https://modelcontextprotocol.io/specification/2026-07-28/server/resources | 자료 노출과 실제 모델 문맥 선택 구분 |
| S15 | https://opensource.org/license/gpl-3.0 | copy/adapt·수정 버전·output의 조건; 언어 변경이 원 조건을 자동 제거하지 않는다는 정책 근거 |
| S16 | https://opensource.org/license/mit ; https://www.apache.org/licenses/LICENSE-2.0 | MIT·Apache 재사용 시 고지·라이선스·NOTICE 등 |
| S17 | https://wiki.fabricmc.net/documentation:entrypoint | 사용자 정의 mod 간 integration 등록 지점 |
| S18 | https://docs.fabricmc.net/develop/commands/basics | Brigadier command tree·command source·권한 |

26.3 공식 자료는 별도 검색 경로로 확인했다. URI 접속 성공과 실제 게임 바이너리 실행을 구분한다. GNU 사이트 직접 조회가 timeout이어서 GPL 원문은 OSI의 동일 라이선스 본문을 확인했다. 법률상 독립 저작물 판단이나 모든 LGPL 연결의 허가를 이 설계만으로 확정하지 않는다. 실제 vendor artifact의 LICENSE·원본 파일별 고지·결합·생성 runtime을 따로 검토한다.

## 이번 패키지에서 수행한 것

기존 handoff와 두 검토서를 읽고 새 사용자 요구로 통합 작성했다. 새 스키마·예제·함수 인덱스·artifact hash·일부 의미 불변조건을 로컬 검사했다. 전체 JCS 준수, Rust/JVM 제품 컴파일, Minecraft/Blender/외부 mod 실행, vendor 채택·동작·성능 검증은 수행하지 않았다. 세부 결과는 `validation/REPORT.json`이다.
