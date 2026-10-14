# 게임 정의 관측 경계

이 디렉터리는 실제 JNI 정의 호출, 반환된 `Class` 동일성과 JVMTI 실행
snapshot을 연결하는 신규 소스다. Cargo workspace와 crate manifest,
Gradle의 Java 모듈로 등록했으며 실제 빌드 및 검사를 진행 중이다.
제품의 증거 issuer와 게임 시작 도구 연결은 미완료다. 대응하는 Java 경계는
`jvm/definition-observer/src/`에 있다. 소스 작성과 정적 검토는 실제 native
실행, 게임 target profile 검증이나 공개 배포를 뜻하지 않는다.

## 관측과 권한

`Agent_OnLoad`가 JDK 25의 실제 JVMTI interface와 capabilities를 확인하고
유한한 callback을 설치한다. `Agent_OnAttach`는 거절한다. 상태 값은 설치와
실제 native binding의 관측 결과이며, 승인이나 쓰기 권한을 발급하지 않는다.
Java는 실제 `Class<?>`를 JNI로 전달한다. native 소유자가 보관한 강참조와
`IsSameObject`로 비교한 대상만 조회하며, 이름·경로·SHA·JSON으로 관측을
등록하는 경로는 없다.

일반 클래스는 selected `ClassLoader.defineClass1` 호출의 native 시도와 실제
반환된 `Class`, ClassFileLoadHook, ClassPrepare를 연결한다. hook의 입력을
최종 정의 바이트로 채택하려면 별도의 신뢰된 시작 경계가 정확한 agent
순서와 이후 변환 부재를 입증해야 한다. callback 설치만으로 최종성을
선언하지 않는다. JVMTI의 hook 순서와 실제 재정의 이벤트는 현재 상태를
검사하는 데 사용한다. [ClassFileLoadHook 공식 명세](https://docs.oracle.com/en/java/javase/25/docs/specs/jvmti.html#ClassFileLoadHook)

숨김 클래스는 일반 hook 입력을 갖는다고 가정하지 않는다. selected
`ClassLoader.defineClass0`의 입력 recipe, 실제 반환된 `Class`, 준비된 클래스의
constant pool과 bytecode를 각각 보존한다. 이를 `loaded_definition_bytes`로
부르거나 완전한 classfile을 재구성했다고 표시하지 않는다. 실행 snapshot과
원본 recipe의 의미 비교는 별도의 좁은 parser가 담당한다.
[OpenJDK 25 숨김 클래스 정의 경계](https://github.com/openjdk/jdk/blob/jdk-25-ga/src/hotspot/share/classfile/klassFactory.cpp),
[GetConstantPool 공식 명세](https://docs.oracle.com/en/java/javase/25/docs/specs/jvmti.html#GetConstantPool)

## 입력 복사와 범위

선택한 byte-array 정의만 상한 안의 `off/len` 구간을 한 번 private array로
복사한다. 원래 native 함수는 같은 byte 내용과 길이, offset 0, 기존의 모든
loader/name/lookup/flags/classData/ProtectionDomain/initialize 인자를 받아
한 번 호출된다. 이 동작은 controlled recipe interposition이다. 내용을
바꾸는 transformer나 수동 관측으로 표시하지 않는다. JNI 예외가 발생하면
그 예외를 보존하고 원래 함수를 추가로 호출하지 않는다. 관측 상한이나
지원하지 않는 조건 때문에 증거를 만들 수 없는 경우, 예외가 없다면 원래
호출을 한 번 전달하고 증거는 발급하지 않는다.

`defineClass2`의 direct ByteBuffer 경로와 선택하지 않은 정의는 원래 호출을
전달하며 증거를 발급하지 않는다. 숨김 클래스의 null/empty name, non-null
classData와 지원하지 않는 recipe도 증거 대상으로 채택하지 않는다. heap,
전체 클래스, 파일 시스템이나 JAR를 훑어서 부족한 정의를 보충하지 않는다.

선택 범위는 Brigadier, 게임의 commands/server commands/scores/NBT/storage/
saved-data 패키지와 MMMM observer/Fabric 경계다. 한 클래스는 최대 8 MiB,
보존한 관측 payload 합계는 64 MiB, 클래스와 메서드는 각각 최대 4096개, 중첩 정의는
64단계로 제한한다. 상한 초과, 모호한 시도, 실패한 JNI 반환, 재정의와
불완전한 callback 연결은 성공 증거로 바꾸지 않는다.

native 작업은 metadata 2 MiB, snapshot 18 MiB, 선택 정의 26 MiB의 논리
payload 예약을 같은 64 MiB 예산 안에서 확인하고, 실제 보존량으로 비용을
옮긴다. Vec capacity가 길이보다 클 수 있고 JVMTI가 반환 길이를 알리기
전에 VM 내부 버퍼를 할당할 수 있으므로, 이 숫자를 Rust heap이나 JVM
전체의 엄격한 메모리 상한으로 보고하지 않는다. 상한을 넘은 반환 버퍼는
즉시 Deallocate하고 증거를 거절한다. VMDeath에서 활성 native 작업이 남아
있다면 참조를 성급하게 해제하지 않고 VM 파괴까지 유지한다. 모든 종료
경로가 즉시 모든 강참조를 해제한다고 보고하지 않는다.

현재 FFI는 little-endian Windows x64 MSVC, Linux x64 GNU와 macOS ARM64
Darwin의 지정한 JDK 25 ABI 구성을 선택한다. Cargo build target 이름과 각
ABI layout 조건을 함께 검사한다. 다른 이름·musl·arm64e·32비트와 big-endian은
거절한다. build script의 TARGET 이름만으로 같은 이름의 custom JSON target을
배제하지 못하므로 소유 빌드와 CI가 정확한 builtin triple을 명시적으로 선택하고
그 실행·compiler·source 근거를 보존해야 한다. 단일 JVMTI 버전 번호 또는 이
구성 검사는 VM vendor/build, JDK source pin이나 closed agent roster를 증명하지 않는다.
현재 실제 native startup 성공은 Windows의 고정 입력 실행뿐이며, Linux·macOS의
C header ABI witness·native startup 및 관리 런처 연결은 미완료다.

## Java 시작 경계

Java premain은 자체 JAR를 bootstrap search에 추가하고, 실제 native 상태와
자체 fixture 세 개를 확인한다. 일반 정의와 숨김 정의는 서로 다른 실제
`Class`·native identity에 결합되어야 한다. 별도의 64 KiB 이하 direct buffer
fixture는 defineClass2 binding만 확인하며 관측 증거가 없어야 한다. fixture는
게임 클래스 초기화, 게임 상태 변경, 스레드, 외부 파일 쓰기를 수행하지
않는다. 실패는 원인을 보존한 premain 실패로 처리한다.

wire 내부 버퍼는 `MMMMDEF1` magic을 갖는 유한한 binary envelope다. JNI
메타데이터는 Modified UTF-8로 해석하며 원래 envelope를 그대로 보존한다.
CP와 bytecode, hidden recipe와 일반 terminal bytes는 별도 필드다. Java
getter는 복사본을 반환한다. 이 envelope는 기존 공개 `0.2.0` 계약의 새
권한 DTO가 아니며, 현재 native target receipt codec을 바꾸지 않는다.

선택적 `observeHiddenForwarder(actualClass)`는 native registry가 보관한
현재 hidden recipe와 VM snapshot을 빌려 좁은 의미 비교를 수행한다.
일치하면 같은 loader에서 이미 관측된 실제 static declaring Class와
`jmethodID`를 연결하고 현재 generation·epoch·ClassStatus를 재검사한다.
반환하는 `MMMMSAM1`은 raw source identity, target identity와 generation,
실제 ClassStatus, 일곱 symbolic 문자열과 reference 목록을 담는 기술용
프레임이다. native 주소는 내보내지 않는다. unsupported recipe, 미관측
target과 stale identity는 empty이며 기존 raw 관측을 없애지 않는다.
실제 JNI/JVMTI 실패와 pending exception은 별도 오류로 보존한다. 이 조회는
실제 SAM dispatch, 전체 reference linkage·접근·초기화 정책이나 closed
source pipeline을 승인하지 않는다.

## 활성화 전 확인

독립 FFI 검토는 함수와 callback 위치, Windows capabilities bit-field 배치,
Agent_OnLoad 단계 제한, JNI 예외·local/global reference 수명, reentrance와
동시 종료를 확인해야 한다. JNI/JVMTI/Java 호출 중 Rust mutex를 보유하지
않는지 확인하고, 실제 반환된 Class의 동일성·현재 generation·재정의
tombstone으로 과거 토큰을 폐기해야 한다. 실제 플랫폼 fixture 실행과 managed
검사는 이 정적 검토와 별도로 수행한다.

제품 연결에는 신뢰된 시작 소유자가 고정한 실제 JVM executable과 source,
agent 아티팩트, closed roster·순서·native access·disabled attach 설정이
필요하다. Class Data Sharing의 복원은 이 정의 호출을 거치지 않을 수
있으므로, 현재 관측 경로를 적용할 시작 recipe는 실제로 CDS를 비활성화해야
한다. 보관된 recipe나 미관측 archive에서 정의를 추정하지 않는다.
[OpenJDK 25 lambda 생성과 CDS 분기](https://github.com/openjdk/jdk/blob/jdk-25-ga/src/java.base/share/classes/java/lang/invoke/InnerClassLambdaMetafactory.java)

실제 parser/predicate/handler의 전체 실행 closure, ordinary
declaring Class와 `jmethodID`, 좁은 hidden SAM의 실제 interface 선택을
검증해야 한다. CP의 symbolic 이름은 로드된 Class 동일성을 대신하지 않는다.
수동으로 제출한 `Class`, recipe 또는 digest도 승인 root를 만들지 않는다.

CalibrationRun은 기존 Application 계획·승인·원장의 원본 Invocation에
결합해야 한다. 봉인된 47개 compiler program을 실제로 로드한 owned pack의
함수로 실행하고, native function trace에서 순서와 선택 명령의 반환을
확인한 뒤 독립 readback의 실제 raw digest를 연결해야 한다. inline 명령
목록을 실행한 뒤 원래 `function ...`이 실행됐다고 receipt를 발급할 수 없다.
이 관측 crate 자체는 calibration 승인, dispatch, readback나 영구 원장을
추가하지 않는다.

## 등록 준비와 실제 검사

`Cargo.toml`은 기존 workspace의 package metadata와 lints를 사용하고
`cdylib`과 `rlib`, library test를 구성한다. 이 관측기는 표준 라이브러리만
사용하며 외부 dependency를 추가하지 않는다. 작은 std-only build script는 실제
Cargo target 이름을 닫힌 compile 설정으로 전달하며 생성 header나 source를 만들지 않는다.
`jvm/definition-observer/build.gradle`은 실제 `DefinitionObserverAgent`를
`Premain-Class`로 지정한다. redefine, retransform과 native-method-prefix
capability manifest는 false다. `Main-Class`, attach용 `Agent-Class`나
`Boot-Class-Path`를 선언하지 않는다. Java agent가 자신의 JAR를 직접
bootstrap search에 추가한다. fixture owner와 bridge, 고정 main은 실제
bootstrap loader에서 로드하고 같은 runtime package에서 one-time snapshot을
공유한다. system-loaded premain의 nested class나 static snapshot을 다른
loader의 main에서 조회하지 않는다.

Cargo workspace의 `crates/mmmm-game-observer`와 JVM settings의
`definition-observer`는 등록됐다. 등록과 lock 갱신은 실제 관리 검사의
성공과 별개다. 현재 source의 변경 입력과 각 실행의 source 입력을 비교해
결과를 재사용해야 한다.

등록 후 실제 관리 검사 대상은 정확한 내장 target을 지정한
`cargo test --locked -p mmmm-game-observer --lib --target <target>`의 48개
테스트와 같은 target의 `cargo clippy --locked -p mmmm-game-observer
--all-targets --target <target> -- -D warnings`, native library build다.
Windows `x86_64-pc-windows-msvc`에서 48개와 strict Clippy 및 library build의
성공을 확인했다. Linux·macOS의 새 ABI 선택 코드 실행은 별도다. Java는 기존 외부 출력
경로와 Java 25 toolchain, `-Xlint:all -Werror`, 기존 JUnit platform을 그대로
사용해 `:definition-observer:test`의 22개 작성된 테스트와
`:definition-observer:jar`를 실행한다. 실행·skip·cache hit와 XML의 실제
testcase 수를 구분한다. 선택적 query, bootstrap publisher와 semantic fixture의
실제 startup 결과는 아래 고정 입력 실행에 연결하며, pure codec 성공으로 대신하지 않는다.

## 제어된 시작 검사와 증거 생산 연결안

다음 연결안 중 Java fixture publisher와 선택적 native query는 소스로
작성됐다. 관리 launcher, 실제 fixture 실행, 게임 source admission과
CalibrationRun 연결은 각각 별도 단계다. G0부터 G4는 저장소 전체의 기존 게이트를
뜻하며, 아래 관측기 검사로 그 게이트를 다시 정의하거나 완료 처리하지 않는다.

1. 시작용 Rust 경계는 기존 관리 실행의 Windows Job, native process identity,
   시간·출력·disk 제한과 drain을 사용한다. 새 별도 원장이나 shell-built
   command를 만들지 않는다. 검사 입력은 소유 lease 안의 실제 Java executable,
   JDK 입력과 source pin, observer DLL·agent JAR 및 실제 build source manifest다.
   같은 물리 파일을 유한하게 열어 digest와 크기, link·경로 경계를 검사하며
   외부에서 보낸 성공 record를 실행 근거로 채택하지 않는다.
2. 고정 argv에는 `--disable-@files`, `-Xshare:off`, `-XX:+DisableAttachMechanism`,
   `-XX:-EnableDynamicAgentLoading`, `--enable-native-access=ALL-UNNAMED`,
   `--illegal-native-access=deny`, 실제 native 소스가 요구하는 하나의 정확한
   `-agentpath:<owned DLL>=jdk25-windows-x64-msvc-controlled-startup-v1`와
   하나의 정확한 `-javaagent:<owned JAR>=protocol=mmmm.definition-observer/1`만
   포함한다. DLL 경로·로드 순서·JDK build를 실제 시작 recipe에 고정한다.
   기존 관리 supervisor는 부모 환경을 이어받으므로 이 경계는
   `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`,
   `JDK_AOT_VM_OPTIONS`를 원래 값의
   조회·출력 없이 빈 값으로 덮어쓴다. 실제 VM의 input arguments도 고정된
   roster와 비교해야 한다. Java executable만의 hash나 이 arguments 조회는
   runtime image의 내장 VM options, 실제 JPLIS/JVMTI 환경과 모든 transformer를
   열거한 증거가 아니다. 입증된 전체 runtime image·native dependency·source
   pin과 정확한 instrumentation 구현·callback 순서의 별도 승인이 필요하다.
   JAR manifest의 `Class-Path`, `Boot-Class-Path`, `Launcher-Agent-Class`와
   추가 agent·wildcard·argfile을 허용하지 않는다. 입력 환경 전체나 개인 경로를 공개 evidence에
   내보내지 않는다.
   [JDK 25 java 옵션 명세](https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html),
   [VM 환경 및 runtime-image 옵션 구현](https://github.com/openjdk/jdk/blob/jdk-25-ga/src/hotspot/share/runtime/arguments.cpp)
3. `DefinitionStartupProbe`에는 main이 없으므로 이를 main으로 실행하거나
   `java -version` 종료를 fixture 성공으로 채택하지 않는다. bootstrap에서
   로드되는 `DefinitionStartupFixtures`가 no-args `runOnce`로 소유 fixture
   세 개를 실제 만들고 actual ordinary·hidden Class와 direct-buffer negative
   query를 immutable startup 관측으로 보존한다. premain은 append 뒤 그 실제
   실행만 호출한다. 고정 `DefinitionStartupEvidenceMain`은 같은 bootstrap
   runtime package의 package-private one-time getter로 그 관측만 조회한다.
   system-loaded premain의 static state를 bootstrap main이 다른 Class identity로
   조회하는 구조를 만들지 않는다. main은
   caller bytes나 digest를 받지 않고 각 현재 Class를 다시 native로 조회해
   issuer epoch·identity·generation과 원래 관측을 비교한다. 게임 클래스,
   arbitrary reflection, native 성공 대체값과 generic agent dispatch는 없다.
   긍정 semantic fixture는 이미 관측한 같은 ordinary Class의 고정 public
   `ownedRunnable` factory만 호출한다. 이 호출은 소유 probe를 초기화하고
   외부 효과가 없는 noncapturing Runnable을 만든다. `Runnable.run`은 호출하지
   않는다. 실제 hidden Class의 원본 recipe·VM snapshot에서 찾은 static target은
   같은 ordinary identity·generation과 실제 JVMTI 초기화 상태에 결합한다.
   symbolic Runnable 이름과 이 fixture의 초기화 관측은 게임 SAM closure나
   초기화 정책을 승인하지 않는다.
4. 그 main의 출력은 `MMMMABI2` magic을 가진 최대 18 MiB의 버전 고정 binary
   startup frame로 제한한다. 원래 `MMMMABI1` frame을 한 필드로 그대로
   보존하며, 이 raw frame은 actual status, ordinary·SAM 없는 hidden의 원래
   `MMMMDEF1` envelope 두 개와 실제 direct-buffer 관측 부재를 포함한다.
   별도 필드는 긍정 hidden의 원래 `MMMMDEF1`과 기술용 `MMMMSAM1`이다.
   각 envelope의 원본을 caller bytes로 대체하지 않는다. 요청 nonce가 있더라도 pairing 식별자로
   사용하며 source proof로 채택하지 않는다. Java 예외나 malformed envelope는
   실패를 보존한다. Rust는 실제 소유 child의 완전한 stdout에서만 frame을
   읽고 원래 envelope들을 외부 evidence 또는 기존 CAS에 보존한다. 실제 child
   종료 0, 완전한 frame, closed startup 입력 검사, 최신 정의 identity 및 drain을
   함께 확인해야 fixture 성공이다. 60초 timeout, 64 MiB 전체 출력, Windows
   기존 2 GiB Job/32 process 상한을 유지하며 실패 후 자동 재시도하지 않는다.
5. 실제 게임 admission은 startup fixture와 분리한다. 기존 paired host가
   parser·predicate·handler actual Class를 같은 native issuer epoch로 조회하고
   필요한 ordinary 정의와 좁은 hidden forwarder snapshot을 검증한다. hidden
   SAM의 실제 interface와 declaring method, 전체 referenced Class closure와
   초기화 정책도 같은 Class·loader·generation에 결합해야 한다. 현재
   `loaded_definition_bytes` receipt에 숨김 recipe SHA를 넣지 않는다. 새
   `loaded_executable_snapshot` proof kind의 private codec와 원본 envelope 보존,
   독립 Rust verifier 및 current ACL/context 재검사를 함께 검토한 뒤 연결한다.
6. CalibrationRun producer는 기존 common setup plan의 48개 owned source와
   실제 native loaded function mapping을 사용한다. fresh manual 승인·scratch
   전체 scope·현재 policy를 확인한 같은 Application 경로가 원본 Invocation을
   내구 저장한 뒤, 실제 `function ...`을 dispatch한다. native trace가 47개
   프로그램의 원래 함수 entry와 line 순서, 선택 명령의 반환, preseed 경계를
   관측하며 독립 readback raw receipt를 별도로 연결한다. 기존 immutable issuer는
   실제 context와 저장된 Invocation ID로만 조회한다. 명령을 inline으로 펼치고
   loaded function이 실행됐다고 발급하거나 요청 hash를 새 증거로 계산하지 않는다.
   setup/cleanup 실패와 불명 쓰기, scratch 충돌·재승인·복구는 같은 journal과
   기존 recovery 경로에 남긴다.

현재 개발용 Windows x64 실행에서는 고정 JDK `25.0.4.1+1`과 선택한 observer
DLL·JAR를 같은 실행 전후 digest에 묶고 actual JNI/JVMTI startup을 확인했다.
ordinary·SAM 없는 hidden 정의·좁은 hidden forwarder의 단일 ABI2 프레임
5,886 bytes를 엄격하게 검증했다. 첫 성공의 raw SHA-256은
`4e43bb003805482f138083fae1cec959d8ef1d22d2e35a2cad43ce8dad2c04dc`다.
세 target의 ABI 선택 코드를 추가하고 정확한 Windows 내장 target으로 빌드한
DLL로 재실행한 여섯 번째 startup도 같은 5,886 bytes의 strict decode를 통과했다.
DLL SHA-256은 `61633704d8daed7eceac0bdfced96111a804c6caa8e7c197e6d5a8361c62c4f5`,
23개 선택 source를 기록한 manifest SHA-256은
`a3ecf7138d7244d5c2af5fc7a574412307de30ff0e702260f2cfe21ae51a3e59`,
새 raw SHA-256은 `7935d96d9f16eb18d1da402df28a44b48993684cd7e4c79edf7102b9653d7c10`다.
원래 input 거절·premain 실패·stdout 경고의 FRAME 거절과 각각의 원시 결과는
저장소 밖에 보존했다. Java 경계 검사 22개 및 Rust 순수 검사 48개의 성공과 이
실제 startup 성공을 구분한다. Linux·macOS startup, 실제 게임 정의·source
admission·초기화 정책·전체 SAM 참조 closure와 write profile 인수는 미완료다.

## 출처와 라이선스

MMMM 소스와 테스트는 독립 작성한 구현이며 저장소 MIT 라이선스를 따른다.
생성한 JDK header나 OpenJDK 구현 본문을 복사하거나 배포하지 않는다. FFI의
공개 ABI와 동작을 확인한 primary source는 다음과 같다.

| 자료 | 확인한 내용 | 자료 자체의 표시 |
| --- | --- | --- |
| [OpenJDK `jni.h`](https://github.com/openjdk/jdk/blob/jdk-25-ga/src/java.base/share/native/include/jni.h) | JNI signature, interface 위치, 버전 | GPLv2 + Classpath exception |
| [Windows `jni_md.h`](https://github.com/openjdk/jdk/blob/jdk-25-ga/src/java.base/windows/native/include/jni_md.h) | Windows primitive type/export ABI | GPLv2 + Classpath exception |
| [OpenJDK `jvmti.xml`](https://github.com/openjdk/jdk/blob/jdk-25-ga/src/hotspot/share/prims/jvmti.xml) | event/function 번호와 공개 JVMTI 동작 | 원본 XML은 GPLv2 |
| [OpenJDK `jvmtiH.xsl`](https://github.com/openjdk/jdk/blob/jdk-25-ga/src/hotspot/share/prims/jvmtiH.xsl) | callback 예약 슬롯과 header 생성 규칙 | 원본 XSL은 GPLv2; header 생성 template는 GPL/Classpath header를 지정 |
| [OpenJDK `ClassLoader.c`](https://github.com/openjdk/jdk/blob/jdk-25-ga/src/java.base/share/native/libjava/ClassLoader.c) | defineClass0/1/2의 실제 인자와 반환 경계 | 해당 소스의 라이선스 header 유지 대상 |
| [JVMS 25 classfile 명세](https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html) | 유한한 classfile/Code/constant-pool 검사 | 공식 명세 참고 |

이 표는 상위 소스의 라이선스를 MMMM 라이선스로 바꾸지 않는다. 이후 vendor
소스나 생성 header를 실제 도입하면 그 입력·라이선스·고지와 배포 조건을
별도로 등록해야 한다.
