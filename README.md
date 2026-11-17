# xss-check

XSS 쇼츠(`xss-1-shorts` 연작) 대본에 나올 사실을 작은 코드로 확인한다. 자바 25 + Thymeleaf 3.1(스프링 없음), 사실 8용 commonmark 0.24·jsoup 1.18, Gradle `application` 플러그인. 코드는 `src/main/java/demo/App.java` 하나.
끼어든 글이 실행되면 `body`에 `data-xss` 속성이 붙게 해 두고, 설치된 Chrome을 headless로 띄워(`--dump-dom`) 다 그려진 DOM에 그 표시가 있는지로 "실행됨 / 안 됨"을 판단한다. 페이지는 자바 내장 `HttpServer`(127.0.0.1, 빈 포트)가 준다.

## 확인하는 것과 결과
1. 글을 그대로 넣으면 `<script>`가 실행되고, `th:text`는 `&lt;script&gt;`로 바꿔 글자만 보인다. `th:utext`는 바꾸지 않아 실행된다 → 확인(브라우저).
2. HTML 본문용 바꾸기로는 못 막는 자리 → 확인(브라우저). (가) `th:href`에 `javascript:` 주소: Thymeleaf가 그대로 넣고 클릭하면 실행. (나) 따옴표 없는 속성 `<img src=입력>`: 띄어쓰기·`=`는 바꾸지 않아 `onerror`가 붙음. (다) 스크립트 안 `var id = 입력;`: 따옴표 밖이라 `;` 뒤가 명령이 됨. 대조로 `th:inline="javascript"`는 문자열로 감싸 막힘.
3. `<script>` 낱말만 지우는 걸러 내기 → 뚫림 확인(브라우저). `<scr<script>ipt>`는 지운 뒤 `<script>`가 되고, `<img onerror>`, `<svg onload>`는 손대지 않고 통과.
4. HttpOnly 쿠키는 `document.cookie`에 안 보임(보통 쿠키만 보임), CSP `script-src 'self'`면 끼어든 인라인 스크립트는 실행 안 되고 같은 서버의 `/app.js`는 실행 → 확인(Chrome headless).
5. 저장형 → 확인(브라우저). 글쓴이가 `POST /5-write`로 `<img src=x onerror=…>`를 남기고 떠난 뒤(브라우저 아님), 서로 다른 Chrome 프로필 두 방문이 `/5-board`를 열면 둘 다 실행(서버 요청 2번). 저장소엔 원문 그대로 두고 보여 줄 때 `th:text`로 바꾸면(`/5-board-safe`) 글자로만 보임.
6. 반사형 → 확인(브라우저). `/6-search?q=<img onerror>` 링크를 열면 서버가 그대로 되비쳐 실행, 서버 저장소 글 수는 그대로. 되비칠 때 `th:text`면 막힘.
7. DOM 기반 → 확인(브라우저). 서버가 받은 요청 줄은 `GET /7-inner HTTP/1.1`뿐(`#` 뒤 없음). 페이지 스크립트가 `#` 뒤를 `innerHTML`로 넣으면 `<img onerror>`는 실행, `<script>`는 요소만 들어가고 실행 안 됨. `textContent`면 글자로만 보임.
8. 꾸밈 허용 함정 → 확인(브라우저). 마크다운(commonmark 기본값)은 `<img onerror>`·`javascript:` 링크를 그대로 HTML로 내보내 `th:utext`면 실행. 사실 3의 걸러 내기를 거쳐도 실행. jsoup `Safelist.basicWithImages`는 `<strong>`·https 링크는 남기고 `onerror`·`javascript:` 주소는 버려 실행 안 됨.

### 보강 (출력 맨 끝 `---- 보강 ----` 아래, 위 1~8의 출력은 그대로)
- 4 보강 → 확인(브라우저). 로그인 응답(`sid` HttpOnly)을 받은 페이지에 끼어든 스크립트가 `fetch('/4b-me', POST)`를 보내면, `document.cookie`엔 `sid`가 안 보이지만 서버는 `Cookie: sid=SECRET123; …`를 받아 `alice(로그인)`으로 처리. 로그인 안 한 새 프로필은 `손님`.
- 7 보강 → 확인(브라우저). 서버가 `?q=`를 화면에 안 넣어도 페이지 스크립트가 주소에서 꺼내 `innerHTML`로 넣으면 실행. 서버가 `th:text`로 바꿔 넣은 글자(`&lt;img …&gt;`)도 페이지 스크립트가 `textContent`로 꺼내 `innerHTML`로 다시 넣으면 실행, `textContent`로 넣으면 안 됨.
- 8 보강 → 확인(브라우저). `<a>`를 허락하는 `Safelist.basic`도 `javascript:`·`JaVaScRiPt:`·`java&#x09;script:` href는 버림(`<a rel="nofollow">`만 남아 클릭해도 실행 안 됨). 걸러 내기 전 원문은 셋 다 클릭 시 실행.
- 9 큰일 확인 → 확인(브라우저). (가) 같은 페이지 안에서 비밀번호를 다시 받으면 끼어든 스크립트가 가짜 확인 창을 넣고, 비밀번호 칸 값(`input.value`)을 읽어 그 값으로 큰일 요청을 보내 서버가 처리(사용자 입력은 페이지 스크립트가 대신 입력). (나) 시뮬레이션: 서버가 승인 토큰을 다른 기기로만 보내는 설계면 끼어든 스크립트의 요청은 `202 승인 대기`, 토큰 없이·지어낸 토큰으로 승인 시도는 `403`, 진짜 토큰(다른 기기 역할의 자바 코드)으로만 처리.
- 10 → CSP `script-src 'self'`여도 같은 사이트의 스크립트는 실행: 사실 4의 `/app.js` 줄이 근거(따로 안 돌림).

## IntelliJ에서 돌리기
1. File > Open 으로 이 폴더를 연다(Gradle 프로젝트로 가져온다). SDK는 Java 25.
2. `src/main/java/demo/App.java` 의 `main` 옆 실행 버튼을 누른다.
3. 콘솔의 `[사실 n]` 줄을 본다. 기대 출력은 `run-expected.txt`.

터미널에서는 `gradlew.bat run`(처음엔 jsoup·commonmark 내려받기로 인터넷 필요) (JAVA_HOME이 Java 25를 가리켜야 한다). Chrome이 기본 위치에 없으면 환경 변수 `CHROME`에 chrome.exe 경로를 넣는다. 없으면 브라우저 줄은 "미확인"으로 나온다.
