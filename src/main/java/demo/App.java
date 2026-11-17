package demo;

import com.sun.net.httpserver.HttpServer;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.StringTemplateResolver;
import org.unbescape.html.HtmlEscape;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.safety.Safelist;

import java.io.File;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * XSS 쇼츠 대본에 쓸 사실을 확인한다.
 * 끼어든 글(공격자 입력)이 실행되면 body 에 data-xss 속성을 붙인다. 진짜 Chrome(headless)으로 열어
 * 다 그려진 DOM 에 data-xss 가 있는지로 "실행됨 / 안 됨"을 판단한다.
 */
public class App {

    /** 실행되면 표시를 남기는 명령(따옴표 없음: 따옴표가 바뀌는 효과를 빼고 보려고). */
    static final String MARK = "document.body.dataset.xss=1";

    static final TemplateEngine ENGINE = new TemplateEngine();
    static {
        StringTemplateResolver r = new StringTemplateResolver();
        r.setTemplateMode(TemplateMode.HTML);
        ENGINE.setTemplateResolver(r);
    }

    static String thymeleaf(String template, Object x) {
        Context c = new Context();
        c.setVariable("x", x);
        return ENGINE.process(template, c);
    }

    /** HTML 본문용 바꾸기(< > & " ' 를 글자로). th:text 와 같은 종류. */
    static String htmlEscape(String s) {
        return HtmlEscape.escapeHtml4Xml(s);
    }

    static String page(String body) {
        return "<!doctype html><html><head><meta charset=utf-8></head><body>" + body + "</body></html>";
    }

    // 브라우저로 열 페이지들: 경로 -> (헤더, HTML)
    static final Map<String, String[]> PAGES = new LinkedHashMap<>();

    public static void main(String[] args) throws Exception {
        System.out.println("Java " + System.getProperty("java.version"));
        String scriptPayload = "<script>" + MARK + "</script>";

        // ---------------- 사실 1 ----------------
        System.out.println();
        System.out.println("[사실 1] 댓글 = " + scriptPayload);
        String raw = page("<p>" + scriptPayload + "</p>");
        String text = thymeleaf(page("<p th:text=\"${x}\"></p>"), scriptPayload);
        String utext = thymeleaf(page("<p th:utext=\"${x}\"></p>"), scriptPayload);
        System.out.println("[사실 1]   글 그대로 이어 붙임 -> " + body(raw));
        System.out.println("[사실 1]   th:text            -> " + body(text));
        System.out.println("[사실 1]   th:utext           -> " + body(utext));
        PAGES.put("/1-raw", new String[]{null, raw});
        PAGES.put("/1-text", new String[]{null, text});
        PAGES.put("/1-utext", new String[]{null, utext});

        // ---------------- 사실 2 ----------------
        System.out.println();
        System.out.println("[사실 2] HTML 본문용 바꾸기(th:text 와 같은 바꾸기)를 했는데도 뚫리는 자리");
        String jsUrl = "javascript:" + MARK;
        String href = thymeleaf(page("<a id=go th:href=\"${x}\">내 홈페이지</a>"
                + "<script>document.getElementById('go').click()</script>"), jsUrl);
        System.out.println("[사실 2]   (가) 링크 주소 th:href, 입력 = " + jsUrl);
        System.out.println("[사실 2]       -> " + body(href).replaceAll("<script>.*</script>", "") + "   (클릭은 페이지가 대신 누름)");
        PAGES.put("/2-href", new String[]{null, href});

        String unq = "x onerror=" + MARK;
        String unquoted = page("<img src=" + htmlEscape(unq) + ">");
        System.out.println("[사실 2]   (나) 따옴표 없는 속성 <img src=입력>, 입력 = " + unq);
        System.out.println("[사실 2]       -> " + body(unquoted));
        PAGES.put("/2-unquoted", new String[]{null, unquoted});

        String num = "1;" + MARK;
        String inScript = page("<script>var id = " + htmlEscape(num) + ";</script>");
        System.out.println("[사실 2]   (다) 스크립트 안 var id = 입력; , 입력 = " + num);
        System.out.println("[사실 2]       -> " + body(inScript));
        PAGES.put("/2-script", new String[]{null, inScript});

        String inScriptTh = thymeleaf(page("<script th:inline=\"javascript\">var id = [[${x}]];</script>"), num);
        System.out.println("[사실 2]   (대조) 같은 자리에 스크립트용 바꾸기(th:inline=javascript)");
        System.out.println("[사실 2]       -> " + body(inScriptTh));
        PAGES.put("/2-script-th", new String[]{null, inScriptTh});

        // ---------------- 사실 3 ----------------
        System.out.println();
        System.out.println("[사실 3] 들어올 때 <script> 낱말만 지우는 걸러 내기 (대소문자 무시, 한 번)");
        List<String> attacks = List.of(
                "<script>" + MARK + "</script>",
                "<scr<script>ipt>" + MARK + "</scr</script>ipt>",
                "<img src=x onerror=" + MARK + ">",
                "<svg onload=" + MARK + ">");
        int i = 0;
        for (String a : attacks) {
            String f = naiveFilter(a);
            System.out.println("[사실 3]   " + a);
            System.out.println("[사실 3]     걸러 낸 뒤 -> " + f);
            PAGES.put("/3-" + (i++), new String[]{null, page("<p>" + f + "</p>")});
        }

        // ---------------- 사실 4 ----------------
        System.out.println();
        System.out.println("[사실 4] 서버가 쿠키 두 개를 줌: sid=SECRET123 (HttpOnly), theme=dark (보통 쿠키)");
        PAGES.put("/4-cookie", new String[]{"cookie",
                page("<p id=c></p><script>document.body.dataset.cookie=document.cookie</script>")});
        System.out.println("[사실 4] CSP script-src 'self' 를 단 페이지에 사실 1의 <script> 가 그대로 끼어듦 (+ 같은 서버의 /app.js)");
        PAGES.put("/4-csp", new String[]{"csp", page("<p>" + scriptPayload + "</p><script src=/app.js></script>")});
        PAGES.put("/4-nocsp", new String[]{null, page("<p>" + scriptPayload + "</p><script src=/app.js></script>")});
        System.out.println("[사실 11] CSP script-src 'self' 가 무엇을 막고 무엇을 못 막나 (6편 두 번째 자물쇠)");
        PAGES.put("/11-img", new String[]{"csp", page("<p><img src=x onerror=" + MARK + "></p>")});
        PAGES.put("/11-upload", new String[]{"csp", page("<p><script src=/uploads/evil.js></script></p>")});
        PAGES.put("/11-loose", new String[]{"csp-loose", page("<p>" + scriptPayload + "</p>")});

        // ---------------- 사실 5~7: 서버가 있어야 하는 것 (브라우저 절에서 돌림) ----------------
        System.out.println();
        System.out.println("[사실 5] 저장형: 글쓴이가 서버에 글을 저장하고 떠남 -> 다른 두 방문자가 게시판을 엶 (브라우저 절)");
        System.out.println("[사실 6] 반사형: 주소 ?q= 의 글을 서버가 화면에 그대로 되비침, 저장 없음 (브라우저 절)");
        System.out.println("[사실 7] DOM 기반: 주소 # 뒤 조각을 페이지 스크립트가 innerHTML / textContent 로 넣음 (브라우저 절)");

        // ---------------- 사실 8 ----------------
        System.out.println();
        String mdIn = "**굵게** [블로그](https://example.com) <img src=x onerror=\"" + MARK + "\"> [누르기](javascript:" + MARK + ")";
        String mdHtml = markdown(mdIn);
        System.out.println("[사실 8] 꾸밈 허용: 마크다운 글 = " + mdIn);
        System.out.println("[사실 8]   마크다운 -> HTML (commonmark 기본값) = " + mdHtml);
        System.out.println("[사실 8]   지울 것을 고르는 걸러 내기(사실 3) 뒤 = " + naiveFilter(mdHtml));
        System.out.println("[사실 8]   허용 목록(jsoup Safelist.basicWithImages) 뒤 = " + safelist(mdHtml));
        String mdImg = "**굵게** <img src=x onerror=\"" + MARK + "\">";
        String mdJs = "**굵게** [누르기](javascript:" + MARK + ")";
        String click = "<script>document.querySelectorAll('a').forEach(a=>a.click())</script>";
        String utextT = "<div th:utext=\"${x}\"></div>";
        PAGES.put("/8-img-utext", new String[]{null, thymeleaf(page(utextT), markdown(mdImg))});
        PAGES.put("/8-img-naive", new String[]{null, thymeleaf(page(utextT), naiveFilter(markdown(mdImg)))});
        PAGES.put("/8-img-safe", new String[]{null, thymeleaf(page(utextT), safelist(markdown(mdImg)))});
        PAGES.put("/8-js-utext", new String[]{null, thymeleaf(page(utextT + click), markdown(mdJs))});
        PAGES.put("/8-js-safe", new String[]{null, thymeleaf(page(utextT + click), safelist(markdown(mdJs)))});

        extraPages();
        browserChecks();
    }

    static String markdown(String md) {
        return HtmlRenderer.builder().build().render(Parser.builder().build().parse(md)).trim();
    }

    /** 허용할 것만 남기는 방식: 목록에 없는 태그·속성·주소 형식은 버린다. */
    static String safelist(String html) {
        return Jsoup.clean(html, "", Safelist.basicWithImages(), new Document.OutputSettings().prettyPrint(false));
    }

    // 사실 5: 서버 저장소(걸러 내지 않고 받은 그대로 저장)
    static final List<String> STORE = Collections.synchronizedList(new ArrayList<>());
    // 서버가 받은 요청 줄
    static final List<String> REQLOG = Collections.synchronizedList(new ArrayList<>());

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    static String query(String rawQuery, String key) {
        if (rawQuery == null) return "";
        for (String kv : rawQuery.split("&")) {
            int e = kv.indexOf('=');
            if (e > 0 && kv.substring(0, e).equals(key)) return URLDecoder.decode(kv.substring(e + 1), StandardCharsets.UTF_8);
        }
        return "";
    }

    /** 요청마다 그때 만드는 페이지(사실 5, 6, 7). 없으면 null. */
    static String dynamicPage(String path, String rawQuery) {
        switch (path) {
            case "/5-board": { // 보여 줄 때 바꾸지 않음
                StringBuilder sb = new StringBuilder("<h1>게시판</h1><ul>");
                synchronized (STORE) { for (String c : STORE) sb.append("<li>").append(c).append("</li>"); }
                return page(sb + "</ul>");
            }
            case "/5-board-safe": // 보여 줄 때 th:text 로 바꿈
                return thymeleaf(page("<h1>게시판</h1><ul><li th:each=\"c : ${x}\" th:text=\"${c}\"></li></ul>"), List.copyOf(STORE));
            case "/6-search":
                return page("<p>검색어: " + query(rawQuery, "q") + "</p>");
            case "/6-search-safe":
                return thymeleaf(page("<p>검색어: <span th:text=\"${x}\"></span></p>"), query(rawQuery, "q"));
            case "/7-inner":
                return page("<div id=out></div><script>document.getElementById('out').innerHTML=decodeURIComponent(location.hash.slice(1))</script>");
            case "/7-text":
                return page("<div id=out></div><script>document.getElementById('out').textContent=decodeURIComponent(location.hash.slice(1))</script>");
            default:
                return null;
        }
    }

    static String naiveFilter(String s) {
        return s.replaceAll("(?i)</?script>", "");
    }

    static String body(String html) {
        int a = html.indexOf("<body>"), b = html.lastIndexOf("</body>");
        return a >= 0 && b > a ? html.substring(a + 6, b) : html;
    }

    // ---------------- 브라우저 ----------------

    static void browserChecks() throws Exception {
        String chrome = findChrome();
        System.out.println();
        if (chrome == null) {
            System.out.println("[브라우저] Chrome 을 못 찾음 -> 브라우저 확인은 미확인 (CHROME 환경 변수로 경로 지정 가능)");
            return;
        }
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            String p = ex.getRequestURI().getPath();
            REQLOG.add(ex.getRequestMethod() + " " + ex.getRequestURI() + " " + ex.getProtocol());
            if (extraRoute(ex, p)) return;
            byte[] out;
            String dyn = dynamicPage(p, ex.getRequestURI().getRawQuery());
            if (p.equals("/5-write") && ex.getRequestMethod().equals("POST")) {
                STORE.add(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)); // 걸러 내지 않고 저장
                ex.sendResponseHeaders(204, -1);
                ex.close();
                return;
            } else if (dyn != null) {
                ex.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                out = dyn.getBytes(StandardCharsets.UTF_8);
            } else if (p.equals("/uploads/evil.js")) { // 공격자가 같은 사이트에 올려 둔 파일
                ex.getResponseHeaders().add("Content-Type", "application/javascript");
                out = MARK.getBytes(StandardCharsets.UTF_8);
            } else if (p.equals("/app.js")) {
                ex.getResponseHeaders().add("Content-Type", "application/javascript");
                out = "document.body.dataset.selfjs=1".getBytes(StandardCharsets.UTF_8);
            } else if (PAGES.containsKey(p)) {
                String[] pg = PAGES.get(p);
                ex.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                if ("cookie".equals(pg[0])) {
                    ex.getResponseHeaders().add("Set-Cookie", "sid=SECRET123; Path=/; HttpOnly");
                    ex.getResponseHeaders().add("Set-Cookie", "theme=dark; Path=/");
                }
                if ("csp".equals(pg[0])) {
                    ex.getResponseHeaders().add("Content-Security-Policy", "script-src 'self'");
                }
                if ("csp-loose".equals(pg[0])) {
                    ex.getResponseHeaders().add("Content-Security-Policy", "script-src 'self' 'unsafe-inline'");
                }
                out = pg[1].getBytes(StandardCharsets.UTF_8);
            } else {
                ex.sendResponseHeaders(404, -1);
                ex.close();
                return;
            }
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        Path profile = Files.createTempDirectory("xss-check-chrome");
        System.out.println("[브라우저] " + chrome + " --headless 로 열어 다 그려진 DOM 을 봄");
        try {
            String[][] rows = {
                    {"1", "/1-raw", "글 그대로"},
                    {"1", "/1-text", "th:text"},
                    {"1", "/1-utext", "th:utext"},
                    {"2", "/2-href", "(가) th:href 에 javascript: 주소"},
                    {"2", "/2-unquoted", "(나) 따옴표 없는 속성 + HTML 바꾸기"},
                    {"2", "/2-script", "(다) 스크립트 안 + HTML 바꾸기"},
                    {"2", "/2-script-th", "(대조) 스크립트 안 + th:inline=javascript"},
                    {"3", "/3-0", "<script> 그대로"},
                    {"3", "/3-1", "<scr<script>ipt>"},
                    {"3", "/3-2", "<img onerror>"},
                    {"3", "/3-3", "<svg onload>"},
            };
            for (String[] row : rows) {
                String dom = dump(chrome, profile, base + row[1]);
                boolean ran = dom.contains("data-xss=\"1\"");
                System.out.printf("[사실 %s] 브라우저: %-36s -> %s%n", row[0], row[2],
                        ran ? "끼어든 명령 실행됨" : "실행 안 됨");
            }
            String dom = dump(chrome, profile, base + "/4-cookie");
            String seen = attr(dom, "data-cookie");
            System.out.println("[사실 4] 브라우저: 페이지 스크립트의 document.cookie = \"" + seen + "\""
                    + (seen.contains("SECRET123") ? "  (HttpOnly 쿠키가 보임)" : "  (HttpOnly 쿠키 sid 는 안 보임)"));
            for (String p : List.of("/4-nocsp", "/4-csp")) {
                dom = dump(chrome, profile, base + p);
                System.out.println("[사실 4] 브라우저: " + (p.equals("/4-csp") ? "CSP 있음" : "CSP 없음")
                        + " -> 끼어든 인라인 스크립트 " + (dom.contains("data-xss=\"1\"") ? "실행됨" : "실행 안 됨")
                        + ", 같은 서버의 /app.js " + (dom.contains("data-selfjs=\"1\"") ? "실행됨" : "실행 안 됨"));
            }
            for (String[] r : new String[][]{
                    {"/11-img", "(가) CSP 'self' + 끼어든 <img onerror>"},
                    {"/11-upload", "(나) CSP 'self' + 같은 사이트에 올린 파일 <script src>"},
                    {"/11-loose", "(다) CSP 'self' 'unsafe-inline' + 끼어든 <script>"}}) {
                dom = dump(chrome, profile, base + r[0]);
                System.out.printf("[사실 11] 브라우저: %-44s -> %s%n", r[1],
                        dom.contains("data-xss=\"1\"") ? "끼어든 명령 실행됨" : "실행 안 됨");
            }

            // ---- 사실 5: 저장형 ----
            String comment = "<img src=x onerror=" + MARK + ">";
            HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(base + "/5-write"))
                    .POST(HttpRequest.BodyPublishers.ofString(comment)).build(), HttpResponse.BodyHandlers.discarding());
            System.out.println("[사실 5] 글쓴이: POST /5-write 로 댓글 " + comment + " 를 남기고 떠남 (브라우저 아님, 다시 안 옴)");
            System.out.println("[사실 5] 서버 저장소 = " + STORE + "   (저장할 때 걸러 내지 않음, 원문 그대로)");
            Path visitorA = Files.createTempDirectory("xss-check-visitorA");
            Path visitorB = Files.createTempDirectory("xss-check-visitorB");
            int before = count("/5-board");
            row("5", "방문자 A(새 프로필) /5-board (보여 줄 때 안 바꿈)", dump(chrome, visitorA, base + "/5-board"));
            row("5", "방문자 B(다른 프로필) /5-board (보여 줄 때 안 바꿈)", dump(chrome, visitorB, base + "/5-board"));
            System.out.println("[사실 5] 서버가 받은 /5-board 요청 수 = " + (count("/5-board") - before) + " (두 방문 각각 저장 글을 받아 감)");
            dom = dump(chrome, visitorA, base + "/5-board-safe");
            row("5", "방문자 A /5-board-safe (보여 줄 때 th:text)", dom);
            System.out.println("[사실 5]   보인 글 -> " + between(dom, "<li>", "</li>") + "   (저장소는 그대로 " + STORE + ")");

            // ---- 사실 6: 반사형 ----
            int stored = STORE.size();
            String link = "/6-search?q=" + enc(comment);
            System.out.println("[사실 6] 링크 = " + link);
            row("6", "링크를 연 사람 /6-search (그대로 되비침)", dump(chrome, profile, base + link));
            row("6", "같은 글 /6-search-safe (되비칠 때 th:text)", dump(chrome, profile, base + "/6-search-safe?q=" + enc(comment)));
            System.out.println("[사실 6] 서버 저장소 글 수: 링크 열기 전 " + stored + " -> 후 " + STORE.size() + " (아무것도 저장 안 됨)");
            printReq("6", "/6-");

            // ---- 사실 7: DOM 기반 ----
            String imgFrag = "<img src=x onerror=" + MARK + ">";
            String scriptFrag = "<script>" + MARK + "</script>";
            System.out.println("[사실 7] 주소 = /7-inner#" + imgFrag + "  (실제로는 # 뒤를 %-인코딩해 엶)");
            row("7", "innerHTML 에 <img onerror>", dump(chrome, profile, base + "/7-inner#" + enc(imgFrag)));
            dom = dump(chrome, profile, base + "/7-inner#" + enc(scriptFrag));
            row("7", "innerHTML 에 <script>", dom);
            System.out.println("[사실 7]   (그때 DOM 의 #out = " + between(dom, "<div id=\"out\">", "</div>") + "  -> 요소는 들어갔지만 실행 안 됨)");
            dom = dump(chrome, profile, base + "/7-text#" + enc(imgFrag));
            row("7", "textContent 에 <img onerror>", dom);
            System.out.println("[사실 7]   (그때 DOM 의 #out = " + between(dom, "<div id=\"out\">", "</div>") + "  -> 글자로만 보임)");
            printReq("7", "/7-");

            // ---- 사실 8: 꾸밈 허용 ----
            row("8", "마크다운 <img onerror> -> th:utext", dump(chrome, profile, base + "/8-img-utext"));
            row("8", "마크다운 <img onerror> -> 걸러 내기 -> utext", dump(chrome, profile, base + "/8-img-naive"));
            row("8", "마크다운 <img onerror> -> Safelist -> utext", dump(chrome, profile, base + "/8-img-safe"));
            row("8", "마크다운 javascript: 링크 클릭 -> utext", dump(chrome, profile, base + "/8-js-utext"));
            row("8", "마크다운 javascript: 링크 클릭 -> Safelist", dump(chrome, profile, base + "/8-js-safe"));

            extraChecks(chrome, base);
        } finally {
            server.stop(0);
        }
    }

    // ================= 보강 (사실 4·7·8 보강, 사실 9, 사실 10) =================
    // 기존 항목의 출력은 그대로 두고, 브라우저 절 맨 끝에 덧붙여 찍는다.

    /** 큰일 확인용 테스트 비밀번호(이 코드 안에서만 쓰는 값). */
    static final String TEST_PW = "pw1234";
    /** 사실 4 보강: /4b-me 가 받은 Cookie 헤더. */
    static final List<String> ME_COOKIES = Collections.synchronizedList(new ArrayList<>());
    /** 사실 9: 서버가 처리한 큰일(송금) 기록. */
    static final List<String> DONE = Collections.synchronizedList(new ArrayList<>());
    /** 사실 9 (나): 승인 대기 송금 id -> 다른 기기로만 보낸 승인 토큰. */
    static final Map<String, String> PENDING = Collections.synchronizedMap(new LinkedHashMap<>());
    static final List<String> APPROVE_LOG = Collections.synchronizedList(new ArrayList<>());

    static final String CLICK_ALL = "<script>document.querySelectorAll('a').forEach(a=>a.click())</script>";
    static final List<String> LINK_ATTACKS = List.of(
            "<a href=\"javascript:" + MARK + "\">누르기</a>",
            "<a href=\"JaVaScRiPt:" + MARK + "\">누르기</a>",
            "<a href=\"java&#x09;script:" + MARK + "\">누르기</a>");

    static void extraPages() {
        // 사실 4 보강: 로그인 응답(HttpOnly sid)을 받은 페이지에 끼어든 스크립트가 같은 사이트로 fetch
        String fetchMe = "<script>" + MARK + ";fetch('/4b-me',{method:'POST'}).then(r=>r.text())"
                + ".then(t=>{document.body.dataset.me=t;document.body.dataset.seen=document.cookie})</script>";
        PAGES.put("/4b-fetch", new String[]{"cookie", page("<p>" + fetchMe + "</p>")});
        PAGES.put("/4b-fetch-nologin", new String[]{null, page("<p>" + fetchMe + "</p>")});

        // 사실 8 보강: <a> 를 허락하는 Safelist.basic 에서 javascript: href
        for (int k = 0; k < LINK_ATTACKS.size(); k++) {
            PAGES.put("/8b-raw-" + k, new String[]{null, page("<div>" + LINK_ATTACKS.get(k) + "</div>" + CLICK_ALL)});
            PAGES.put("/8b-safe-" + k, new String[]{null, page("<div>" + safelistBasic(LINK_ATTACKS.get(k)) + "</div>" + CLICK_ALL)});
        }

        // 사실 9 (가): 같은 페이지 안에서 비밀번호를 다시 받는 확인
        String injected9a = "<script>" + MARK + ";"
                // 가짜 확인 창 띄우기
                + "var f=document.createElement('div');f.id='fake';f.textContent='보안 확인: 비밀번호를 다시 입력하세요';"
                + "document.body.prepend(f);"
                // 진짜 입력 칸의 값 읽기 -> 그 값으로 서버에 큰일 요청
                + "document.addEventListener('input',e=>{if(e.target.id==='pw'){document.body.dataset.stolen=e.target.value;"
                + "fetch('/9a-transfer',{method:'POST',body:e.target.value}).then(r=>r.text()).then(t=>document.body.dataset.result=t)}},true)"
                + "</script>";
        String user9a = "<script>setTimeout(()=>{var pw=document.getElementById('pw');pw.value='" + TEST_PW + "';"
                + "pw.dispatchEvent(new Event('input',{bubbles:true}))},100)</script>";
        PAGES.put("/9a-page", new String[]{null, page("<p>댓글: " + injected9a + "</p>"
                + "<h2>송금 확인: 비밀번호를 다시 입력하세요</h2><input type=password id=pw><button id=ok>확인</button>" + user9a)});

        // 사실 9 (나): 다른 기기 승인이 있어야 처리
        String injected9b = "<script>" + MARK + ";(async()=>{"
                + "var r=await fetch('/9b-transfer',{method:'POST'});var t=await r.text();document.body.dataset.req=r.status+' '+t;"
                + "var id=t.split('id=')[1];"
                + "var a=await fetch('/9b-approve?id='+id,{method:'POST'});document.body.dataset.notoken=a.status+'';"
                + "var b=await fetch('/9b-approve?id='+id+'&token=guess',{method:'POST'});document.body.dataset.guess=b.status+''"
                + "})()</script>";
        PAGES.put("/9b-page", new String[]{null, page("<p>댓글: " + injected9b + "</p>")});
    }

    /** <a> 를 허락하는 허용 목록(Safelist.basic: a[href] 는 http·https·ftp·mailto 만). */
    static String safelistBasic(String html) {
        return Jsoup.clean(html, "", Safelist.basic(), new Document.OutputSettings().prettyPrint(false));
    }

    static void send(com.sun.net.httpserver.HttpExchange ex, int code, String body, String type) throws java.io.IOException {
        byte[] out = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", type);
        ex.sendResponseHeaders(code, out.length);
        ex.getResponseBody().write(out);
        ex.close();
    }

    /** 보강용 경로. 처리했으면 true. */
    static boolean extraRoute(com.sun.net.httpserver.HttpExchange ex, String p) throws java.io.IOException {
        String q = ex.getRequestURI().getRawQuery();
        switch (p) {
            case "/4b-me": { // 쿠키의 세션으로 로그인 사용자 판단
                String c = String.valueOf(ex.getRequestHeaders().getFirst("Cookie"));
                ME_COOKIES.add(c);
                send(ex, 200, c.contains("sid=SECRET123") ? "alice(로그인)" : "손님(로그인 안 됨)", "text/plain; charset=utf-8");
                return true;
            }
            case "/7b-q-inner": // 서버는 ?q= 를 화면에 안 넣음. 페이지 스크립트가 주소에서 꺼내 innerHTML
                send(ex, 200, page("<div id=out></div><script>document.getElementById('out').innerHTML="
                        + "new URLSearchParams(location.search).get('q')</script>"), "text/html; charset=utf-8");
                return true;
            case "/7b-esc-inner": // 서버는 th:text 로 바꿔 넣음 -> 페이지 스크립트가 꺼내 innerHTML
            case "/7b-esc-text": { // 대조: textContent
                String sink = p.endsWith("inner") ? "innerHTML" : "textContent";
                send(ex, 200, thymeleaf(page("<p id=src th:text=\"${x}\"></p><div id=out></div><script>document.getElementById('out')."
                        + sink + "=document.getElementById('src').textContent</script>"), query(q, "q")), "text/html; charset=utf-8");
                return true;
            }
            case "/9a-transfer": { // 같은 페이지 비밀번호 재확인: 비밀번호가 맞으면 처리
                String pw = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                boolean ok = pw.equals(TEST_PW);
                if (ok) DONE.add("9a 송금");
                send(ex, ok ? 200 : 403, ok ? "처리됨" : "비밀번호 틀림", "text/plain; charset=utf-8");
                return true;
            }
            case "/9b-transfer": { // 다른 기기 승인 방식: 요청은 받되 승인 대기, 토큰은 응답에 안 넣음
                String id = String.valueOf(PENDING.size() + 1);
                PENDING.put(id, java.util.UUID.randomUUID().toString()); // 다른 기기로만 보냈다고 가정
                send(ex, 202, "승인 대기 id=" + id, "text/plain; charset=utf-8");
                return true;
            }
            case "/9b-approve": {
                String id = query(q, "id"), token = query(q, "token");
                String want = PENDING.get(id);
                boolean ok = want != null && want.equals(token);
                APPROVE_LOG.add("승인 시도 id=" + id + " 토큰=" + (token.isEmpty() ? "(없음)" : token.equals(want) ? "(다른 기기의 진짜 토큰)" : token)
                        + " -> " + (ok ? "200 처리됨" : "403 거절"));
                if (ok) { DONE.add("9b 송금 id=" + id); PENDING.remove(id); }
                send(ex, ok ? 200 : 403, ok ? "처리됨" : "거절", "text/plain; charset=utf-8");
                return true;
            }
            default:
                return false;
        }
    }

    static void extraChecks(String chrome, String base) throws Exception {
        System.out.println();
        System.out.println("---------------- 보강 ----------------");

        // ---- 사실 4 보강 ----
        Path p4 = Files.createTempDirectory("xss-check-4b");
        String dom = dump(chrome, p4, base + "/4b-fetch");
        System.out.println("[사실 4 보강] 로그인 응답(sid=SECRET123 HttpOnly)을 받은 페이지에 끼어든 스크립트가 fetch('/4b-me', POST)");
        row("4 보강", "끼어든 스크립트", dom);
        System.out.println("[사실 4 보강]   스크립트가 본 document.cookie = \"" + attr(dom, "data-seen") + "\"  (sid 는 못 읽음)");
        System.out.println("[사실 4 보강]   서버가 받은 Cookie 헤더 = \"" + (ME_COOKIES.isEmpty() ? "(요청 없음)" : ME_COOKIES.get(0)) + "\"");
        System.out.println("[사실 4 보강]   서버 응답(스크립트가 받음) = \"" + attr(dom, "data-me") + "\"");
        dom = dump(chrome, Files.createTempDirectory("xss-check-4b0"), base + "/4b-fetch-nologin");
        System.out.println("[사실 4 보강]   (대조) 로그인 안 한 새 프로필에서 같은 fetch -> 서버 응답 = \"" + attr(dom, "data-me") + "\"");

        // ---- 사실 7 보강 ----
        Path p7 = Files.createTempDirectory("xss-check-7b");
        String img = "<img src=x onerror=" + MARK + ">";
        System.out.println("[사실 7 보강] 입력 = " + img);
        row("7 보강", "?q= 를 페이지 스크립트가 innerHTML", dump(chrome, p7, base + "/7b-q-inner?q=" + enc(img)));
        String resp = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(base + "/7b-esc-inner?q=" + enc(img))).build(),
                HttpResponse.BodyHandlers.ofString()).body();
        System.out.println("[사실 7 보강]   서버 응답(th:text 로 바꿈)의 #src = " + between(resp, "<p id=src>", "</p>"));
        row("7 보강", "그 글자를 꺼내 innerHTML", dump(chrome, p7, base + "/7b-esc-inner?q=" + enc(img)));
        row("7 보강", "(대조) 그 글자를 꺼내 textContent", dump(chrome, p7, base + "/7b-esc-text?q=" + enc(img)));

        // ---- 사실 8 보강 ----
        Path p8 = Files.createTempDirectory("xss-check-8b");
        System.out.println("[사실 8 보강] 허용 목록 jsoup Safelist.basic (<a href> 허락, 주소 형식은 http·https·ftp·mailto)");
        System.out.println("[사실 8 보강]   https 링크 -> " + safelistBasic("<a href=\"https://example.com\">블로그</a>"));
        for (int k = 0; k < LINK_ATTACKS.size(); k++) {
            System.out.println("[사실 8 보강]   " + LINK_ATTACKS.get(k) + " -> " + safelistBasic(LINK_ATTACKS.get(k)));
            row("8 보강", "  그대로 + 클릭", dump(chrome, p8, base + "/8b-raw-" + k));
            row("8 보강", "  Safelist.basic 뒤 + 클릭", dump(chrome, p8, base + "/8b-safe-" + k));
        }

        // ---- 사실 9 ----
        Path p9 = Files.createTempDirectory("xss-check-9");
        System.out.println("[사실 9] (가) 같은 페이지 안에서 비밀번호를 다시 받는 큰일 확인 (사용자 입력은 페이지 스크립트가 대신 입력)");
        int done0 = DONE.size();
        dom = dump(chrome, p9, base + "/9a-page");
        row("9", "(가) 끼어든 스크립트", dom);
        System.out.println("[사실 9]   가짜 확인 창 = " + (dom.contains("id=\"fake\"") ? "페이지에 들어감 (\"" + between(dom, "<div id=\"fake\">", "</div>") + "\")" : "없음"));
        System.out.println("[사실 9]   끼어든 스크립트가 읽은 비밀번호 칸 값(input.value) = \"" + attr(dom, "data-stolen") + "\"");
        System.out.println("[사실 9]   그 값으로 보낸 큰일 요청의 서버 응답 = \"" + attr(dom, "data-result") + "\", 서버 처리 기록 " + done0 + " -> " + DONE.size());

        System.out.println("[사실 9] (나) 다른 기기 승인 방식 (시뮬레이션: 서버가 승인 토큰을 다른 기기로만 보내고 응답에는 안 넣음)");
        done0 = DONE.size();
        dom = dump(chrome, p9, base + "/9b-page");
        row("9", "(나) 끼어든 스크립트", dom);
        System.out.println("[사실 9]   끼어든 스크립트의 큰일 요청 -> " + attr(dom, "data-req"));
        System.out.println("[사실 9]   스크립트가 토큰 없이 승인 시도 -> " + attr(dom, "data-notoken") + ", 지어낸 토큰으로 -> " + attr(dom, "data-guess"));
        System.out.println("[사실 9]   그 뒤 서버 처리 기록 " + done0 + " -> " + DONE.size() + " (처리 안 됨, 승인 대기)");
        String pid, tok;
        synchronized (PENDING) { Map.Entry<String, String> e = PENDING.entrySet().iterator().next(); pid = e.getKey(); tok = e.getValue(); }
        int code = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(base + "/9b-approve?id=" + pid + "&token=" + tok))
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.discarding()).statusCode();
        System.out.println("[사실 9]   사용자가 다른 기기에서 승인(진짜 토큰) -> " + code + ", 서버 처리 기록 -> " + DONE.size());
        synchronized (APPROVE_LOG) { APPROVE_LOG.forEach(l -> System.out.println("[사실 9]   서버: " + l)); }

        // ---- 사실 10 ----
        System.out.println("[사실 10] CSP script-src 'self' 여도 같은 사이트의 스크립트는 실행 -> 사실 4의 \"CSP 있음 ... 같은 서버의 /app.js 실행됨\" 줄이 근거");
    }

    static void row(String n, String label, String dom) {
        System.out.printf("[사실 %s] 브라우저: %-36s -> %s%n", n, label,
                dom.contains("data-xss=\"1\"") ? "끼어든 명령 실행됨" : "실행 안 됨");
    }

    static int count(String path) {
        synchronized (REQLOG) { return (int) REQLOG.stream().filter(l -> l.startsWith("GET " + path + " ")).count(); }
    }

    static void printReq(String n, String prefix) {
        System.out.println("[사실 " + n + "] 서버가 받은 요청 줄:");
        synchronized (REQLOG) {
            REQLOG.stream().filter(l -> l.startsWith("GET " + prefix)).forEach(l -> System.out.println("[사실 " + n + "]   " + l));
        }
    }

    static String between(String s, String a, String b) {
        int i = s.indexOf(a);
        if (i < 0) return "(없음)";
        i += a.length();
        int j = s.indexOf(b, i);
        return j < 0 ? s.substring(i) : s.substring(i, j);
    }

    static String attr(String dom, String name) {
        int a = dom.indexOf(name + "=\"");
        if (a < 0) return "";
        a += name.length() + 2;
        return dom.substring(a, dom.indexOf('"', a));
    }

    static String dump(String chrome, Path profile, String url) throws Exception {
        Process p = new ProcessBuilder(chrome, "--headless=new", "--disable-gpu", "--no-first-run",
                "--user-data-dir=" + profile, "--virtual-time-budget=3000", "--dump-dom", url)
                .redirectError(ProcessBuilder.Redirect.DISCARD).start();
        byte[] out = p.getInputStream().readAllBytes();
        if (!p.waitFor(60, TimeUnit.SECONDS)) p.destroyForcibly();
        return new String(out, StandardCharsets.UTF_8);
    }

    static String findChrome() {
        String env = System.getenv("CHROME");
        if (env != null && new File(env).isFile()) return env;
        for (String c : List.of(
                "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
                System.getProperty("user.home") + "\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
                "/usr/bin/google-chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")) {
            if (new File(c).isFile()) return c;
        }
        return null;
    }
}
