package co.inid;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class InIDTest {
    static final String APP = "https://app.test";

    final FakeInID fake = new FakeInID();
    final InID inid = fake.inid();

    static InIDRequest get(String pathAndQuery, String cookie) {
        return InIDRequest.of("GET", APP + pathAndQuery, cookie);
    }

    static Map<String, List<String>> queryOf(String location) {
        return Codec.parseQuery(URI.create(location).getRawQuery());
    }

    static String q(Map<String, List<String>> query, String key) {
        return Codec.first(query, key);
    }

    /** name=value from a Set-Cookie, or null; value decoded. */
    static String cookieValue(InIDResponse res, String name) {
        for (String c : res.setCookies()) if (c.startsWith(name + "=")) return Codec.decodeComponent(c.substring(name.length() + 1, c.indexOf(';')));
        return null;
    }

    static String setCookie(InIDResponse res, String name) {
        for (String c : res.setCookies()) if (c.startsWith(name + "=")) return c;
        return null;
    }

    static String cookies(String... pairs) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < pairs.length; i += 2) out.append(i == 0 ? "" : "; ").append(pairs[i]).append('=').append(Codec.component(pairs[i + 1]));
        return out.toString();
    }

    static Map<String, Object> flowOf(InIDResponse signin) {
        String c = signin.setCookies().get(0);
        String value = c.substring(c.indexOf('=') + 1, c.indexOf(';'));
        return Codec.jsonObject(new String(Codec.fromB64url(Codec.decodeComponent(value)), StandardCharsets.UTF_8));
    }

    String flowCookieHeader(InIDResponse signin) {
        String c = signin.setCookies().get(0);
        return c.substring(0, c.indexOf(';'));
    }

    // ---------- 1. signin ----------
    @Nested
    class Signin {
        @Test
        void redirectsToAuthorizeWithEverything() {
            InIDResponse res = inid.handle(get("/api/inid/signin?return_to=%2Fdashboard%3Fx%3D1&ui_locales=es&login_hint=ana%40x.co&entrance=team", null));
            assertEquals(302, res.status());
            assertEquals("no-store", res.header("Cache-Control"));
            String location = res.header("Location");
            assertTrue(location.startsWith(FakeInID.ISSUER + "/oauth/authorize?"), location);
            Map<String, List<String>> query = queryOf(location);
            assertEquals(FakeInID.PK, q(query, "client_id"));
            assertEquals(APP + "/api/inid/callback", q(query, "redirect_uri"));
            assertEquals("code", q(query, "response_type"));
            assertEquals("openid profile email phone", q(query, "scope"));
            assertEquals("S256", q(query, "code_challenge_method"));
            assertEquals("es", q(query, "ui_locales"));
            assertEquals("ana@x.co", q(query, "login_hint"));
            assertEquals("team", q(query, "entrance"));
            assertNull(q(query, "prompt"));
            assertNull(q(query, "display"));

            Map<String, Object> flow = flowOf(res);
            assertEquals(q(query, "state"), flow.get("state"));
            assertEquals(q(query, "nonce"), flow.get("nonce"));
            assertEquals("/dashboard?x=1", flow.get("returnTo"));
            assertEquals(Codec.sha256((String) flow.get("verifier")), q(query, "code_challenge"));
            assertEquals(22, ((String) flow.get("state")).length());
            assertEquals(43, ((String) flow.get("verifier")).length());

            String cookie = res.setCookies().get(0);
            assertTrue(cookie.startsWith("__inid_flow_" + flow.get("state") + "="), cookie);
            assertTrue(cookie.contains("; Path=/api/inid; Max-Age=600; HttpOnly; SameSite=Lax; Secure"), cookie);
        }

        @Test
        void sanitizesReturnTo() {
            for (String bad : List.of("%2F%2Fevil.com", "%2F%5Cevil.com", "https%3A%2F%2Fevil.com", "evil")) {
                InIDResponse res = inid.handle(get("/api/inid/signin?return_to=" + bad, null));
                assertEquals("/", flowOf(res).get("returnTo"), bad);
            }
            assertEquals("/", flowOf(inid.handle(get("/api/inid/signin", null))).get("returnTo"));
        }

        @Test
        void asksAgainAfterSigningOut() {
            InIDResponse res = inid.handle(get("/api/inid/signin", "__inid_out=1"));
            assertEquals("login", q(queryOf(res.header("Location")), "prompt"));
        }

        @Test
        void embedAddsDisplayAndPrompt() {
            InIDResponse res = inid.handle(get("/api/inid/signin?display=embed&return_to=%2Fdashboard&page=%2Flogin", null));
            Map<String, List<String>> query = queryOf(res.header("Location"));
            assertEquals("embed", q(query, "display"));
            assertEquals("login", q(query, "prompt"));
            Map<String, Object> flow = flowOf(res);
            assertEquals(true, flow.get("embed"));
            assertEquals("/login", flow.get("page"));
            assertEquals("/dashboard", flow.get("returnTo"));
        }

        @Test
        void resumesAfterGoogleInTheFrame() {
            String cont = Codec.component("request=r1&session=s1&from=google&lang=es&evil=1");
            InIDResponse res = inid.handle(get("/api/inid/signin?display=embed&continue=" + cont, null));
            assertEquals(FakeInID.ISSUER + "/oauth/authorize/continue?request=r1&session=s1&from=google&lang=es&display=embed", res.header("Location"));
            assertTrue(res.setCookies().isEmpty());
        }

        @Test
        void plainHttpAppHasNoSecureCookies() {
            InIDResponse res = inid.handle(InIDRequest.of("GET", "http://localhost:8080/api/inid/signin", null));
            assertFalse(res.setCookies().get(0).contains("Secure"));
            assertEquals("http://localhost:8080/api/inid/callback", q(queryOf(res.header("Location")), "redirect_uri"));
        }
    }

    // ---------- 2. callback ----------
    @Nested
    class Callback {
        InIDResponse signin(String query) {
            return inid.handle(get("/api/inid/signin" + query, null));
        }

        void tokensWithNonce(String nonce) {
            fake.tokenEndpoint = form -> {
                Map<String, Object> claims = fake.claims("user_1", 600);
                claims.put("nonce", nonce);
                return new InIDHttp.Response(200, Codec.toJson(Map.of("id_token", fake.token(claims), "refresh_token", "rt_1", "access_token", "at", "expires_in", 600)));
            };
        }

        @Test
        void exchangesTheCodeAndSetsTheSession() {
            InIDResponse start = signin("?return_to=%2Fdashboard");
            Map<String, Object> flow = flowOf(start);
            tokensWithNonce((String) flow.get("nonce"));
            InIDResponse res = inid.handle(get("/api/inid/callback?code=c1&state=" + flow.get("state"), flowCookieHeader(start) + "; __inid_out=1"));
            assertEquals(302, res.status());
            assertEquals("/dashboard", res.header("Location"));

            InIDHttp.Request call = fake.calls("/oauth/token").get(0);
            String expected = "Basic " + Base64.getEncoder().encodeToString((FakeInID.PK + ":" + FakeInID.SK).getBytes(StandardCharsets.UTF_8));
            assertEquals(expected, call.headers().get("Authorization"));
            Map<String, List<String>> form = Codec.parseQuery(call.body());
            assertEquals("authorization_code", q(form, "grant_type"));
            assertEquals("c1", q(form, "code"));
            assertEquals(APP + "/api/inid/callback", q(form, "redirect_uri"));
            assertEquals(flow.get("verifier"), q(form, "code_verifier"));

            assertTrue(setCookie(res, "__inid_flow_" + flow.get("state")).contains("Path=/api/inid; Max-Age=0"));
            assertNotNull(cookieValue(res, "__inid_session"));
            assertTrue(setCookie(res, "__inid_session").contains("Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax; Secure"));
            assertEquals("rt_1", cookieValue(res, "__inid_refresh"));
            assertTrue(setCookie(res, "__inid_out").contains("Max-Age=0"));
            assertTrue(inid.auth(cookies("__inid_session", cookieValue(res, "__inid_session"))).isSignedIn());
        }

        @Test
        void wrongNonceFails() {
            InIDResponse start = signin("");
            Map<String, Object> flow = flowOf(start);
            tokensWithNonce("someone-else");
            InIDResponse res = inid.handle(get("/api/inid/callback?code=c1&state=" + flow.get("state"), flowCookieHeader(start)));
            assertEquals(400, res.status());
            assertNull(cookieValue(res, "__inid_session"));
        }

        @Test
        void stateMismatchGoesHome() {
            InIDResponse start = signin("?return_to=%2Fdashboard");
            InIDResponse res = inid.handle(get("/api/inid/callback?code=c1&state=other", flowCookieHeader(start)));
            assertEquals(302, res.status());
            assertEquals("/", res.header("Location"));
            assertTrue(setCookie(res, "__inid_flow_other").contains("Max-Age=0"));
            assertTrue(fake.calls("/oauth/token").isEmpty());
        }

        @Test
        void noCodeGoesToReturnTo() {
            InIDResponse start = signin("?return_to=%2Fdashboard");
            InIDResponse res = inid.handle(get("/api/inid/callback?error=access_denied&state=" + flowOf(start).get("state"), flowCookieHeader(start)));
            assertEquals("/dashboard", res.header("Location"));
        }

        @Test
        void embeddedFlowLeavesTheFrame() {
            InIDResponse start = signin("?display=embed&return_to=%2Fdash%3Cboard");
            Map<String, Object> flow = flowOf(start);
            tokensWithNonce((String) flow.get("nonce"));
            InIDResponse res = inid.handle(get("/api/inid/callback?code=c1&state=" + flow.get("state"), flowCookieHeader(start)));
            assertEquals(200, res.status());
            assertEquals("text/html; charset=utf-8", res.header("Content-Type"));
            assertEquals("<!doctype html><meta charset=\"utf-8\"><script>(window.top || window).location.replace(\"/dash\\u003cboard\")</script>", res.body());
            assertNotNull(cookieValue(res, "__inid_session"));
        }

        @Test
        void continuesInThePageAfterGoogle() {
            InIDResponse start = signin("?display=embed&return_to=%2Fdashboard&page=%2Flogin%3Fa%3D1");
            Map<String, Object> flow = flowOf(start);
            InIDResponse res = inid.handle(get("/api/inid/callback?inid_continue=abc&state=" + flow.get("state"), flowCookieHeader(start)));
            assertEquals(302, res.status());
            assertEquals("/login?a=1&inid_continue=abc", res.header("Location"));
        }
    }

    // ---------- 3. renewal ----------
    @Nested
    class Renewal {
        void renewsWith(String refreshToken) {
            fake.tokenEndpoint = form -> new InIDHttp.Response(200, Codec.toJson(Map.of("id_token", fake.token("user_1", 600), "refresh_token", refreshToken)));
        }

        @Test
        void freshSessionIsNotRenewed() {
            SessionResult s = inid.session(cookies("__inid_session", fake.token("user_1", 300), "__inid_refresh", "rt_1"), true, true);
            assertEquals("user_1", s.session().user().id());
            assertTrue(s.setCookies().isEmpty());
            assertTrue(fake.calls("/oauth/token").isEmpty());
        }

        @Test
        void renewsNearExpiry() {
            renewsWith("rt_2");
            SessionResult s = inid.session(cookies("__inid_session", fake.token("user_1", 30), "__inid_refresh", "rt_1", "theme", "dark"), true, true);
            assertEquals("user_1", s.session().user().id());
            assertEquals(fake.now() + 600, s.session().expiresAt());
            Map<String, List<String>> form = Codec.parseQuery(fake.calls("/oauth/token").get(0).body());
            assertEquals("refresh_token", q(form, "grant_type"));
            assertEquals("rt_1", q(form, "refresh_token"));
            assertEquals(2, s.setCookies().size());
            Map<String, String> jar = Codec.parseCookies(s.cookieHeader());
            assertEquals("rt_2", jar.get("__inid_refresh"));
            assertEquals("dark", jar.get("theme"));
            assertNotEquals(null, jar.get("__inid_session"));
        }

        @Test
        void renewsAnExpiredSession() {
            renewsWith("rt_2");
            SessionResult s = inid.session(cookies("__inid_session", fake.token("user_1", -100), "__inid_refresh", "rt_1"), true, true);
            assertNotNull(s.session());
        }

        @Test
        void withoutRefreshNothingIsAsked() {
            SessionResult s = inid.session(cookies("__inid_session", fake.token("user_1", 30), "__inid_refresh", "rt_1"));
            assertNotNull(s.session());
            assertTrue(fake.calls("/oauth/token").isEmpty());
        }

        @Test
        void fourHundredEndsTheSession() {
            fake.tokenEndpoint = form -> new InIDHttp.Response(400, "{\"error\":\"invalid_grant\"}");
            SessionResult s = inid.session(cookies("__inid_session", fake.token("user_1", 30), "__inid_refresh", "rt_1", "theme", "dark"), true, true);
            assertNull(s.session());
            assertEquals(2, s.setCookies().size());
            assertTrue(s.setCookies().stream().allMatch(c -> c.contains("Max-Age=0")));
            assertEquals("theme=dark", s.cookieHeader());
        }

        @Test
        void networkErrorKeepsAValidSession() {
            fake.tokenEndpoint = form -> null;
            SessionResult s = inid.session(cookies("__inid_session", fake.token("user_1", 30), "__inid_refresh", "rt_1"), true, true);
            assertEquals("user_1", s.session().user().id());
            assertTrue(s.setCookies().isEmpty());
        }

        @Test
        void fiveHundredKeepsAValidSession() {
            fake.tokenEndpoint = form -> new InIDHttp.Response(503, "");
            SessionResult s = inid.session(cookies("__inid_session", fake.token("user_1", 30), "__inid_refresh", "rt_1"), true, true);
            assertNotNull(s.session());
        }

        @Test
        void networkErrorDoesNotKeepAnExpiredSession() {
            fake.tokenEndpoint = form -> null;
            SessionResult s = inid.session(cookies("__inid_session", fake.token("user_1", -5), "__inid_refresh", "rt_1"), true, true);
            assertNull(s.session());
        }

        @Test
        void gateRenewsForTheSameRequest() {
            renewsWith("rt_2");
            GateResult g = inid.gate(get("/dashboard", cookies("__inid_session", fake.token("user_1", 30), "__inid_refresh", "rt_1")), List.of(Rule.path("/dashboard")));
            assertNull(g.response());
            assertTrue(g.auth().isSignedIn());
            assertEquals(2, g.setCookies().size());
            assertEquals("rt_2", Codec.parseCookies(g.cookieHeader()).get("__inid_refresh"));
        }
    }

    // ---------- 4. signout ----------
    @Test
    void signoutRevokesClearsAndRemembers() {
        InIDResponse res = inid.handle(InIDRequest.of("POST", APP + "/api/inid/signout", cookies("__inid_session", fake.token("user_1", 300), "__inid_refresh", "rt_1")));
        assertEquals(200, res.status());
        assertEquals("{\"ok\":true}", res.body());
        assertEquals("no-store", res.header("Cache-Control"));
        assertEquals("application/json", res.header("Content-Type"));
        InIDHttp.Request revoke = fake.calls("/oauth/revoke").get(0);
        Map<String, List<String>> form = Codec.parseQuery(revoke.body());
        assertEquals("rt_1", q(form, "token"));
        assertEquals("refresh_token", q(form, "token_type_hint"));
        assertTrue(revoke.headers().get("Authorization").startsWith("Basic "));
        assertTrue(setCookie(res, "__inid_session").contains("Max-Age=0"));
        assertTrue(setCookie(res, "__inid_refresh").contains("Max-Age=0"));
        assertEquals("__inid_out=1; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax; Secure", setCookie(res, "__inid_out"));
    }

    @Test
    void signoutWorksWhenInIDIsDown() {
        InID down = new InID(fake.config(), r -> { throw new java.io.IOException("down"); }, fake.clock());
        InIDResponse res = down.handle(InIDRequest.of("POST", APP + "/api/inid/signout", "__inid_refresh=rt_1"));
        assertEquals(200, res.status());
        assertEquals("1", cookieValue(res, "__inid_out"));
    }

    // ---------- 5. /session ----------
    @Test
    void sessionJsonIsCamelCase() throws Exception {
        Map<String, Object> claims = fake.claims("user_1", 300);
        claims.put("given_name", "Ana");
        claims.put("family_name", "Gómez");
        claims.put("email", "ana@x.co");
        claims.put("email_verified", true);
        claims.put("phone_number", "+573001234567");
        claims.put("roles", List.of("admin", 3));
        claims.put("permissions", List.of("invoices:read"));
        claims.put("public_metadata", Map.of("plan", "pro"));
        InIDResponse res = inid.handle(get("/api/inid/session", cookies("__inid_session", fake.token(claims))));
        assertEquals(200, res.status());
        assertEquals("no-store", res.header("Cache-Control"));
        JsonNode body = Codec.JSON.readTree(res.body());
        JsonNode user = body.get("user");
        assertEquals(List.of("id", "firstName", "lastName", "name", "email", "emailVerified", "phone", "roles", "permissions", "publicMetadata"),
                iterable(user.fieldNames()));
        assertEquals("user_1", user.get("id").asText());
        assertEquals("Ana Gómez", user.get("name").asText());
        assertTrue(user.get("emailVerified").asBoolean());
        assertEquals("+573001234567", user.get("phone").asText());
        assertEquals(1, user.get("roles").size());
        assertEquals("pro", user.get("publicMetadata").get("plan").asText());
        assertEquals(FakeInID.ISSUER + "/account?client_id=" + FakeInID.PK, body.get("accountUrl").asText());
    }

    @Test
    void sessionJsonWhenSignedOut() throws Exception {
        JsonNode body = Codec.JSON.readTree(inid.handle(get("/api/inid/session", null)).body());
        assertTrue(body.get("user").isNull());
    }

    @Test
    void userNullsAndNameFallback() {
        Map<String, Object> claims = fake.claims("u", 300);
        claims.put("name", "Only Name");
        InIDUser user = InIDUser.of(claims);
        assertNull(user.firstName());
        assertNull(user.email());
        assertFalse(user.emailVerified());
        assertEquals("Only Name", user.name());
        assertEquals(List.of(), user.roles());
        assertEquals(Map.of(), user.publicMetadata());
        assertTrue(user.has(null, null));
    }

    @Test
    void hasRoleAndPermission() {
        Map<String, Object> claims = fake.claims("u", 300);
        claims.put("roles", List.of("admin"));
        claims.put("permissions", List.of("invoices:read"));
        InIDUser user = InIDUser.of(claims);
        assertTrue(user.has("admin", null));
        assertTrue(user.has(null, "invoices:read"));
        assertTrue(user.has("admin", "invoices:read"));
        assertFalse(user.has("admin", "invoices:write"));
        assertFalse(user.has("staff", null));
        assertTrue(user.has(null, null), "signed in, nothing asked: true");
        assertFalse(InIDAuth.ANONYMOUS.has(null, null), "signed out: always false");
        assertTrue(InIDAuth.of(new InIDSession(user, 0, Map.of())).has(null, null));
    }

    @Test
    void pathOnlyRuleLetsAnySignedInUserThrough() {
        GateResult g = inid.gate(get("/panel/x", cookies("__inid_session", fake.token("user_1", 300))), List.of(Rule.path("/panel")));
        assertNull(g.response());
        assertTrue(g.auth().has(null, null));
    }

    // ---------- sessions route ----------
    @Test
    void sessionsListMarksTheCurrentOne() throws Exception {
        Map<String, Object> claims = fake.claims("user_1", 300);
        claims.put("sid", "s1");
        String cookie = cookies("__inid_session", fake.token(claims));
        fake.sessionsList = new InIDHttp.Response(200, "{\"sessions\":[{\"id\":\"s1\",\"createdAt\":\"a\",\"lastActiveAt\":\"b\",\"device\":\"Mac\"},{\"id\":\"s2\",\"createdAt\":\"a\",\"lastActiveAt\":\"b\",\"device\":null}]}");
        JsonNode body = Codec.JSON.readTree(inid.handle(get("/api/inid/sessions", cookie)).body());
        assertTrue(body.get("sessions").get(0).get("current").asBoolean());
        assertFalse(body.get("sessions").get(1).get("current").asBoolean());
        assertEquals("Bearer " + FakeInID.SK, fake.calls("/v1/users/user_1/sessions").get(0).headers().get("Authorization"));

        InIDResponse others = inid.handle(InIDRequest.of("DELETE", APP + "/api/inid/sessions?others=1", cookie));
        assertEquals("{\"ended\":1}", others.body());
        assertEquals(1, fake.calls("/v1/users/user_1/sessions/s2").size());

        InIDResponse one = inid.handle(InIDRequest.of("DELETE", APP + "/api/inid/sessions/s9", cookie));
        assertEquals("{\"ended\":1}", one.body());
        assertEquals("DELETE", fake.calls("/v1/users/user_1/sessions/s9").get(0).method());
    }

    @Test
    void sessionsNeedsSignIn() {
        InIDResponse res = inid.handle(get("/api/inid/sessions", null));
        assertEquals(401, res.status());
        assertEquals("{\"error\":\"not_signed_in\"}", res.body());
    }

    @Test
    void unknownRouteIs404() {
        InIDResponse res = inid.handle(get("/api/inid/nope", null));
        assertEquals(404, res.status());
        assertEquals("{\"error\":\"not_found\"}", res.body());
        assertEquals(404, inid.handle(InIDRequest.of("POST", APP + "/api/inid/signin", null)).status());
    }

    // ---------- 6. the gate ----------
    @Nested
    class Gate {
        final List<Rule> rules = List.of(
                Rule.path("/dashboard"),
                Rule.path("/admin").role("admin").entrance("team"),
                Rule.pattern("^/reports/\\d+$").permission("reports:read"));

        @Test
        void redirectsToSignInWithReturnTo() {
            GateResult g = inid.gate(get("/dashboard/x?y=1", null), rules);
            assertEquals(307, g.response().status());
            assertEquals(APP + "/api/inid/signin?return_to=%2Fdashboard%2Fx%3Fy%3D1", g.response().header("Location"));
            assertEquals("no-store", g.response().header("Cache-Control"));
        }

        @Test
        void addsTheEntrance() {
            GateResult g = inid.gate(get("/admin", null), rules);
            assertEquals(APP + "/api/inid/signin?return_to=%2Fadmin&entrance=team", g.response().header("Location"));
        }

        @Test
        void subpathsOnly() {
            assertNull(inid.gate(get("/dashboardx", null), rules).response());
            assertNull(inid.gate(get("/", null), rules).response());
            assertNotNull(inid.gate(get("/dashboard", null), rules).response());
            assertNotNull(inid.gate(get("/admin/users/1", null), rules).response());
        }

        @Test
        void forbidsWithoutTheRole() {
            String cookie = cookies("__inid_session", fake.token("user_1", 300));
            GateResult g = inid.gate(get("/admin/users", cookie), rules);
            assertEquals(403, g.response().status());
            assertEquals("Forbidden", g.response().body());
            assertNull(inid.gate(get("/dashboard", cookie), rules).response());
            assertEquals(403, inid.gate(get("/reports/7", cookie), rules).response().status());
        }

        @Test
        void letsInWithTheRole() {
            Map<String, Object> claims = fake.claims("user_1", 300);
            claims.put("roles", List.of("admin"));
            GateResult g = inid.gate(get("/admin", cookies("__inid_session", fake.token(claims))), rules);
            assertNull(g.response());
            assertTrue(g.auth().isSignedIn());
            assertEquals("user_1", g.auth().userId());
            assertTrue(g.auth().hasRole("admin"));
        }

        @Test
        void googleReturnGoesToInID() {
            GateResult g = inid.gate(get("/?state=inidg_abc&code=xyz&scope=email", null), rules);
            assertEquals(307, g.response().status());
            assertEquals(FakeInID.ISSUER + "/oauth/google/callback?state=inidg_abc&code=xyz&scope=email", g.response().header("Location"));
            assertNull(inid.gate(get("/?state=other&code=xyz", null), rules).response());
            assertNull(inid.gate(get("/?state=inidg_abc", null), rules).response());
        }

        @Test
        void apiPathIsAnswered() {
            GateResult g = inid.gate(get("/api/inid/session", null), rules);
            assertEquals(200, g.response().status());
            GateResult skipped = inid.gate(get("/api/inid/session", null), rules, false);
            assertTrue(skipped.skipped());
            assertNull(skipped.response());
        }

        @Test
        void appUrlWinsBehindAProxy() {
            InID proxied = new InID(InIDConfig.builder().publishableKey(FakeInID.PK).secretKey(FakeInID.SK).issuer(FakeInID.ISSUER)
                    .appUrl("https://shop.example/").env(Map.of()).build(), fake, fake.clock());
            GateResult g = proxied.gate(InIDRequest.of("GET", "http://10.0.0.1:8080/dashboard", null), rules);
            assertEquals("https://shop.example/api/inid/signin?return_to=%2Fdashboard", g.response().header("Location"));
        }
    }

    // ---------- 7. webhooks ----------
    @Nested
    class WebhooksTest {
        final String body = "{\"type\":\"session.ended\",\"sub\":\"user_1\",\"sid\":\"s1\",\"created_at\":\"2026-11-16T00:00:00Z\"}";

        @Test
        void valid() {
            WebhookEvent event = inid.verifyWebhook(body, Webhooks.sign("whsec_test", body, fake.now()));
            assertEquals("session.ended", event.type());
            assertEquals("user_1", event.sub());
            assertEquals("s1", event.sid());
            assertEquals("2026-11-16T00:00:00Z", event.createdAt());
        }

        @Test
        void wrongSecret() {
            assertSignatureRejected(Webhooks.sign("whsec_other", body, fake.now()));
        }

        @Test
        void tooOld() {
            assertSignatureRejected(Webhooks.sign("whsec_test", body, fake.now() - 301));
            assertNotNull(inid.verifyWebhook(body, Webhooks.sign("whsec_test", body, fake.now() - 299)));
        }

        @Test
        void tamperedBody() {
            String sig = Webhooks.sign("whsec_test", body, fake.now());
            assertThrows(InIDException.class, () -> inid.verifyWebhook(body.replace("s1", "s2"), sig));
        }

        @Test
        void malformedHeader() {
            String good = Webhooks.sign("whsec_test", body, fake.now());
            String v1 = good.substring(good.indexOf("v1="));
            for (String bad : new String[]{null, "", "garbage", "t=" + fake.now(), v1, "t=abc," + v1, "t=" + fake.now() + ",v1=zz"}) {
                assertSignatureRejected(bad);
            }
        }

        void assertSignatureRejected(String signature) {
            InIDException e = assertThrows(InIDException.class, () -> inid.verifyWebhook(body, signature));
            assertEquals("invalid_signature", e.code());
        }
    }

    // ---------- 8. ID token verification ----------
    @Nested
    class Verification {
        String signedIn(String token) {
            return inid.auth(cookies("__inid_session", token)).userId();
        }

        @Test
        void acceptsAGoodToken() {
            assertEquals("user_1", signedIn(fake.token("user_1", 300)));
            assertEquals("user_1", inid.verifyBearer("Bearer " + fake.token("user_1", 300)).user().id());
        }

        @Test
        void wrongAudience() {
            Map<String, Object> claims = fake.claims("user_1", 300);
            claims.put("aud", "pk_test_other");
            assertNull(signedIn(fake.token(claims)));
            assertNull(inid.verifyBearer("Bearer " + fake.token(claims)));
        }

        @Test
        void wrongIssuer() {
            Map<String, Object> claims = fake.claims("user_1", 300);
            claims.put("iss", "https://evil.test");
            assertNull(signedIn(fake.token(claims)));
        }

        @Test
        void badSignature() {
            String forged = FakeInID.sign(fake.claims("user_1", 300), FakeInID.KID, fake.otherKeys.getPrivate());
            assertNull(signedIn(forged));
            String good = fake.token("user_1", 300);
            String tampered = good.substring(0, good.lastIndexOf('.')) + ".AAAA";
            assertNull(signedIn(tampered));
        }

        @Test
        void unknownKidIsLookedUpOnce() {
            assertNotNull(signedIn(fake.token("user_1", 300)));
            assertEquals(1, fake.jwksCalls);
            String unknown = FakeInID.sign(fake.claims("user_1", 300), "k2", fake.keys.getPrivate());
            fake.nowMillis.addAndGet(5000);
            assertNull(signedIn(unknown));
            assertEquals(2, fake.jwksCalls);
            fake.nowMillis.addAndGet(5000);
            assertNull(signedIn(unknown));
            assertEquals(2, fake.jwksCalls, "a missed kid is remembered");
        }

        @Test
        void unknownKidsAtMostOnceASecond() {
            assertNotNull(signedIn(fake.token("user_1", 300)));
            fake.nowMillis.addAndGet(5000);
            assertNull(signedIn(FakeInID.sign(fake.claims("u", 300), "k2", fake.keys.getPrivate())));
            assertNull(signedIn(FakeInID.sign(fake.claims("u", 300), "k3", fake.keys.getPrivate())));
            assertEquals(2, fake.jwksCalls);
        }

        @Test
        void jwksIsKeptAnHour() {
            signedIn(fake.token("user_1", 7200));
            fake.nowMillis.addAndGet(3_000_000);
            signedIn(fake.token("user_1", 7200));
            assertEquals(1, fake.jwksCalls);
            fake.nowMillis.addAndGet(700_000);
            signedIn(fake.token("user_1", 7200));
            assertEquals(2, fake.jwksCalls);
        }

        @Test
        void expiredNeverCountsAsSignedIn() {
            String expired = fake.token("user_1", -1);
            assertNull(signedIn(expired));
            assertNull(inid.verifyBearer("Bearer " + expired));
        }

        @Test
        void otherAlgorithmsAndGarbage() {
            String good = fake.token("user_1", 300);
            String none = Codec.b64url("{\"alg\":\"none\",\"kid\":\"k1\"}".getBytes(StandardCharsets.UTF_8)) + good.substring(good.indexOf('.'));
            assertNull(signedIn(none));
            assertNull(signedIn("not-a-token"));
            assertNull(signedIn("a.b.c"));
            assertNull(inid.verifyBearer(null));
            assertNull(inid.verifyBearer("Bearer "));
        }

        @Test
        void missingSubOrExp() {
            Map<String, Object> claims = fake.claims("user_1", 300);
            claims.remove("exp");
            assertNull(signedIn(fake.token(claims)));
            Map<String, Object> noSub = fake.claims("user_1", 300);
            noSub.remove("sub");
            assertNull(signedIn(fake.token(noSub)));
        }
    }

    // ---------- configuration ----------
    @Test
    void configValidatesKeysAndReadsTheEnvironment() {
        InIDException e = assertThrows(InIDException.class, () -> InIDConfig.builder().env(Map.of()).build());
        assertTrue(e.getMessage().contains("INID_PUBLISHABLE_KEY"));
        assertThrows(InIDException.class, () -> InIDConfig.builder().env(Map.of("INID_PUBLISHABLE_KEY", "pk_x", "INID_SECRET_KEY", "nope")).build());
        InIDConfig config = InIDConfig.builder().env(Map.of("INID_PUBLISHABLE_KEY", "pk_x", "INID_SECRET_KEY", "sk_y", "INID_ISSUER", "https://id.local/", "INID_APP_URL", "https://app.local/")).build();
        assertEquals("https://id.local", config.issuer());
        assertEquals("https://app.local", config.appUrl());
        assertEquals("/api/inid", config.apiPath());
        assertEquals("openid profile email phone", config.scope());
        assertEquals(InIDConfig.DEFAULT_ISSUER, InIDConfig.builder().publishableKey("pk_a").secretKey("sk_b").env(Map.of()).build().issuer());
    }

    // ---------- the app API ----------
    @Test
    void appApiUsesTheSecretKey() {
        InIDHttp.Request[] seen = new InIDHttp.Request[1];
        InID api = new InID(fake.config(), r -> {
            seen[0] = r;
            return new InIDHttp.Response(200, "{\"ok\":true}");
        }, fake.clock());
        api.api().setRole("user 1", "admin");
        assertEquals("PUT", seen[0].method());
        assertEquals(FakeInID.ISSUER + "/v1/users/user%201/role", seen[0].url());
        assertEquals("Bearer " + FakeInID.SK, seen[0].headers().get("Authorization"));
        assertEquals("{\"role\":\"admin\"}", seen[0].body());
        InID failing = new InID(fake.config(), r -> new InIDHttp.Response(404, "{\"error\":\"user_not_found\"}"), fake.clock());
        InIDException e = assertThrows(InIDException.class, () -> failing.api().user("x"));
        assertEquals("user_not_found", e.code());
        assertEquals(404, e.status());
    }

    private static List<String> iterable(java.util.Iterator<String> it) {
        List<String> out = new java.util.ArrayList<>();
        it.forEachRemaining(out::add);
        return out;
    }
}
