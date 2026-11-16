package co.inid;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Sign-in with InID for an app's server. The app is an OpenID Connect client of InID (its
 * publishable key is the client id, its secret key the client secret); signing in is the
 * authorization code flow with PKCE. The session is InID's signed ID token in a cookie,
 * checked with InID's public keys (never a call to InID); the refresh token renews it.
 *
 * <pre>
 *   InID inid = new InID(InIDConfig.fromEnv());
 *   GateResult gate = inid.gate(request, List.of(Rule.path("/dashboard")));
 *   if (gate.response() != null) return gate.response();   // InID's routes, a sign-in, a 403
 *   // ...the page, with gate.auth(); add gate.setCookies() to its response
 * </pre>
 */
public final class InID {
    public static final String SESSION_COOKIE = "__inid_session";
    public static final String REFRESH_COOKIE = "__inid_refresh";
    public static final String FLOW_COOKIE = "__inid_flow";
    // This browser signed out of the app: its next sign-in asks instead of going in by itself
    public static final String OUT_COOKIE = "__inid_out";

    private static final long COOKIE_MAX_AGE = 30L * 86_400;
    // A session with less than this left is renewed now, not in the middle of the next request
    private static final long RENEW_BEFORE_SECONDS = 60;
    private static final Pattern STATE = Pattern.compile("^[\\w-]{1,64}$");

    private final InIDConfig config;
    private final InIDHttp http;
    private final Clock clock;
    private final TokenVerifier verifier;
    private final String basic;
    private final InIDApi api;

    public InID(InIDConfig config) {
        this(config, InIDHttp.jdk(), Clock.systemUTC());
    }

    public InID(InIDConfig config, InIDHttp http, Clock clock) {
        this.config = config;
        this.http = http;
        this.clock = clock;
        this.verifier = new TokenVerifier(config.issuer(), config.publishableKey(), http, clock);
        this.basic = "Basic " + Base64.getEncoder().encodeToString(
                (Codec.component(config.publishableKey()) + ":" + Codec.component(config.secretKey())).getBytes(StandardCharsets.UTF_8));
        this.api = new InIDApi(config, http);
    }

    public InIDConfig config() { return config; }

    /** InID's API with the secret key: users, roles, metadata, invitations. */
    public InIDApi api() { return api; }

    // ---------- sessions ----------

    /** The session in these cookies, without renewing it. */
    public SessionResult session(String cookieHeader) {
        return session(cookieHeader, false, true);
    }

    /**
     * The session in these cookies. With refresh, one that ends within a minute is renewed:
     * setCookies go back to the browser, cookieHeader is what this same request should see.
     */
    public SessionResult session(String cookieHeader, boolean refresh, boolean secure) {
        Map<String, String> jar = Codec.parseCookies(cookieHeader);
        String token = jar.get(SESSION_COOKIE);
        TokenVerifier.Verified current = token != null && !token.isEmpty() ? verifier.verify(token, null) : null;
        long now = nowSeconds();
        if (current != null && current.exp() - now > RENEW_BEFORE_SECONDS) return new SessionResult(sessionOf(current), List.of(), null);
        InIDSession stillGood = current != null && !current.expired() ? sessionOf(current) : null;
        String refreshToken = jar.get(REFRESH_COOKIE);
        if (!refresh || refreshToken == null || refreshToken.isEmpty()) return new SessionResult(stillGood, List.of(), null);
        try {
            Map<String, Object> tokens = token(Map.of("grant_type", "refresh_token", "refresh_token", refreshToken));
            TokenVerifier.Verified renewed = verifier.verify(String.valueOf(tokens.get("id_token")), null);
            if (renewed == null) throw new InIDException("invalid_id_token", 400);
            Map<String, String> next = new LinkedHashMap<>(jar);
            next.put(SESSION_COOKIE, String.valueOf(tokens.get("id_token")));
            next.put(REFRESH_COOKIE, String.valueOf(tokens.get("refresh_token")));
            return new SessionResult(sessionOf(renewed), sessionCookies(tokens, secure), Codec.serializeJar(next));
        } catch (InIDException e) {
            // InID said no (signed out elsewhere, authorization taken back): the session is over
            if (e.status() > 0 && e.status() < 500) {
                Map<String, String> rest = new LinkedHashMap<>(jar);
                rest.remove(SESSION_COOKIE);
                rest.remove(REFRESH_COOKIE);
                return new SessionResult(null, clearCookies(secure), Codec.serializeJar(rest));
            }
            // InID couldn't be reached: what's still valid stays
            return new SessionResult(stillGood, List.of(), null);
        }
    }

    /** Who is signed in, from a Cookie header (reads the session; the gate is what renews it). */
    public InIDAuth auth(String cookieHeader) {
        return InIDAuth.of(session(cookieHeader).session());
    }

    /**
     * A native app's request to its backend: "Bearer &lt;id_token&gt;" (or the bare token). The
     * session, or null when the token isn't InID's for this app or has expired.
     */
    public InIDSession verifyBearer(String authorization) {
        if (authorization == null) return null;
        String token = authorization.regionMatches(true, 0, "Bearer ", 0, 7) ? authorization.substring(7).trim() : authorization.trim();
        if (token.isEmpty()) return null;
        TokenVerifier.Verified checked = verifier.verify(token, null);
        return checked == null || checked.expired() ? null : sessionOf(checked);
    }

    /** Webhook from InID, with the configured webhook secret. Throws invalid_signature if forged. */
    public WebhookEvent verifyWebhook(String rawBody, String signature) {
        return Webhooks.verify(config.webhookSecret(), rawBody, signature, nowSeconds());
    }

    // ---------- the gate ----------

    public GateResult gate(InIDRequest request, List<Rule> protect) {
        return gate(request, protect, true);
    }

    /**
     * What every framework's middleware does with each request. routes = false leaves the
     * api path to the framework's own route (it then calls {@link #handle}).
     */
    public GateResult gate(InIDRequest request, List<Rule> protect, boolean routes) {
        String path = request.path();
        String apiPath = config.apiPath();
        if (path.equals(apiPath) || path.startsWith(apiPath + "/")) {
            return routes
                    ? new GateResult(handle(request), InIDAuth.ANONYMOUS, List.of(), null, false)
                    : new GateResult(null, InIDAuth.ANONYMOUS, List.of(), null, true);
        }
        URI url = request.url();
        Map<String, List<String>> query = Codec.parseQuery(url.getRawQuery());
        // Back from Google on the app's own domain: Google's answer is for InID, so the person
        // goes straight on there, before any page renders
        String state = Codec.first(query, "state");
        if (state != null && state.startsWith("inidg_") && (query.containsKey("code") || query.containsKey("error"))) {
            InIDResponse to = new InIDResponse(307, "").header("Location", config.issuer() + "/oauth/google/callback?" + url.getRawQuery());
            return new GateResult(to, InIDAuth.ANONYMOUS, List.of(), null, false);
        }
        String origin = config.appUrl() != null ? config.appUrl() : originOf(url);
        boolean secure = origin.startsWith("https://");
        SessionResult result = session(request.cookieHeader(), true, secure);
        InIDSession session = result.session();
        List<Rule> rules = new ArrayList<>();
        if (protect != null) for (Rule rule : protect) if (rule.matches(request)) rules.add(rule);
        if (session == null && !rules.isEmpty()) {
            Map<String, String> to = new LinkedHashMap<>();
            to.put("return_to", path + (url.getRawQuery() != null ? "?" + url.getRawQuery() : ""));
            for (Rule rule : rules) {
                if (rule.entranceName() != null && !rule.entranceName().isEmpty()) {
                    to.put("entrance", rule.entranceName());
                    break;
                }
            }
            InIDResponse signIn = InIDResponse.redirect(307, origin + apiPath + "/signin?" + Codec.form(to), result.setCookies());
            return new GateResult(signIn, InIDAuth.ANONYMOUS, List.of(), null, false);
        }
        if (session != null) {
            for (Rule rule : rules) {
                if (!rule.allows(session.user())) {
                    // Signed in, without the role or permission the path needs
                    InIDResponse forbidden = new InIDResponse(403, "Forbidden")
                            .header("Content-Type", "text/plain; charset=utf-8")
                            .withCookies(result.setCookies());
                    return new GateResult(forbidden, InIDAuth.of(session), List.of(), null, false);
                }
            }
        }
        return new GateResult(null, InIDAuth.of(session), result.setCookies(), result.cookieHeader(), false);
    }

    // ---------- the routes under apiPath ----------

    /** The app's routes under the api path: signin, callback, signout, session, sessions. */
    public InIDResponse handle(InIDRequest request) {
        try {
            return route(request);
        } catch (InIDException e) {
            int status = e.status() >= 400 && e.status() < 500 ? 400 : 502;
            return InIDResponse.json(status, Map.of("error", e.code()));
        }
    }

    private InIDResponse route(InIDRequest request) {
        URI url = request.url();
        String apiPath = config.apiPath();
        String origin = config.appUrl() != null ? config.appUrl() : originOf(url);
        boolean secure = origin.startsWith("https://");
        String path = request.path();
        String action = path.startsWith(apiPath + "/") ? path.substring(apiPath.length() + 1) : "";
        String redirectUri = origin + apiPath + "/callback";
        String method = request.method().toUpperCase();
        Map<String, List<String>> query = Codec.parseQuery(url.getRawQuery());
        Map<String, String> jar = Codec.parseCookies(request.cookieHeader());

        if (method.equals("GET") && action.equals("signin")) {
            // display=embed: InID's form inside the app's own page
            boolean embed = "embed".equals(Codec.first(query, "display"));
            // Back from Google, the frame goes on with the same sign-in (its flow cookie stays)
            String resume = Codec.first(query, "continue");
            if (embed && resume != null) {
                Map<String, List<String>> given = Codec.parseQuery(resume);
                Map<String, String> kept = new LinkedHashMap<>();
                for (String k : List.of("request", "session", "from", "lang")) {
                    String v = Codec.first(given, k);
                    if (v != null && !v.isEmpty()) kept.put(k, v);
                }
                kept.put("display", "embed");
                return InIDResponse.redirect(302, config.issuer() + "/oauth/authorize/continue?" + Codec.form(kept), List.of());
            }
            Map<String, Object> flow = new LinkedHashMap<>();
            flow.put("state", Codec.random(16));
            flow.put("nonce", Codec.random(16));
            flow.put("verifier", Codec.random(32));
            flow.put("returnTo", Codec.safeReturn(Codec.first(query, "return_to")));
            if (embed) {
                // page: where the form is, to go on there after Google
                String page = Codec.first(query, "page");
                flow.put("embed", true);
                flow.put("page", Codec.safeReturn(page != null && !page.isEmpty() ? page : Codec.first(query, "return_to")));
            }
            Map<String, String> params = new LinkedHashMap<>();
            params.put("client_id", config.publishableKey());
            params.put("redirect_uri", redirectUri);
            params.put("response_type", "code");
            params.put("scope", config.scope());
            params.put("state", (String) flow.get("state"));
            params.put("nonce", (String) flow.get("nonce"));
            params.put("code_challenge", Codec.sha256((String) flow.get("verifier")));
            params.put("code_challenge_method", "S256");
            for (String passed : List.of("ui_locales", "login_hint", "prompt", "entrance")) {
                String v = Codec.first(query, passed);
                if (v != null && !v.isEmpty()) params.put(passed, v);
            }
            // In the page, someone InID knows still clicks to go in: never signed in by just loading it
            if (embed) {
                params.put("display", "embed");
                params.put("prompt", "login");
            }
            // Right after signing out, InID asks too: they chose to leave, so opening a page doesn't take them back in
            if (jar.containsKey(OUT_COOKIE) && !jar.get(OUT_COOKIE).isEmpty()) params.put("prompt", "login");
            // One cookie per sign-in (named by its state): two at once don't overwrite each other
            String flowCookie = Codec.cookie(FLOW_COOKIE + "_" + flow.get("state"),
                    Codec.b64url(Codec.toJson(flow).getBytes(StandardCharsets.UTF_8)), 600, apiPath, secure);
            return InIDResponse.redirect(302, config.issuer() + "/oauth/authorize?" + Codec.form(params), List.of(flowCookie));
        }

        if (method.equals("GET") && action.equals("callback")) {
            String state = Codec.first(query, "state");
            if (state == null) state = "";
            String flowName = STATE.matcher(state).matches() ? FLOW_COOKIE + "_" + state : FLOW_COOKIE;
            String clearFlow = Codec.cookie(flowName, "", 0, apiPath, secure);
            Map<String, Object> flow = null;
            try {
                String raw = jar.get(flowName);
                if (raw != null && !raw.isEmpty()) flow = Codec.jsonObject(Codec.fromB64url(raw));
            } catch (IOException | IllegalArgumentException ignored) {
                // A flow cookie we can't read is no flow
            }
            boolean embedded = flow != null && Boolean.TRUE.equals(flow.get("embed"));
            boolean stateMatches = flow != null && state.equals(flow.get("state")) && query.containsKey("state");
            // Back from Google, a sign-in that started in the app's page goes on in it
            String resume = Codec.first(query, "inid_continue");
            if (resume != null && embedded && stateMatches) {
                String page = Codec.safeReturn(flow.get("page"));
                int q = page.indexOf('?');
                String pagePath = q < 0 ? page : page.substring(0, q);
                Map<String, List<String>> pageQuery = Codec.parseQuery(q < 0 ? null : page.substring(q + 1));
                pageQuery.put("inid_continue", new ArrayList<>(List.of(resume)));
                return InIDResponse.redirect(302, pagePath + "?" + Codec.formMulti(pageQuery), List.of());
            }
            String code = Codec.first(query, "code");
            String returnTo = Codec.safeReturn(flow == null ? null : flow.get("returnTo"));
            if (flow == null || code == null || code.isEmpty() || !stateMatches) return go(embedded, returnTo, List.of(clearFlow));
            Map<String, String> exchange = new LinkedHashMap<>();
            exchange.put("grant_type", "authorization_code");
            exchange.put("code", code);
            exchange.put("redirect_uri", redirectUri);
            exchange.put("code_verifier", String.valueOf(flow.get("verifier")));
            Map<String, Object> tokens = token(exchange);
            if (verifier.verify(String.valueOf(tokens.get("id_token")), String.valueOf(flow.get("nonce"))) == null) {
                throw new InIDException("invalid_id_token", 400);
            }
            List<String> cookies = new ArrayList<>();
            cookies.add(clearFlow);
            cookies.addAll(sessionCookies(tokens, secure));
            cookies.add(Codec.cookie(OUT_COOKIE, "", 0, "/", secure));
            return go(embedded, returnTo, cookies);
        }

        if (method.equals("POST") && action.equals("signout")) {
            String refreshToken = jar.get(REFRESH_COOKIE);
            // The sign-in ends at InID too (best effort); the person's InID stays signed in
            if (refreshToken != null && !refreshToken.isEmpty()) {
                try {
                    http.send(new InIDHttp.Request("POST", config.issuer() + "/oauth/revoke", formHeaders(),
                            Codec.form(Map.of("token", refreshToken, "token_type_hint", "refresh_token")), Duration.ofSeconds(3)));
                } catch (IOException | RuntimeException ignored) {
                    // Signing out here never waits on InID
                }
            }
            List<String> cookies = new ArrayList<>(clearCookies(secure));
            cookies.add(Codec.cookie(OUT_COOKIE, "1", COOKIE_MAX_AGE, "/", secure));
            return InIDResponse.json(200, Map.of("ok", true)).withCookies(cookies);
        }

        // The person's own sessions at this app, and ending them: one or all but this one
        if (action.equals("sessions") || action.startsWith("sessions/")) {
            InIDSession current = session(request.cookieHeader()).session();
            if (current == null) return InIDResponse.json(401, Map.of("error", "not_signed_in"));
            String base = "/v1/users/" + Codec.component(current.user().id()) + "/sessions";
            Object sid = current.claims().get("sid");
            if (method.equals("GET")) {
                List<Map<String, Object>> out = new ArrayList<>();
                for (Map<String, Object> s : listSessions(base)) {
                    Map<String, Object> item = new LinkedHashMap<>(s);
                    item.put("current", s.get("id") != null && s.get("id").equals(sid));
                    out.add(item);
                }
                return InIDResponse.json(200, Map.of("sessions", out));
            }
            if (method.equals("DELETE")) {
                String one = action.startsWith("sessions/") ? Codec.decodeComponent(action.substring("sessions/".length())) : "";
                List<String> ending = new ArrayList<>();
                if (!one.isEmpty()) {
                    ending.add(one);
                } else {
                    String others = Codec.first(query, "others");
                    if (others != null && !others.isEmpty()) {
                        for (Map<String, Object> s : listSessions(base)) if (!String.valueOf(s.get("id")).equals(sid)) ending.add(String.valueOf(s.get("id")));
                    }
                }
                for (String id : ending) appCall("DELETE", base + "/" + Codec.component(id));
                return InIDResponse.json(200, Map.of("ended", ending.size()));
            }
        }

        if (method.equals("GET") && action.equals("session")) {
            SessionResult result = session(request.cookieHeader(), true, secure);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("user", result.session() == null ? null : result.session().user());
            body.put("accountUrl", config.issuer() + "/account?" + Codec.form(Map.of("client_id", config.publishableKey())));
            return InIDResponse.json(200, body).withCookies(result.setCookies());
        }

        return InIDResponse.json(404, Map.of("error", "not_found"));
    }

    // ---------- helpers ----------

    // From InID's form inside the page, the whole page goes on (not just its frame)
    private InIDResponse go(boolean embedded, String to, List<String> cookies) {
        if (!embedded) return InIDResponse.redirect(302, to, cookies);
        String target = Codec.toJson(to).replace("<", "\\u003c");
        return new InIDResponse(200, "<!doctype html><meta charset=\"utf-8\"><script>(window.top || window).location.replace(" + target + ")</script>")
                .header("Content-Type", "text/html; charset=utf-8")
                .header("Cache-Control", "no-store")
                .withCookies(cookies);
    }

    private Map<String, Object> token(Map<String, String> params) {
        InIDHttp.Response res;
        try {
            res = http.send(new InIDHttp.Request("POST", config.issuer() + "/oauth/token", formHeaders(), Codec.form(params), Duration.ofSeconds(15)));
        } catch (IOException e) {
            throw new InIDException("unreachable", 0, e);
        }
        Map<String, Object> body = Codec.jsonObject(res.body());
        if (!res.ok()) throw new InIDException(body.get("error") instanceof String s ? s : "token_failed", res.status());
        return body;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> listSessions(String base) {
        InIDHttp.Response res = appCall("GET", base);
        if (!res.ok()) throw new InIDException("sessions_unavailable", 502);
        Object list = Codec.jsonObject(res.body()).get("sessions");
        List<Map<String, Object>> out = new ArrayList<>();
        if (list instanceof List<?> items) for (Object item : items) if (item instanceof Map) out.add((Map<String, Object>) item);
        return out;
    }

    private InIDHttp.Response appCall(String method, String path) {
        try {
            return http.send(new InIDHttp.Request(method, config.issuer() + path, Map.of("Authorization", "Bearer " + config.secretKey()), null, Duration.ofSeconds(15)));
        } catch (IOException e) {
            throw new InIDException("sessions_unavailable", 502, e);
        }
    }

    private Map<String, String> formHeaders() {
        return Map.of("Content-Type", "application/x-www-form-urlencoded", "Authorization", basic);
    }

    private static InIDSession sessionOf(TokenVerifier.Verified checked) {
        return new InIDSession(InIDUser.of(checked.claims()), checked.exp(), checked.claims());
    }

    private static List<String> sessionCookies(Map<String, Object> tokens, boolean secure) {
        return List.of(
                Codec.cookie(SESSION_COOKIE, String.valueOf(tokens.get("id_token")), COOKIE_MAX_AGE, "/", secure),
                Codec.cookie(REFRESH_COOKIE, String.valueOf(tokens.get("refresh_token")), COOKIE_MAX_AGE, "/", secure));
    }

    private static List<String> clearCookies(boolean secure) {
        return List.of(Codec.cookie(SESSION_COOKIE, "", 0, "/", secure), Codec.cookie(REFRESH_COOKIE, "", 0, "/", secure));
    }

    private long nowSeconds() {
        return clock.millis() / 1000;
    }

    static String originOf(URI url) {
        String scheme = url.getScheme() == null ? "http" : url.getScheme().toLowerCase();
        int port = url.getPort();
        boolean defaultPort = port == -1 || (scheme.equals("http") && port == 80) || (scheme.equals("https") && port == 443);
        return scheme + "://" + url.getHost() + (defaultPort ? "" : ":" + port);
    }
}
