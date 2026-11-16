package co.inid.spring;

import co.inid.InID;
import co.inid.InIDAuth;
import co.inid.InIDHttp;
import co.inid.InIDUser;
import co.inid.Rule;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = InIDFilterTest.App.class, properties = {
        "inid.publishable-key=" + InIDFilterTest.PK,
        "inid.secret-key=sk_test_secret",
        "inid.issuer=" + InIDFilterTest.ISSUER,
        "inid.protect[0].path=/dashboard",
        "inid.protect[1].path=/admin",
        "inid.protect[1].role=admin",
        "inid.protect[1].entrance=team",
        "inid.protect[2].path=/panel",
})
@AutoConfigureMockMvc
class InIDFilterTest {
    static final String PK = "pk_test_abc";
    static final String ISSUER = "https://id.test";
    static final Fake FAKE = new Fake();

    @SpringBootConfiguration
    @EnableAutoConfiguration
    @Import(Pages.class)
    static class App {
        // The real auto-configured filter, with InID faked underneath
        @Bean
        InID inid(InIDProperties properties) {
            return new InID(InIDAutoConfiguration.configOf(properties), FAKE, Clock.systemUTC());
        }

        @Bean
        InIDProtect moreRules() {
            return InIDProtect.of(Rule.pattern("^/reports/\\d+$").permission("reports:read"));
        }
    }

    @RestController
    static class Pages {
        @GetMapping("/")
        String home(InIDAuth auth) {
            return auth.isSignedIn() ? "hi " + auth.userId() : "hi";
        }

        @GetMapping("/dashboard")
        String dashboard(@CurrentInIDUser InIDUser user, HttpServletRequest request) {
            return user.id() + "|" + InIDContext.current().userId() + "|" + request.getHeader("Cookie");
        }

        @GetMapping("/admin")
        String admin() {
            return "admin";
        }

        @GetMapping("/panel")
        String panel() {
            return "panel";
        }

        @GetMapping("/reports/7")
        String report() {
            return "report";
        }

        @RequireInID(permission = "billing:read")
        @GetMapping("/billing")
        String billing() {
            return "billing";
        }
    }

    @Autowired
    MockMvc mvc;

    @BeforeEach
    void reset() {
        FAKE.token = () -> new InIDHttp.Response(400, "{\"error\":\"invalid_grant\"}");
        FAKE.calls.clear();
    }

    @Test
    void protectedPathRedirectsToSignIn() throws Exception {
        mvc.perform(get("/dashboard/x").queryParam("y", "1"))
                .andExpect(status().is(307))
                .andExpect(header().string("Location", "http://localhost/api/inid/signin?return_to=%2Fdashboard%2Fx%3Fy%3D1"));
        mvc.perform(get("/admin"))
                .andExpect(header().string("Location", "http://localhost/api/inid/signin?return_to=%2Fadmin&entrance=team"));
    }

    @Test
    void openPathsStayOpen() throws Exception {
        mvc.perform(get("/")).andExpect(status().isOk()).andExpect(content().string("hi"));
        mvc.perform(get("/").header("Cookie", "__inid_session=" + FAKE.token("user_1", 300, List.of(), List.of())))
                .andExpect(content().string("hi user_1"));
    }

    @Test
    void signedInSeesTheUser() throws Exception {
        String token = FAKE.token("user_1", 300, List.of(), List.of());
        mvc.perform(get("/dashboard").header("Cookie", "__inid_session=" + token))
                .andExpect(status().isOk())
                .andExpect(content().string("user_1|user_1|__inid_session=" + token));
    }

    @Test
    void missingRoleIs403() throws Exception {
        String cookie = "__inid_session=" + FAKE.token("user_1", 300, List.of(), List.of());
        mvc.perform(get("/admin/users").header("Cookie", cookie)).andExpect(status().isForbidden()).andExpect(content().string("Forbidden"));
        mvc.perform(get("/reports/7").header("Cookie", cookie)).andExpect(status().isForbidden());
        // A path-only rule lets any signed-in user through
        mvc.perform(get("/panel").header("Cookie", cookie)).andExpect(status().isOk()).andExpect(content().string("panel"));
        String admin = "__inid_session=" + FAKE.token("user_1", 300, List.of("admin"), List.of("reports:read"));
        mvc.perform(get("/admin").header("Cookie", admin)).andExpect(status().isOk());
        mvc.perform(get("/reports/7").header("Cookie", admin)).andExpect(status().isOk());
    }

    @Test
    void requireInIDAnnotation() throws Exception {
        mvc.perform(get("/billing")).andExpect(status().is(307))
                .andExpect(header().string("Location", "/api/inid/signin?return_to=%2Fbilling"));
        mvc.perform(get("/billing").header("Cookie", "__inid_session=" + FAKE.token("u", 300, List.of(), List.of())))
                .andExpect(status().isForbidden());
        mvc.perform(get("/billing").header("Cookie", "__inid_session=" + FAKE.token("u", 300, List.of(), List.of("billing:read"))))
                .andExpect(status().isOk()).andExpect(content().string("billing"));
    }

    @Test
    void renewsAndTheRequestSeesTheNewSession() throws Exception {
        String renewed = FAKE.token("user_1", 600, List.of(), List.of());
        FAKE.token = () -> new InIDHttp.Response(200, "{\"id_token\":\"" + renewed + "\",\"refresh_token\":\"rt_2\"}");
        MvcResult result = mvc.perform(get("/dashboard").header("Cookie", "__inid_session=" + FAKE.token("user_1", 30, List.of(), List.of()) + "; __inid_refresh=rt_1"))
                .andExpect(status().isOk())
                .andExpect(content().string("user_1|user_1|__inid_session=" + renewed + "; __inid_refresh=rt_2"))
                .andReturn();
        List<String> cookies = result.getResponse().getHeaders("Set-Cookie");
        assertThat(cookies).anyMatch(c -> c.startsWith("__inid_session=" + renewed));
        assertThat(cookies).anyMatch(c -> c.startsWith("__inid_refresh=rt_2"));
    }

    @Test
    void endedSessionGoesToSignIn() throws Exception {
        MvcResult result = mvc.perform(get("/dashboard").header("Cookie", "__inid_session=" + FAKE.token("user_1", 30, List.of(), List.of()) + "; __inid_refresh=rt_1"))
                .andExpect(status().is(307))
                .andReturn();
        assertThat(result.getResponse().getHeaders("Set-Cookie")).anyMatch(c -> c.startsWith("__inid_session=") && c.contains("Max-Age=0"));
    }

    @Test
    void sessionRoute() throws Exception {
        mvc.perform(get("/api/inid/session"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(content().json("{\"user\":null,\"accountUrl\":\"https://id.test/account?client_id=pk_test_abc\"}", true));
        MvcResult signedIn = mvc.perform(get("/api/inid/session").header("Cookie", "__inid_session=" + FAKE.token("user_1", 300, List.of("admin"), List.of())))
                .andReturn();
        Map<?, ?> user = (Map<?, ?>) new ObjectMapper().readValue(signedIn.getResponse().getContentAsString(), Map.class).get("user");
        assertThat(user.keySet().stream().map(String::valueOf).toList()).containsExactly("id", "firstName", "lastName", "name", "email", "emailVerified", "phone", "roles", "permissions", "publicMetadata");
        assertThat(user.get("roles")).isEqualTo(List.of("admin"));
    }

    @Test
    void signinAndSignoutRoutes() throws Exception {
        MvcResult signin = mvc.perform(get("/api/inid/signin").queryParam("return_to", "/dashboard"))
                .andExpect(status().isFound())
                .andReturn();
        assertThat(signin.getResponse().getHeader("Location")).startsWith(ISSUER + "/oauth/authorize?client_id=pk_test_abc&redirect_uri="
                + URLEncoder.encode("http://localhost/api/inid/callback", StandardCharsets.UTF_8));
        assertThat(signin.getResponse().getHeaders("Set-Cookie")).anyMatch(c -> c.startsWith("__inid_flow_") && !c.contains("Secure"));

        MvcResult signout = mvc.perform(post("/api/inid/signout").header("Cookie", "__inid_refresh=rt_1"))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"ok\":true}"))
                .andReturn();
        assertThat(signout.getResponse().getHeaders("Set-Cookie")).anyMatch(c -> c.startsWith("__inid_out=1"));
        assertThat(FAKE.calls).contains(ISSUER + "/oauth/revoke");

        mvc.perform(get("/api/inid/whatever")).andExpect(status().isNotFound()).andExpect(content().json("{\"error\":\"not_found\"}"));
    }

    @Test
    void backFromGoogleGoesToInID() throws Exception {
        mvc.perform(get("/").queryParam("state", "inidg_abc").queryParam("code", "z"))
                .andExpect(status().is(307))
                .andExpect(header().string("Location", ISSUER + "/oauth/google/callback?state=inidg_abc&code=z"));
    }

    /** InID in memory: a JWKS and ID tokens signed with a test RSA key. */
    static final class Fake implements InIDHttp {
        final KeyPair keys;
        final List<String> calls = new ArrayList<>();
        volatile Supplier<Response> token;

        Fake() {
            try {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                keys = gen.generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public Response send(Request request) {
            calls.add(request.url());
            if (request.url().endsWith("/.well-known/jwks.json")) {
                RSAPublicKey pub = (RSAPublicKey) keys.getPublic();
                return new Response(200, "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"n\":\"" + b64(unsigned(pub.getModulus())) + "\",\"e\":\"" + b64(unsigned(pub.getPublicExponent())) + "\"}]}");
            }
            if (request.url().endsWith("/oauth/token")) return token.get();
            return new Response(200, "{}");
        }

        String token(String sub, long expIn, List<String> roles, List<String> permissions) {
            long now = System.currentTimeMillis() / 1000;
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("iss", ISSUER);
            claims.put("aud", PK);
            claims.put("sub", sub);
            claims.put("exp", now + expIn);
            claims.put("roles", roles);
            claims.put("permissions", permissions);
            try {
                ObjectMapper json = new ObjectMapper();
                String data = b64(json.writeValueAsBytes(Map.of("alg", "RS256", "kid", "k1"))) + "." + b64(json.writeValueAsBytes(claims));
                Signature rsa = Signature.getInstance("SHA256withRSA");
                rsa.initSign(keys.getPrivate());
                rsa.update(data.getBytes(StandardCharsets.US_ASCII));
                return data + "." + b64(rsa.sign());
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        private static String b64(byte[] bytes) {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        }

        private static byte[] unsigned(BigInteger value) {
            byte[] bytes = value.toByteArray();
            return bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
        }
    }
}
