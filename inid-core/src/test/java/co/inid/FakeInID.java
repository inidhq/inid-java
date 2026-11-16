package co.inid;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

/** InID in memory: serves a JWKS, signs ID tokens with a test RSA key, records every call. */
final class FakeInID implements InIDHttp {
    static final String ISSUER = "https://id.test";
    static final String PK = "pk_test_abc";
    static final String SK = "sk_test_secret";
    static final String KID = "k1";

    final KeyPair keys;
    final KeyPair otherKeys;
    final List<Request> requests = new ArrayList<>();
    final AtomicLong nowMillis = new AtomicLong(1_800_000_000_000L);
    int jwksCalls;
    /** What POST /oauth/token answers; null = connection refused. */
    Function<Map<String, List<String>>, Response> tokenEndpoint = form -> new Response(200, "{}");
    Response sessionsList = new Response(200, "{\"sessions\":[]}");

    FakeInID() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            keys = gen.generateKeyPair();
            otherKeys = gen.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    Clock clock() {
        return new Clock() {
            @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(java.time.ZoneId zone) { return this; }
            @Override public Instant instant() { return Instant.ofEpochMilli(nowMillis.get()); }
        };
    }

    long now() {
        return nowMillis.get() / 1000;
    }

    InIDConfig config() {
        return InIDConfig.builder().publishableKey(PK).secretKey(SK).issuer(ISSUER).webhookSecret("whsec_test").env(Map.of()).build();
    }

    InID inid() {
        return new InID(config(), this, clock());
    }

    @Override
    public Response send(Request request) throws IOException {
        requests.add(request);
        String url = request.url();
        if (url.equals(ISSUER + "/.well-known/jwks.json")) {
            jwksCalls++;
            RSAPublicKey pub = (RSAPublicKey) keys.getPublic();
            return new Response(200, Codec.toJson(Map.of("keys", List.of(Map.of(
                    "kty", "RSA", "kid", KID, "alg", "RS256", "use", "sig",
                    "n", Codec.b64url(unsigned(pub.getModulus())), "e", Codec.b64url(unsigned(pub.getPublicExponent())))))));
        }
        if (url.equals(ISSUER + "/oauth/token")) {
            Response res = tokenEndpoint.apply(Codec.parseQuery(request.body()));
            if (res == null) throw new IOException("connection refused");
            return res;
        }
        if (url.equals(ISSUER + "/oauth/revoke")) return new Response(200, "{}");
        if (url.contains("/v1/users/") && url.endsWith("/sessions") && request.method().equals("GET")) return sessionsList;
        if (url.contains("/v1/users/") && request.method().equals("DELETE")) return new Response(200, "{\"ended\":1}");
        return new Response(404, "{\"error\":\"not_found\"}");
    }

    List<Request> calls(String suffix) {
        return requests.stream().filter(r -> r.url().endsWith(suffix)).toList();
    }

    Map<String, Object> claims(String sub, long expIn) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("iss", ISSUER);
        c.put("aud", PK);
        c.put("sub", sub);
        c.put("iat", now());
        c.put("exp", now() + expIn);
        return c;
    }

    String token(Map<String, Object> claims) {
        return sign(claims, KID, keys.getPrivate());
    }

    String token(String sub, long expIn) {
        return token(claims(sub, expIn));
    }

    static String sign(Map<String, Object> claims, String kid, PrivateKey key) {
        String header = Codec.b64url(Codec.toJson(Map.of("alg", "RS256", "typ", "JWT", "kid", kid)).getBytes(StandardCharsets.UTF_8));
        String payload = Codec.b64url(Codec.toJson(claims).getBytes(StandardCharsets.UTF_8));
        try {
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(key);
            rsa.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
            return header + "." + payload + "." + Codec.b64url(rsa.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) return java.util.Arrays.copyOfRange(bytes, 1, bytes.length);
        return bytes;
    }
}
