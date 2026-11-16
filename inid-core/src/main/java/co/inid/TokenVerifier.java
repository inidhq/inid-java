package co.inid;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Checks ID tokens with InID's public keys (JWKS), kept an hour. A key it doesn't know (InID
 * just rotated) is looked up at once, but once per key and at most once a second, so tokens
 * with made-up key ids can't make it ask InID again and again.
 */
final class TokenVerifier {
    record Verified(Map<String, Object> claims, long exp, boolean expired) {
    }

    private final String issuer;
    private final String audience;
    private final InIDHttp http;
    private final Clock clock;

    private Map<String, PublicKey> keys;
    private long fetchedAt;
    private long askedAt;
    private final Set<String> missed = new HashSet<>();

    TokenVerifier(String issuer, String audience, InIDHttp http, Clock clock) {
        this.issuer = issuer;
        this.audience = audience;
        this.http = http;
        this.clock = clock;
    }

    /** The token's claims, or null. An expired one still comes back (expired = true) so it can be renewed. */
    Verified verify(String token, String nonce) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) return null;
        try {
            Map<String, Object> header = Codec.jsonObject(Codec.fromB64url(parts[0]));
            if (!"RS256".equals(header.get("alg")) || !(header.get("kid") instanceof String kid)) return null;
            PublicKey key = keyFor(kid);
            if (key == null) return null;
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initVerify(key);
            rsa.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!rsa.verify(Codec.fromB64url(parts[2]))) return null;
            Map<String, Object> claims = Codec.jsonObject(Codec.fromB64url(parts[1]));
            if (!issuer.equals(claims.get("iss")) || !audience.equals(claims.get("aud"))) return null;
            if (!(claims.get("sub") instanceof String) || !(claims.get("exp") instanceof Number exp)) return null;
            if (nonce != null && !Objects.equals(nonce, claims.get("nonce"))) return null;
            long expSeconds = (long) Math.floor(exp.doubleValue());
            return new Verified(claims, expSeconds, expSeconds <= clock.millis() / 1000);
        } catch (InIDException e) {
            throw e;
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            return null;
        }
    }

    private synchronized PublicKey keyFor(String kid) {
        long now = clock.millis();
        boolean known = keys != null;
        if (known && now - fetchedAt < 3_600_000) {
            if (keys.containsKey(kid)) return keys.get(kid);
            if (missed.contains(kid) || now - askedAt < 1000) return null;
            missed.add(kid);
            if (missed.size() > 100) missed.clear();
        }
        // Only lookups for unknown keys count toward "once a second"
        long nextAskedAt = known ? now : 0;
        if (known) askedAt = now;
        InIDHttp.Response res;
        try {
            res = http.send(new InIDHttp.Request("GET", issuer + "/.well-known/jwks.json", Map.of(), null, Duration.ofSeconds(10)));
        } catch (IOException e) {
            throw new InIDException("jwks_unavailable", 0, e);
        }
        if (!res.ok()) throw new InIDException("jwks_unavailable", res.status());
        Map<String, PublicKey> fresh = new HashMap<>();
        Object list = Codec.jsonObject(res.body()).get("keys");
        if (list instanceof List<?> items) {
            for (Object item : items) {
                if (!(item instanceof Map<?, ?> jwk) || !"RSA".equals(jwk.get("kty")) || !(jwk.get("kid") instanceof String id)) continue;
                try {
                    BigInteger n = new BigInteger(1, Codec.fromB64url(String.valueOf(jwk.get("n"))));
                    BigInteger e = new BigInteger(1, Codec.fromB64url(String.valueOf(jwk.get("e"))));
                    fresh.put(id, KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e)));
                } catch (GeneralSecurityException | IllegalArgumentException ignored) {
                    // A key we can't read is a key we don't trust
                }
            }
        }
        keys = fresh;
        fetchedAt = now;
        askedAt = nextAskedAt;
        return keys.get(kid);
    }
}
