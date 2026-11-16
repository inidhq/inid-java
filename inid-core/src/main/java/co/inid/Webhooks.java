package co.inid;

import com.fasterxml.jackson.databind.JsonNode;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

/** Verifies InID's webhooks: header InID-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256>. */
public final class Webhooks {
    public static final String SIGNATURE_HEADER = "InID-Signature";
    static final long TOLERANCE_SECONDS = 300;

    private Webhooks() {
    }

    /** The body exactly as received (before any JSON parsing). Throws invalid_signature if forged. */
    public static WebhookEvent verify(String secret, String rawBody, String signature) {
        return verify(secret, rawBody, signature, System.currentTimeMillis() / 1000);
    }

    public static WebhookEvent verify(String secret, String rawBody, String signature, long nowSeconds) {
        if (secret == null || secret.isEmpty()) throw new InIDException("webhook_secret_missing");
        Map<String, String> parts = new HashMap<>();
        for (String part : String.valueOf(signature == null ? "" : signature).split(",")) {
            int at = part.indexOf('=');
            if (at > 0) parts.put(part.substring(0, at).trim(), part.substring(at + 1).trim());
        }
        long at;
        try {
            at = Long.parseLong(parts.getOrDefault("t", ""));
        } catch (NumberFormatException e) {
            throw new InIDException("invalid_signature");
        }
        String v1 = parts.get("v1");
        if (at == 0 || v1 == null || v1.isEmpty() || Math.abs(nowSeconds - at) > TOLERANCE_SECONDS) throw new InIDException("invalid_signature");
        byte[] given;
        try {
            given = HexFormat.of().parseHex(v1);
        } catch (IllegalArgumentException e) {
            throw new InIDException("invalid_signature");
        }
        String body = rawBody == null ? "" : rawBody;
        byte[] expected;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            expected = mac.doFinal((at + "." + body).getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        // Constant time: the comparison doesn't reveal how much of a forged signature was right
        if (!MessageDigest.isEqual(given, expected)) throw new InIDException("invalid_signature");
        try {
            JsonNode json = Codec.JSON.readTree(body);
            if (json == null || !json.isObject()) throw new InIDException("invalid_payload");
            return new WebhookEvent(json);
        } catch (java.io.IOException e) {
            throw new InIDException("invalid_payload");
        }
    }

    /** The header value for a body; to test your webhook endpoint. */
    public static String sign(String secret, String rawBody, long nowSeconds) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return "t=" + nowSeconds + ",v1=" + HexFormat.of().formatHex(mac.doFinal((nowSeconds + "." + rawBody).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
