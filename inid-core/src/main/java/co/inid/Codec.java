package co.inid;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.regex.Pattern;

/** Small encoding helpers that behave like the browser's (the reference SDK uses those). */
final class Codec {
    static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern SAFE_PATH = Pattern.compile("^/(?![/\\\\])");

    private Codec() {
    }

    static String b64url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static byte[] fromB64url(String text) {
        return Base64.getUrlDecoder().decode(text);
    }

    static String random(int size) {
        byte[] bytes = new byte[size];
        RANDOM.nextBytes(bytes);
        return b64url(bytes);
    }

    static String sha256(String text) {
        try {
            return b64url(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static String toJson(Object value) {
        try {
            return JSON.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    static Map<String, Object> jsonObject(byte[] bytes) throws IOException {
        return JSON.readValue(bytes, new TypeReference<LinkedHashMap<String, Object>>() {
        });
    }

    static Map<String, Object> jsonObject(String text) {
        if (text == null || text.isBlank()) return new LinkedHashMap<>();
        try {
            return jsonObject(text.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            return new LinkedHashMap<>();
        }
    }

    /** encodeURIComponent: cookie values and Basic auth parts. */
    static String component(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8)
                .replace("+", "%20").replace("%21", "!").replace("%27", "'")
                .replace("%28", "(").replace("%29", ")").replace("%7E", "~");
    }

    /** decodeURIComponent; a malformed value stays as it is. */
    static String decodeComponent(String value) {
        try {
            return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return value;
        }
    }

    /** application/x-www-form-urlencoded, like URLSearchParams. */
    static String form(Map<String, String> params) {
        StringJoiner out = new StringJoiner("&");
        params.forEach((k, v) -> out.add(URLEncoder.encode(k, StandardCharsets.UTF_8) + "=" + URLEncoder.encode(v, StandardCharsets.UTF_8)));
        return out.toString();
    }

    static String formMulti(Map<String, List<String>> params) {
        StringJoiner out = new StringJoiner("&");
        params.forEach((k, values) -> {
            for (String v : values) out.add(URLEncoder.encode(k, StandardCharsets.UTF_8) + "=" + URLEncoder.encode(v, StandardCharsets.UTF_8));
        });
        return out.toString();
    }

    static Map<String, List<String>> parseQuery(String raw) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        if (raw == null || raw.isEmpty()) return out;
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) continue;
            int at = pair.indexOf('=');
            String key = decodeForm(at < 0 ? pair : pair.substring(0, at));
            String value = at < 0 ? "" : decodeForm(pair.substring(at + 1));
            out.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
        }
        return out;
    }

    static String first(Map<String, List<String>> query, String key) {
        List<String> values = query.get(key);
        return values == null || values.isEmpty() ? null : values.get(0);
    }

    private static String decodeForm(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return value;
        }
    }

    static Map<String, String> parseCookies(String header) {
        Map<String, String> jar = new LinkedHashMap<>();
        if (header == null) return jar;
        for (String part : header.split(";\\s*")) {
            int at = part.indexOf('=');
            if (at > 0) jar.put(part.substring(0, at).trim(), decodeComponent(part.substring(at + 1)));
        }
        return jar;
    }

    static String serializeJar(Map<String, String> jar) {
        StringJoiner out = new StringJoiner("; ");
        jar.forEach((k, v) -> out.add(k + "=" + component(v)));
        return out.toString();
    }

    static String cookie(String name, String value, long maxAge, String path, boolean secure) {
        return name + "=" + component(value) + "; Path=" + path + "; Max-Age=" + maxAge + "; HttpOnly; SameSite=Lax" + (secure ? "; Secure" : "");
    }

    /** Only somewhere in the app itself: a path, never another site. */
    static String safeReturn(Object to) {
        return to instanceof String s && SAFE_PATH.matcher(s).find() ? s : "/";
    }
}
