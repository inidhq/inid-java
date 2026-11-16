package co.inid;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * An answer InID's routes or the gate give, for the framework to send as is: status,
 * headers (Set-Cookie may repeat) and a text body (empty for redirects).
 */
public final class InIDResponse {
    private final int status;
    private final List<Map.Entry<String, String>> headers = new ArrayList<>();
    private final String body;

    public InIDResponse(int status, String body) {
        this.status = status;
        this.body = body == null ? "" : body;
    }

    static InIDResponse redirect(int status, String location, List<String> cookies) {
        return new InIDResponse(status, "").header("Location", location).header("Cache-Control", "no-store").withCookies(cookies);
    }

    static InIDResponse json(int status, Object body) {
        return new InIDResponse(status, Codec.toJson(body))
                .header("Content-Type", "application/json")
                .header("Cache-Control", "no-store");
    }

    InIDResponse header(String name, String value) {
        headers.add(new AbstractMap.SimpleImmutableEntry<>(name, value));
        return this;
    }

    InIDResponse withCookies(List<String> cookies) {
        for (String c : cookies) header("Set-Cookie", c);
        return this;
    }

    public int status() { return status; }
    public String body() { return body; }

    /** Every header in order; Set-Cookie can appear several times. */
    public List<Map.Entry<String, String>> headers() {
        return Collections.unmodifiableList(headers);
    }

    /** The first value of a header (case-insensitive), or null. */
    public String header(String name) {
        for (Map.Entry<String, String> h : headers) if (h.getKey().equalsIgnoreCase(name)) return h.getValue();
        return null;
    }

    public List<String> headers(String name) {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, String> h : headers) if (h.getKey().equalsIgnoreCase(name)) out.add(h.getValue());
        return out;
    }

    public List<String> setCookies() {
        return headers("Set-Cookie");
    }
}
