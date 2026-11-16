package co.inid;

import java.net.URI;

/**
 * What InID needs from an incoming request, in any framework: method, full URL (the
 * app's origin, path and query) and the Cookie header.
 */
public record InIDRequest(String method, URI url, String cookieHeader) {
    public static InIDRequest of(String method, String url, String cookieHeader) {
        return new InIDRequest(method, URI.create(url), cookieHeader);
    }

    /** The path as sent (still percent-encoded), "/" when empty. */
    public String path() {
        String p = url.getRawPath();
        return p == null || p.isEmpty() ? "/" : p;
    }
}
