package co.inid;

import java.util.List;

/**
 * The session in a request's cookies. setCookies go back to the browser (a renewed or ended
 * session); cookieHeader, when not null, is what the rest of this same request should see.
 */
public record SessionResult(InIDSession session, List<String> setCookies, String cookieHeader) {
}
