package co.inid;

import java.util.Map;

/**
 * A verified session: the person, when its token ends (seconds since 1970; renewed before
 * then) and the ID token's claims.
 */
public record InIDSession(InIDUser user, long expiresAt, Map<String, Object> claims) {
}
