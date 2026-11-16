package co.inid;

import java.util.List;

/**
 * What the gate decided for a request. When response is set, send it as is (InID's routes, a
 * sign-in redirect, back from Google, a 403). Otherwise go on with auth, add setCookies to the
 * app's response, and use cookieHeader (when set) for the rest of the request.
 * skipped: an api-path request left for the framework's own route (routes = false).
 */
public record GateResult(InIDResponse response, InIDAuth auth, List<String> setCookies, String cookieHeader, boolean skipped) {
}
