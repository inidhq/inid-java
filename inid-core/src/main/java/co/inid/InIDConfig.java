package co.inid;

import java.util.Map;

/**
 * The app's InID settings. Anything not given comes from the environment
 * (INID_PUBLISHABLE_KEY, INID_SECRET_KEY, INID_ISSUER, INID_APP_URL, INID_WEBHOOK_SECRET).
 * Missing or malformed keys fail here, at startup, instead of on the first sign-in.
 */
public final class InIDConfig {
    public static final String DEFAULT_ISSUER = "https://id.inid.co";
    public static final String DEFAULT_API_PATH = "/api/inid";
    public static final String DEFAULT_SCOPE = "openid profile email phone";

    private final String publishableKey;
    private final String secretKey;
    private final String issuer;
    private final String apiPath;
    private final String scope;
    private final String appUrl;
    private final String webhookSecret;

    private InIDConfig(Builder b) {
        Map<String, String> env = b.env != null ? b.env : System.getenv();
        this.publishableKey = pick(b.publishableKey, env.get("INID_PUBLISHABLE_KEY"), "");
        this.secretKey = pick(b.secretKey, env.get("INID_SECRET_KEY"), "");
        this.issuer = trimSlash(pick(b.issuer, env.get("INID_ISSUER"), DEFAULT_ISSUER));
        this.apiPath = trimSlash(pick(b.apiPath, null, DEFAULT_API_PATH));
        this.scope = pick(b.scope, null, DEFAULT_SCOPE);
        String app = trimSlash(pick(b.appUrl, env.get("INID_APP_URL"), ""));
        this.appUrl = app.isEmpty() ? null : app;
        String webhook = pick(b.webhookSecret, env.get("INID_WEBHOOK_SECRET"), "");
        this.webhookSecret = webhook.isEmpty() ? null : webhook;
        if (!publishableKey.startsWith("pk_")) {
            throw new InIDException("INID_PUBLISHABLE_KEY is missing: set it to your publishable key (pk_...)");
        }
        if (!secretKey.startsWith("sk_")) {
            throw new InIDException("INID_SECRET_KEY is missing: set it to your secret key (sk_...)");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Everything from the environment. */
    public static InIDConfig fromEnv() {
        return builder().build();
    }

    public String publishableKey() { return publishableKey; }
    public String secretKey() { return secretKey; }
    public String issuer() { return issuer; }
    public String apiPath() { return apiPath; }
    public String scope() { return scope; }
    /** The app's own origin when requests don't say it (behind proxies), or null. */
    public String appUrl() { return appUrl; }
    /** Only needed to verify webhooks; null when not set. */
    public String webhookSecret() { return webhookSecret; }

    private static String pick(String given, String fromEnv, String fallback) {
        if (given != null && !given.isEmpty()) return given;
        if (fromEnv != null && !fromEnv.isEmpty()) return fromEnv;
        return fallback;
    }

    private static String trimSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    public static final class Builder {
        private String publishableKey, secretKey, issuer, apiPath, scope, appUrl, webhookSecret;
        private Map<String, String> env;

        public Builder publishableKey(String v) { publishableKey = v; return this; }
        public Builder secretKey(String v) { secretKey = v; return this; }
        public Builder issuer(String v) { issuer = v; return this; }
        public Builder apiPath(String v) { apiPath = v; return this; }
        public Builder scope(String v) { scope = v; return this; }
        public Builder appUrl(String v) { appUrl = v; return this; }
        public Builder webhookSecret(String v) { webhookSecret = v; return this; }
        /** The environment to read (defaults to System.getenv()); for tests. */
        public Builder env(Map<String, String> v) { env = v; return this; }

        public InIDConfig build() {
            return new InIDConfig(this);
        }
    }
}
