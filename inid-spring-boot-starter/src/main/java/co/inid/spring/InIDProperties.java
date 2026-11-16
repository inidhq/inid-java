package co.inid.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * inid.* settings. Relaxed binding also reads INID_PUBLISHABLE_KEY, INID_SECRET_KEY,
 * INID_ISSUER, INID_APP_URL and INID_WEBHOOK_SECRET from the environment.
 */
@ConfigurationProperties(prefix = "inid")
public class InIDProperties {
    /** Publishable key (pk_test_... or pk_live_...). */
    private String publishableKey;
    /** Secret key (sk_...). */
    private String secretKey;
    /** InID itself; https://id.inid.co by default. */
    private String issuer;
    /** The app's own origin, when requests don't say it (behind proxies). */
    private String appUrl;
    /** Where InID's routes live. */
    private String apiPath = "/api/inid";
    /** What the app asks for. */
    private String scope = "openid profile email phone";
    /** Only to verify webhooks (whsec_...). */
    private String webhookSecret;
    /** Paths that need someone signed in (and maybe a role or permission). */
    private List<ProtectRule> protect = new ArrayList<>();

    public static class ProtectRule {
        /** A path; matches itself and its subpaths. */
        private String path;
        /** Or a regular expression searched in the path. */
        private String pattern;
        private String role;
        private String permission;
        /** The entrance (door) the sign-in goes through. */
        private String entrance;

        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        public String getPattern() { return pattern; }
        public void setPattern(String pattern) { this.pattern = pattern; }
        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
        public String getPermission() { return permission; }
        public void setPermission(String permission) { this.permission = permission; }
        public String getEntrance() { return entrance; }
        public void setEntrance(String entrance) { this.entrance = entrance; }
    }

    public String getPublishableKey() { return publishableKey; }
    public void setPublishableKey(String publishableKey) { this.publishableKey = publishableKey; }
    public String getSecretKey() { return secretKey; }
    public void setSecretKey(String secretKey) { this.secretKey = secretKey; }
    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    public String getAppUrl() { return appUrl; }
    public void setAppUrl(String appUrl) { this.appUrl = appUrl; }
    public String getApiPath() { return apiPath; }
    public void setApiPath(String apiPath) { this.apiPath = apiPath; }
    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }
    public String getWebhookSecret() { return webhookSecret; }
    public void setWebhookSecret(String webhookSecret) { this.webhookSecret = webhookSecret; }
    public List<ProtectRule> getProtect() { return protect; }
    public void setProtect(List<ProtectRule> protect) { this.protect = protect; }
}
