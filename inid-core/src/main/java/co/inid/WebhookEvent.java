package co.inid;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A verified webhook event. type: user.created, user.updated, user.deleted (may carry token),
 * session.created, session.ended (carries sid), subscription.cancel_requested,
 * customer.logged_out, customer.registered, checkout.abandoned.
 */
public record WebhookEvent(JsonNode json) {
    public String type() { return text("type"); }
    public String createdAt() { return text("created_at"); }
    public String sub() { return text("sub"); }
    public String token() { return text("token"); }
    public String sid() { return text("sid"); }
    public String subscription() { return text("subscription"); }

    private String text(String field) {
        JsonNode value = json.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }
}
