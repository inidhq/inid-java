package co.inid;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/** InID's API for the app's server, with the secret key (see docs/api.md). */
public final class InIDApi {
    private final InIDConfig config;
    private final InIDHttp http;

    InIDApi(InIDConfig config, InIDHttp http) {
        this.config = config;
        this.http = http;
    }

    /** GET /v1/users/{sub}: their data, role and private metadata. */
    public JsonNode user(String sub) {
        return call("GET", "/v1/users/" + Codec.component(sub), null);
    }

    /** PUT /v1/users/{sub}/role; null goes back to the role new users get. */
    public JsonNode setRole(String sub, String role) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("role", role);
        return call("PUT", "/v1/users/" + Codec.component(sub) + "/role", body);
    }

    /** PATCH /v1/users/{sub}/metadata; each one given replaces the previous (null leaves it). */
    public JsonNode updateMetadata(String sub, Map<String, ?> publicMetadata, Map<String, ?> privateMetadata) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (publicMetadata != null) body.put("publicMetadata", publicMetadata);
        if (privateMetadata != null) body.put("privateMetadata", privateMetadata);
        return call("PATCH", "/v1/users/" + Codec.component(sub) + "/metadata", body);
    }

    /** GET /v1/roles: the app's roles, default role and entrances. */
    public JsonNode roles() {
        return call("GET", "/v1/roles", null);
    }

    /** POST /v1/invitations: someone may come in with that confirmed email (role optional). */
    public JsonNode invite(String email, String role) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", email);
        if (role != null) body.put("role", role);
        return call("POST", "/v1/invitations", body);
    }

    /** GET /v1/users/{sub}/sessions */
    public JsonNode sessions(String sub) {
        return call("GET", "/v1/users/" + Codec.component(sub) + "/sessions", null);
    }

    /** DELETE /v1/users/{sub}/sessions/{sid}, or all of them with sid null. */
    public JsonNode endSessions(String sub, String sid) {
        return call("DELETE", "/v1/users/" + Codec.component(sub) + "/sessions" + (sid == null ? "" : "/" + Codec.component(sid)), null);
    }

    /** Any other call to InID's API with the secret key; body is serialized as JSON. */
    public JsonNode call(String method, String path, Object body) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Bearer " + config.secretKey());
        if (body != null) headers.put("Content-Type", "application/json");
        InIDHttp.Response res;
        try {
            res = http.send(new InIDHttp.Request(method, config.issuer() + path, headers, body == null ? null : Codec.toJson(body), Duration.ofSeconds(15)));
        } catch (IOException e) {
            throw new InIDException("unreachable", 0, e);
        }
        JsonNode json;
        try {
            json = res.body() == null || res.body().isBlank() ? Codec.JSON.createObjectNode() : Codec.JSON.readTree(res.body());
        } catch (IOException e) {
            json = Codec.JSON.createObjectNode();
        }
        if (!res.ok()) {
            JsonNode error = json.get("error");
            throw new InIDException(error != null && error.isTextual() ? error.asText() : "request_failed", res.status());
        }
        return json;
    }
}
