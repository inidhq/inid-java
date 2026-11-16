package co.inid;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * The signed-in person, from InID's ID token. Serializes to the camelCase JSON the browser
 * components read (the /session route).
 */
public record InIDUser(
        String id,
        String firstName,
        String lastName,
        String name,
        String email,
        boolean emailVerified,
        String phone,
        List<String> roles,
        List<String> permissions,
        Map<String, Object> publicMetadata) {

    @SuppressWarnings("unchecked")
    public static InIDUser of(Map<String, Object> claims) {
        String firstName = text(claims.get("given_name"));
        String lastName = text(claims.get("family_name"));
        String joined = String.join(" ", nonNull(firstName, lastName));
        Object meta = claims.get("public_metadata");
        return new InIDUser(
                String.valueOf(claims.get("sub")),
                firstName,
                lastName,
                joined.isEmpty() ? text(claims.get("name")) : joined,
                text(claims.get("email")),
                Boolean.TRUE.equals(claims.get("email_verified")),
                text(claims.get("phone_number")),
                strings(claims.get("roles")),
                strings(claims.get("permissions")),
                meta instanceof Map ? Collections.unmodifiableMap((Map<String, Object>) meta) : Map.of());
    }

    /** Whether they have the role and/or the permission (both, when both are given; true with neither). */
    public boolean has(String role, String permission) {
        if (role != null && !roles.contains(role)) return false;
        return permission == null || permissions.contains(permission);
    }

    public boolean hasRole(String role) {
        return has(role, null);
    }

    public boolean hasPermission(String permission) {
        return has(null, permission);
    }

    private static String text(Object value) {
        return value instanceof String s && !s.isEmpty() ? s : null;
    }

    private static List<String> nonNull(String... parts) {
        List<String> out = new ArrayList<>();
        for (String p : parts) if (p != null) out.add(p);
        return out;
    }

    private static List<String> strings(Object value) {
        List<String> out = new ArrayList<>();
        if (value instanceof List<?> list) for (Object item : list) if (item instanceof String s) out.add(s);
        return Collections.unmodifiableList(out);
    }
}
