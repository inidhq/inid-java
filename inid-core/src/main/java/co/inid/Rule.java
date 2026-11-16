package co.inid;

import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * A path that needs someone signed in and, optionally, a role or permission:
 * {@code Rule.path("/admin").role("admin")}. entrance: the door its sign-in goes through.
 * A path matches itself and its subpaths ("/admin" matches "/admin/x", not "/adminx").
 */
public final class Rule {
    private final Predicate<InIDRequest> matcher;
    private final String role;
    private final String permission;
    private final String entrance;

    private Rule(Predicate<InIDRequest> matcher, String role, String permission, String entrance) {
        this.matcher = matcher;
        this.role = role;
        this.permission = permission;
        this.entrance = entrance;
    }

    public static Rule path(String path) {
        String prefix = path.endsWith("/") ? path : path + "/";
        return new Rule(r -> r.path().equals(path) || r.path().startsWith(prefix), null, null, null);
    }

    /** A regular expression searched in the path (like JavaScript's RegExp.test). */
    public static Rule pattern(String regex) {
        return pattern(Pattern.compile(regex));
    }

    public static Rule pattern(Pattern pattern) {
        return new Rule(r -> pattern.matcher(r.path()).find(), null, null, null);
    }

    /** Any condition on the request. */
    public static Rule when(Predicate<InIDRequest> condition) {
        return new Rule(condition, null, null, null);
    }

    public Rule role(String role) {
        return new Rule(matcher, role, permission, entrance);
    }

    public Rule permission(String permission) {
        return new Rule(matcher, role, permission, entrance);
    }

    public Rule entrance(String entrance) {
        return new Rule(matcher, role, permission, entrance);
    }

    public String requiredRole() { return role; }
    public String requiredPermission() { return permission; }
    public String entranceName() { return entrance; }

    public boolean matches(InIDRequest request) {
        return matcher.test(request);
    }

    /** Signed-in people pass a rule without role or permission; otherwise they need what it asks. */
    public boolean allows(InIDUser user) {
        if (user == null) return false;
        if (role != null && !user.roles().contains(role)) return false;
        return permission == null || user.permissions().contains(permission);
    }
}
