package co.inid;

/** Who is signed in, for a page or an API route. */
public final class InIDAuth {
    public static final InIDAuth ANONYMOUS = new InIDAuth(null);

    private final InIDSession session;

    private InIDAuth(InIDSession session) {
        this.session = session;
    }

    public static InIDAuth of(InIDSession session) {
        return session == null ? ANONYMOUS : new InIDAuth(session);
    }

    public boolean isSignedIn() { return session != null; }
    public String userId() { return session == null ? null : session.user().id(); }
    public InIDUser user() { return session == null ? null : session.user(); }
    public InIDSession session() { return session; }

    /** has("admin", null), has(null, "invoices:read"); false when signed out. */
    public boolean has(String role, String permission) {
        return session != null && session.user().has(role, permission);
    }

    public boolean hasRole(String role) { return has(role, null); }
    public boolean hasPermission(String permission) { return has(null, permission); }
}
