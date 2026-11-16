package co.inid.spring;

import co.inid.InIDAuth;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/** Who is signed in, for the current request (set by {@link InIDFilter}). */
public final class InIDContext {
    /** The request attribute holding the {@link InIDAuth}. */
    public static final String ATTRIBUTE = InIDAuth.class.getName();

    private InIDContext() {
    }

    /** The current request's auth; anonymous outside a request or before the filter ran. */
    public static InIDAuth current() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        Object auth = attributes == null ? null : attributes.getAttribute(ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        return auth instanceof InIDAuth a ? a : InIDAuth.ANONYMOUS;
    }

    public static InIDAuth of(HttpServletRequest request) {
        Object auth = request.getAttribute(ATTRIBUTE);
        return auth instanceof InIDAuth a ? a : InIDAuth.ANONYMOUS;
    }
}
