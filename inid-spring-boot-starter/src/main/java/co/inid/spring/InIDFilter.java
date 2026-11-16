package co.inid.spring;

import co.inid.GateResult;
import co.inid.InID;
import co.inid.InIDRequest;
import co.inid.InIDResponse;
import co.inid.Rule;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

/**
 * InID for every request: answers the api path routes, renews the session, applies the
 * protect rules, and leaves the {@link co.inid.InIDAuth} in the request for the app.
 */
public class InIDFilter extends OncePerRequestFilter {
    private final InID inid;
    private final List<Rule> rules;

    public InIDFilter(InID inid, List<Rule> rules) {
        this.inid = inid;
        this.rules = List.copyOf(rules);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String cookieHeader = cookieHeaderOf(request);
        GateResult gate = inid.gate(new InIDRequest(request.getMethod(), urlOf(request), cookieHeader), rules);
        if (gate.response() != null) {
            write(gate.response(), response);
            return;
        }
        request.setAttribute(InIDContext.ATTRIBUTE, gate.auth());
        for (String c : gate.setCookies()) response.addHeader("Set-Cookie", c);
        // A renewed session: the rest of this request sees the new cookies too
        HttpServletRequest next = gate.cookieHeader() != null ? new RenewedCookies(request, gate.cookieHeader()) : request;
        chain.doFilter(next, response);
    }

    static void write(InIDResponse answer, HttpServletResponse response) throws IOException {
        response.setStatus(answer.status());
        for (Map.Entry<String, String> h : answer.headers()) response.addHeader(h.getKey(), h.getValue());
        byte[] body = answer.body().getBytes(StandardCharsets.UTF_8);
        if (body.length > 0) {
            response.setContentLength(body.length);
            response.getOutputStream().write(body);
        }
        response.flushBuffer();
    }

    static URI urlOf(HttpServletRequest request) {
        StringBuffer url = request.getRequestURL();
        if (request.getQueryString() != null) url.append('?').append(request.getQueryString());
        return URI.create(url.toString());
    }

    private static String cookieHeaderOf(HttpServletRequest request) {
        Enumeration<String> headers = request.getHeaders("Cookie");
        List<String> all = headers == null ? List.of() : Collections.list(headers);
        if (!all.isEmpty()) return String.join("; ", all);
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        List<String> parts = new ArrayList<>();
        for (Cookie c : cookies) parts.add(c.getName() + "=" + c.getValue());
        return String.join("; ", parts);
    }

    private static final class RenewedCookies extends HttpServletRequestWrapper {
        private final String header;

        RenewedCookies(HttpServletRequest request, String header) {
            super(request);
            this.header = header;
        }

        @Override
        public String getHeader(String name) {
            return "cookie".equalsIgnoreCase(name) ? header : super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            return "cookie".equalsIgnoreCase(name) ? Collections.enumeration(List.of(header)) : super.getHeaders(name);
        }

        @Override
        public Cookie[] getCookies() {
            List<Cookie> out = new ArrayList<>();
            for (String part : header.split(";\\s*")) {
                int at = part.indexOf('=');
                if (at <= 0) continue;
                String value = URLDecoder.decode(part.substring(at + 1).replace("+", "%2B"), StandardCharsets.UTF_8);
                try {
                    out.add(new Cookie(part.substring(0, at), value));
                } catch (IllegalArgumentException ignored) {
                    // A name the servlet API refuses stays out of getCookies()
                }
            }
            return out.toArray(new Cookie[0]);
        }
    }
}
