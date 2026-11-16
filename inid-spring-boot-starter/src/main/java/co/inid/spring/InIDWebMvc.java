package co.inid.spring;

import co.inid.InID;
import co.inid.InIDAuth;
import co.inid.InIDUser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** Spring MVC pieces: InIDAuth / @CurrentInIDUser parameters and @RequireInID. */
public class InIDWebMvc implements WebMvcConfigurer {
    private final InID inid;

    public InIDWebMvc(InID inid) {
        this.inid = inid;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new ArgumentResolver());
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new RequireInterceptor(inid.config().apiPath()));
    }

    static final class ArgumentResolver implements HandlerMethodArgumentResolver {
        @Override
        public boolean supportsParameter(MethodParameter parameter) {
            return parameter.getParameterType() == InIDAuth.class
                    || (parameter.hasParameterAnnotation(CurrentInIDUser.class) && parameter.getParameterType() == InIDUser.class);
        }

        @Override
        public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mav, NativeWebRequest web, WebDataBinderFactory binder) {
            HttpServletRequest request = web.getNativeRequest(HttpServletRequest.class);
            InIDAuth auth = request == null ? InIDAuth.ANONYMOUS : InIDContext.of(request);
            return parameter.getParameterType() == InIDAuth.class ? auth : auth.user();
        }
    }

    static final class RequireInterceptor implements HandlerInterceptor {
        private final String apiPath;

        RequireInterceptor(String apiPath) {
            this.apiPath = apiPath;
        }

        @Override
        public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
            if (!(handler instanceof HandlerMethod method)) return true;
            RequireInID required = AnnotatedElementUtils.findMergedAnnotation(method.getMethod(), RequireInID.class);
            if (required == null) required = AnnotatedElementUtils.findMergedAnnotation(method.getBeanType(), RequireInID.class);
            if (required == null) return true;
            InIDAuth auth = InIDContext.of(request);
            if (!auth.isSignedIn()) {
                if ("GET".equals(request.getMethod())) {
                    String back = request.getRequestURI() + (request.getQueryString() != null ? "?" + request.getQueryString() : "");
                    response.setHeader("Cache-Control", "no-store");
                    response.setStatus(307);
                    response.setHeader("Location", request.getContextPath() + apiPath + "/signin?return_to=" + URLEncoder.encode(back, StandardCharsets.UTF_8));
                } else {
                    response.setStatus(401);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"not_signed_in\"}");
                }
                return false;
            }
            String role = required.role().isEmpty() ? null : required.role();
            String permission = required.permission().isEmpty() ? null : required.permission();
            if ((role != null || permission != null) && !auth.has(role, permission)) {
                response.setStatus(403);
                response.setContentType("text/plain; charset=utf-8");
                response.getWriter().write("Forbidden");
                return false;
            }
            return true;
        }
    }
}
