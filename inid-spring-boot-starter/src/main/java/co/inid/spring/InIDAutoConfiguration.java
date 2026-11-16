package co.inid.spring;

import co.inid.InID;
import co.inid.InIDConfig;
import co.inid.Rule;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.filter.OrderedFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.ArrayList;
import java.util.List;

/** InID for Spring Boot: the InID bean from inid.* settings, its filter and MVC pieces. */
@AutoConfiguration
@EnableConfigurationProperties(InIDProperties.class)
public class InIDAutoConfiguration {
    // Before Spring Security (-100), so InID's routes and the gate come first
    public static final int FILTER_ORDER = OrderedFilter.REQUEST_WRAPPER_FILTER_MAX_ORDER - 110;

    @Bean
    @ConditionalOnMissingBean
    public InID inid(InIDProperties properties) {
        return new InID(configOf(properties));
    }

    static InIDConfig configOf(InIDProperties p) {
        return InIDConfig.builder()
                .publishableKey(p.getPublishableKey())
                .secretKey(p.getSecretKey())
                .issuer(p.getIssuer())
                .appUrl(p.getAppUrl())
                .apiPath(p.getApiPath())
                .scope(p.getScope())
                .webhookSecret(p.getWebhookSecret())
                .build();
    }

    static List<Rule> rulesOf(InIDProperties properties, ObjectProvider<InIDProtect> beans) {
        List<Rule> rules = new ArrayList<>();
        for (InIDProperties.ProtectRule r : properties.getProtect()) {
            Rule rule;
            if (r.getPattern() != null && !r.getPattern().isEmpty()) rule = Rule.pattern(r.getPattern());
            else if (r.getPath() != null && !r.getPath().isEmpty()) rule = Rule.path(r.getPath());
            else throw new IllegalArgumentException("inid.protect: each rule needs a path or a pattern");
            if (r.getRole() != null && !r.getRole().isEmpty()) rule = rule.role(r.getRole());
            if (r.getPermission() != null && !r.getPermission().isEmpty()) rule = rule.permission(r.getPermission());
            if (r.getEntrance() != null && !r.getEntrance().isEmpty()) rule = rule.entrance(r.getEntrance());
            rules.add(rule);
        }
        beans.orderedStream().forEach(p -> rules.addAll(p.rules()));
        return rules;
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    static class Servlet {
        @Bean
        @ConditionalOnMissingBean(name = "inidFilter")
        public FilterRegistrationBean<InIDFilter> inidFilter(InID inid, InIDProperties properties, ObjectProvider<InIDProtect> protect) {
            FilterRegistrationBean<InIDFilter> registration = new FilterRegistrationBean<>(new InIDFilter(inid, rulesOf(properties, protect)));
            registration.setOrder(FILTER_ORDER);
            registration.setName("inidFilter");
            return registration;
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnClass(WebMvcConfigurer.class)
    static class Mvc {
        @Bean
        public InIDWebMvc inidWebMvc(InID inid) {
            return new InIDWebMvc(inid);
        }
    }
}
