package co.inid.spring;

import co.inid.Rule;

import java.util.List;

/**
 * Protect rules in code, added to those in inid.protect:
 * <pre>
 *   &#64;Bean InIDProtect protect() {
 *       return InIDProtect.of(Rule.path("/dashboard"), Rule.path("/admin").role("admin"));
 *   }
 * </pre>
 */
public record InIDProtect(List<Rule> rules) {
    public static InIDProtect of(Rule... rules) {
        return new InIDProtect(List.of(rules));
    }
}
