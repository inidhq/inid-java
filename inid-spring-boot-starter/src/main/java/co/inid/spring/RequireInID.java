package co.inid.spring;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * A controller (or one of its methods) that needs someone signed in and, optionally, a role
 * or permission: {@code @RequireInID(role = "admin")}. Signed out: GET goes to sign in, other
 * methods get 401; without the role or permission: 403.
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequireInID {
    String role() default "";

    String permission() default "";
}
