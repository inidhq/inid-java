package co.inid.spring;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Injects the signed-in {@link co.inid.InIDUser} into a controller method (null when no one
 * is signed in): {@code String me(@CurrentInIDUser InIDUser user)}. A parameter of type
 * {@link co.inid.InIDAuth} is injected without any annotation.
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CurrentInIDUser {
}
