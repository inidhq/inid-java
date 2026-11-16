# InID for Java and Spring Boot

Sign in with InID from a Java server. The browser components (`@inid/js`, `@inid/react`) work unchanged: this SDK answers the same routes under `/api/inid`.

- `inid-core`: any Java 17+ server. Its only dependency is `jackson-databind`.
- `inid-spring-boot-starter`: Spring Boot 3. It auto-configures the filter, the protect rules, the `InIDAuth` parameter, `@CurrentInIDUser` and `@RequireInID`.

## Install

```xml
<dependency>
  <groupId>co.inid</groupId>
  <artifactId>inid-spring-boot-starter</artifactId>
  <version>0.1.0</version>
</dependency>
```

Not using Spring? Use `inid-core` instead.

## Spring Boot

`application.yml`:

```yaml
inid:
  publishable-key: ${INID_PUBLISHABLE_KEY}   # pk_test_... / pk_live_...
  secret-key: ${INID_SECRET_KEY}             # sk_...
  # issuer: https://id.inid.co               # default
  # app-url: https://shop.example.com        # behind a proxy that hides the origin
  # webhook-secret: ${INID_WEBHOOK_SECRET}   # only to verify webhooks
  protect:
    - path: /dashboard                       # /dashboard and everything under it
    - path: /admin
      role: admin
      entrance: team                         # the door its sign-in goes through
    - pattern: ^/reports/\d+$
      permission: reports:read
```

If you leave these settings out, Spring's relaxed binding also reads the `INID_PUBLISHABLE_KEY`, `INID_SECRET_KEY`, `INID_ISSUER`, `INID_APP_URL` and `INID_WEBHOOK_SECRET` environment variables. Missing or malformed keys fail at startup.

A controller:

```java
import co.inid.InID;
import co.inid.InIDAuth;
import co.inid.InIDUser;
import co.inid.WebhookEvent;
import co.inid.spring.CurrentInIDUser;
import co.inid.spring.RequireInID;
import org.springframework.web.bind.annotation.*;

@RestController
class AccountController {
    private final InID inid;

    AccountController(InID inid) {
        this.inid = inid;
    }

    @GetMapping("/dashboard")
    String dashboard(@CurrentInIDUser InIDUser user) {      // protected in application.yml
        return "Hello " + user.name();
    }

    @GetMapping("/")
    String home(InIDAuth auth) {                             // any page: who is signed in, if anyone
        return auth.isSignedIn() ? "Hi " + auth.userId() : "Hi";
    }

    @RequireInID(role = "admin")                             // signed out: sign in (GET) or 401; no role: 403
    @PostMapping("/admin/users/{id}/role")
    void makeAdmin(@PathVariable String id) {
        inid.api().setRole(id, "admin");                     // the app API, with the secret key
    }

    @PostMapping("/webhooks/inid")
    void webhook(@RequestBody String body, @RequestHeader("InID-Signature") String signature) {
        WebhookEvent event = inid.verifyWebhook(body, signature);   // throws if forged or too old
        switch (event.type()) {
            case "user.deleted" -> { /* delete event.sub() */ }
            case "session.ended" -> { /* end event.sid() */ }
            default -> { }
        }
    }

    // A native app's request to your API, with the ID token as a bearer
    @GetMapping("/api/me")
    String me(@RequestHeader(value = "Authorization", required = false) String authorization) {
        var session = inid.verifyBearer(authorization);       // null if not InID's, not for this app, or expired
        if (session == null) throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.UNAUTHORIZED);
        return session.user().id();
    }
}
```

Anywhere in the request, `InIDContext.current()` returns the `InIDAuth`. It is also the request attribute `InIDContext.ATTRIBUTE`.

`auth.has("admin", null)`, `auth.has(null, "invoices:read")` and `auth.has("admin", "invoices:read")` check roles and permissions. With both given, both must hold. A signed-out user never has anything. A signed-in user asked for neither gets true.

You can also write the rules in code, and they are added to the ones in `application.yml`:

```java
@Bean
InIDProtect protect() {
    return InIDProtect.of(Rule.path("/billing").permission("billing:read"),
                          Rule.when(request -> request.path().startsWith("/beta")));
}
```

To sign people in from your pages, use the browser component:

```html
<script src="https://cdn.jsdelivr.net/npm/@inid/js@0.1/dist/inid.global.js"></script>
<inid-sign-in></inid-sign-in>
```

What the filter does on each request:

1. It answers `GET /api/inid/signin`, `/callback`, `/session`, `POST /signout` and `/sessions`.
2. It renews a session that is about to expire, and the rest of the same request sees the renewed cookies.
3. It applies the protect rules. Signed out, the person goes to sign in. Signed in without the role or permission, they get a 403.

It runs before Spring Security.

## Any other Java server (`inid-core`)

```java
InID inid = new InID(InIDConfig.fromEnv());
List<Rule> rules = List.of(Rule.path("/dashboard"), Rule.path("/admin").role("admin"));

// For each request
GateResult gate = inid.gate(InIDRequest.of(method, fullUrl, cookieHeader), rules);
if (gate.response() != null) {
    // InID's routes, a sign-in redirect, a 403: send gate.response() as is
    // (status, headers(), body())
} else {
    // gate.auth() is who is signed in; add gate.setCookies() to your response as Set-Cookie
}
```

`InIDConfig.builder()` overrides any setting. `new InID(config, http, clock)` takes your own HTTP transport (`InIDHttp`) and clock.

## Tests

```sh
docker run --rm -v "$PWD":/app -v inid-m2:/root/.m2 -w /app maven:3.9-eclipse-temurin-21 mvn -q -B test
```

## License

MIT
