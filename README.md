# JWT Security Library

This library provides basic security configuration for JWT token-based Spring Security applications.

## Features

- JWT token validation
- JWKS URL configuration
- Method-based security (@PreAuthorize, @PostAuthorize)
- Access control based on user roles and authorities

## Installation

Add the dependency to Maven:

```xml
<dependency>
    <groupId>com.thales</groupId>
    <artifactId>auth-security-lib</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Configuration

Set the JWKS URL in your `application.properties` or `application.yml` file:

```properties
jwt.security.enabled=true
jwt.security.jwks-url=https://your-auth-server/.well-known/jwks.json
```

## Using @PreAuthorize

Spring Security @PreAuthorize annotations provide method-level access control. This library automatically makes the necessary configuration for @PreAuthorize and other method-level security annotations to work.

### Example Usage

```java
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecuredController {

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminEndpoint() {
        return "This endpoint is accessible only for users with ADMIN role";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String userEndpoint() {
        return "This endpoint is accessible only for users with USER role";
    }
    
    @GetMapping("/user-or-admin")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public String userOrAdminEndpoint() {
        return "This endpoint is accessible for users with either USER or ADMIN role";
    }
}
```

### Supported SpEL Functions

Spring Expression Language (SpEL) supports the following functions:

- `hasRole('ROLE_NAME')`: Checks if the user has a specific role
- `hasAnyRole('ROLE1', 'ROLE2')`: Checks if the user has any of the specified roles
- `hasAuthority('AUTHORITY_NAME')`: Checks if the user has a specific authority
- `hasAnyAuthority('AUTH1', 'AUTH2')`: Checks if the user has any of the specified authorities
- `isAuthenticated()`: Checks if the user is authenticated
- `isAnonymous()`: Checks if the user is anonymous
- `authentication.principal`: The authenticated username or other principal information

### Recommended Practices

1. Always add method-level security checks for sensitive operations
2. Update legacy code that uses `@Secured` to use `@PreAuthorize` instead
3. Use SpEL functions to create more complex authorization rules
4. Always implement appropriate exception handling mechanisms when access is denied

## More Information

For more information, please refer to the official Spring Security documentation: [Spring Security Method Security](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#method-security) 