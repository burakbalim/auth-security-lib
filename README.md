# Auth Security Library

A library that provides JWT token validation and placing user information in a thread-safe context.

## Features

- JWT token validation (with RSA public key)
- Automatic public key management from JWKS endpoint
- Extraction of user information from JWT token
- Storing user information in a thread-safe context
- Auto-configuration for Spring Boot applications

## Installation

Add the following dependency to your Maven project's `pom.xml` file:

```xml
<dependency>
    <groupId>com.thales</groupId>
    <artifactId>auth-security-lib</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

## Configuration

You must add the following settings to your application's `application.yml` or `application.properties` file:

```yaml
jwt:
  security:
    enabled: true  # Default is true
    jwks-url: "https://your-jwks-endpoint-url/jwks"  # REQUIRED: JWKS endpoint URL
```

**Note:** The `jwks-url` property is mandatory. The application won't work properly without it.

### Example Configuration for Word-Flashy Service

```properties
# JWT security settings
jwt.security.enabled=true
jwt.security.jwks-url=https://apigw.staging.wordflashy.com/gw/oauth2/jwks
```

## Usage

### Using JwtSecurityContext

You can access user information from the JWT token from any Spring component:

```java
import com.thales.security.context.JwtSecurityContext;
import com.thales.security.model.JwtUserClaims;

@Service
public class YourService {

    public void someMethod() {
        // Access current user information
        JwtUserClaims currentUser = JwtSecurityContext.getCurrentUser();
        
        if (currentUser != null) {
            String userId = currentUser.getUserId();
            String username = currentUser.getUsername();
            List<String> roles = currentUser.getRoles();
            
            // Implement your business logic here
        }
    }
}
```

### About JWKS (JSON Web Key Set)

The library uses public keys from the JWKS endpoint to validate JWT tokens. These public keys are managed automatically:

- Keys are retrieved from the JWKS endpoint at application startup
- Keys are automatically refreshed at intervals (every 12 hours)
- If no public key is found for a key ID (kid), the keys are refreshed immediately

### Customization

If you want to change the default behavior, you can define your own `SecurityFilterChain` bean:

```java
@Configuration
public class YourSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}
```

## Version History

- 0.0.1-SNAPSHOT: Initial version

## License

This project is licensed under the [MIT License](LICENSE). 