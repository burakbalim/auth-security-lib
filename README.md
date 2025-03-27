# JWT Güvenlik Kütüphanesi

Bu kütüphane, JWT token temelli Spring Security uygulamaları için temel güvenlik yapılandırmasını sağlar.

## Özellikler

- JWT token doğrulama
- JWKS URL yapılandırması
- Metot tabanlı güvenlik (@PreAuthorize, @PostAuthorize)
- Kullanıcı rol ve yetkilerine göre erişim kontrolü

## Kurulum

Maven'a bağımlılık ekleyin:

```xml
<dependency>
    <groupId>com.thales</groupId>
    <artifactId>auth-security-lib</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Yapılandırma

`application.properties` veya `application.yml` dosyasında JWKS URL'yi ayarlayın:

```properties
jwt.security.enabled=true
jwt.security.jwks-url=https://your-auth-server/.well-known/jwks.json
```

## @PreAuthorize Kullanımı

Spring Security @PreAuthorize annotation'ları, metot seviyesinde erişim kontrolü sağlar. Bu kütüphane, @PreAuthorize ve diğer metot seviyesi güvenlik annotation'larının çalışması için gerekli yapılandırmayı otomatik olarak yapar.

### Örnek Kullanım

```java
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecuredController {

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminEndpoint() {
        return "Bu endpoint sadece ADMIN rolüne sahip kullanıcılar için erişilebilir";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String userEndpoint() {
        return "Bu endpoint sadece USER rolüne sahip kullanıcılar için erişilebilir";
    }
    
    @GetMapping("/user-or-admin")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public String userOrAdminEndpoint() {
        return "Bu endpoint USER veya ADMIN rolüne sahip kullanıcılar için erişilebilir";
    }
}
```

### Desteklenen SpEL Fonksiyonları

Spring Expression Language (SpEL) aşağıdaki fonksiyonları destekler:

- `hasRole('ROLE_NAME')`: Kullanıcının belirli bir role sahip olup olmadığını kontrol eder
- `hasAnyRole('ROLE1', 'ROLE2')`: Kullanıcının belirtilen rollerden herhangi birine sahip olup olmadığını kontrol eder
- `hasAuthority('AUTHORITY_NAME')`: Kullanıcının belirli bir yetkiye sahip olup olmadığını kontrol eder
- `hasAnyAuthority('AUTH1', 'AUTH2')`: Kullanıcının belirtilen yetkilerden herhangi birine sahip olup olmadığını kontrol eder
- `isAuthenticated()`: Kullanıcının kimliğinin doğrulanıp doğrulanmadığını kontrol eder
- `isAnonymous()`: Kullanıcının anonim olup olmadığını kontrol eder
- `authentication.principal`: Kimliği doğrulanmış kullanıcı adı veya diğer ana bilgiler

### Tavsiye Edilen Uygulamalar

1. Hassas işlemler için her zaman metot seviyesinde güvenlik kontrolü ekleyin
2. `@PreAuthorize` yerine `@Secured` kullanan eski kodları güncelleyin
3. SpEL fonksiyonlarını kullanarak daha karmaşık yetkilendirme kuralları oluşturun
4. Her zaman erişim reddedildiğinde uygun istisna işleme mekanizmalarını uygulayın

## Daha Fazla Bilgi

Daha fazla bilgi için lütfen resmi Spring Security dokümantasyonuna bakın: [Spring Security Method Security](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#method-security) 