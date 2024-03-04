package storysphere.auth_server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration
public class CustomClaimsConfiguration {

    @Value("${token.settings.issuer}")
    private String tokenIssuer;

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {

                context.getClaims().issuer(tokenIssuer);

                var authorities = context.getPrincipal().getAuthorities();
                context.getClaims().claim(
                        "authorities",
                        authorities.stream().map(GrantedAuthority::getAuthority).toList()
                );
            }
        };
    }

}
