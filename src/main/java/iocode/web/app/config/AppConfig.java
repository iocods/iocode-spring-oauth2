package iocode.web.app.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

@Configuration
public class AppConfig implements CommandLineRunner {

  private final Logger logger = LoggerFactory.getLogger(AppConfig.class);

  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails user = User.builder()
            .username("iocode")
            .roles("USER", "ADMIN")
            .password("password")
            .build();
    return new InMemoryUserDetailsManager(user);
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("client")
            .clientSecret("secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .tokenSettings(
                TokenSettings.builder()
                  .authorizationCodeTimeToLive(Duration.ofHours(12))
                  .accessTokenTimeToLive(Duration.ofHours(12))
                  .build()
            )
            .redirectUri("http://localhost:8081")
            .scope(OidcScopes.OPENID)
            .build();
    return new InMemoryRegisteredClientRepository(registeredClient);
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    logger.info("String Value of Public Key: "+publicKey.toString());
    logger.info("String Value of Private Key: "+privateKey.toString());
    RSAKey rsaKey = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
    return new ImmutableJWKSet<>(new JWKSet(rsaKey));
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder()
            .build();
  }

  @Override
  public void run(String... args) throws Exception {

    // Generating a challenge for testing
    byte[] code = new byte[32];
    new SecureRandom(code);
    var verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(code);
    logger.info("Verifier For Authorization Code: " + verifier);
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    byte[] digested = messageDigest.digest(verifier.getBytes());
    var challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digested);
    logger.info("Challenge For Authorization Code: " + challenge);
  }
}
