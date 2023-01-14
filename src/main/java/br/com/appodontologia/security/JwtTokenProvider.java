package br.com.appodontologia.security;

import br.com.appodontologia.configuration.EnvironmentConfiguration;
import br.com.appodontologia.util.Constants;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;

import static br.com.appodontologia.exception.ExceptionResolver.getRootException;
import static java.util.stream.Collectors.joining;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {
    private SecretKey secretKey;
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    private final EnvironmentConfiguration env;

    @PostConstruct
    public void init() {
        var secret = Base64.getEncoder().encodeToString(env.getJwtSecret().getBytes());
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(Authentication authentication) {
        String username = authentication.getName();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Claims claims = Jwts.claims().setSubject(username);

        if (!authorities.isEmpty()) {
            claims.put(Constants.FIELD_AUTHORITIES, authorities.stream().map(GrantedAuthority::getAuthority).collect(joining(",")));
        }

        Date now = new Date();
        Date validity = new Date(now.getTime() + env.getJwtTimeExpiration());
        String token = Jwts.builder().setClaims(claims).setIssuedAt(now).setExpiration(validity).signWith(this.secretKey, SignatureAlgorithm.HS512).compact();

        return Constants.FIELD_BEARER + token;
    }

    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(Constants.FIELD_BEARER)) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(this.secretKey).build().parseClaimsJws(token).getBody();
        Object authoritiesClaim = claims.get(Constants.FIELD_AUTHORITIES);

        Collection<? extends GrantedAuthority> authorities = authoritiesClaim == null ? AuthorityUtils.NO_AUTHORITIES : AuthorityUtils.commaSeparatedStringToAuthorityList(authoritiesClaim.toString());

        User principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    public boolean validateToken(String token) throws IOException {
        try {
            Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(this.secretKey).build().parseClaimsJws(token);
            log.info("expiration date: {}", claims.getBody().getExpiration());
            return true;

        } catch (SecurityException e) {
            log.error("Assinatura JWT inválida: {}", e.getMessage());
            getRootException(HttpStatus.UNAUTHORIZED, request, response, Constants.ERROR_UNAUTHORIZED, Constants.MESSAGE_INVALID_JWT_SIGNATURE);


        } catch (MalformedJwtException e) {
            log.error("Token JWT inválido: {}", e.getMessage());
            getRootException(HttpStatus.UNAUTHORIZED, request, response, Constants.ERROR_UNAUTHORIZED, Constants.MESSAGE_INVALID_JWT_TOKEN);


        } catch (ExpiredJwtException e) {
            log.error("Token JWT expirou: {}", e.getMessage());
            getRootException(HttpStatus.UNAUTHORIZED, request, response, Constants.ERROR_UNAUTHORIZED, Constants.MESSAGE_EXPIRED_JWT_TOKEN);


        } catch (UnsupportedJwtException e) {
            log.error("Token JWT é incompatível: {}", e.getMessage());
            getRootException(HttpStatus.UNAUTHORIZED, request, response, Constants.ERROR_UNAUTHORIZED, Constants.MESSAGE_UNSUPPORTED_JWT_TOKEN);


        } catch (IllegalArgumentException e) {
            log.error("String JWT está vazia: {}", e.getMessage());
            getRootException(HttpStatus.UNAUTHORIZED, request, response, Constants.ERROR_UNAUTHORIZED, Constants.MESSAGE_EMPTY_JWT_TOKEN);

        }
        return false;
    }
}

