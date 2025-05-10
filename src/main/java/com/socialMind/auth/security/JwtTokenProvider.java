package com.socialMind.auth.security;

import com.socialMind.auth.domain.User;
import com.socialMind.auth.security.oauth2.UserPrincipal;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenProvider {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration}")
    private int jwtExpirationInMs;

    private Key key;

    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public String generateToken(Authentication authentication) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

        if (authentication.getPrincipal() instanceof UserPrincipal) {
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

            return Jwts.builder()
                    .setSubject(Long.toString(userPrincipal.getId()))
                    .claim("email", userPrincipal.getEmail())
                    .setIssuedAt(new Date())
                    .setExpiration(expiryDate)
                    .signWith(key)
                    .compact();
        } else if (authentication.getPrincipal() instanceof User) {
            User userPrincipal = (User) authentication.getPrincipal();

            return Jwts.builder()
                    .setSubject(Long.toString(userPrincipal.getId()))
                    .claim("email", userPrincipal.getEmail())
                    .claim("role", userPrincipal.getRole().name())
                    .setIssuedAt(new Date())
                    .setExpiration(expiryDate)
                    .signWith(key)
                    .compact();
        }

        throw new IllegalArgumentException("Tipo de usuário não suportado");
    }

    public Long getUserIdFromJWT(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException ex) {
            System.out.println("Token JWT inválido");
        } catch (ExpiredJwtException ex) {
            System.out.println("Token JWT expirado");
        } catch (UnsupportedJwtException ex) {
            System.out.println("Token JWT não suportado");
        } catch (IllegalArgumentException ex) {
            System.out.println("JWT claims string está vazia");
        }
        return false;
    }
}