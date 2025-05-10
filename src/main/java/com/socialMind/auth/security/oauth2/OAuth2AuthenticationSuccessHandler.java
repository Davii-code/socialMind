package com.socialMind.auth.security.oauth2;

import com.socialMind.auth.security.JwtTokenProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider tokenProvider;

    @Autowired
    public OAuth2AuthenticationSuccessHandler(JwtTokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        // Gerar o token JWT
        String token = tokenProvider.generateToken(authentication);

        // Imprimir o token no console do servidor
        System.out.println("\n\n==================================================");
        System.out.println("LOGIN OAUTH2 BEM-SUCEDIDO - TOKEN JWT:");
        System.out.println("Bearer " + token);
        System.out.println("==================================================\n\n");

        // Redirecionar para o Swagger UI
        getRedirectStrategy().sendRedirect(request, response, "/swagger-ui.html");
    }
}