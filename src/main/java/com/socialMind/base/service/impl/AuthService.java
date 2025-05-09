package com.socialMind.base.service.impl;

import com.socialMind.base.config.Constants;
import com.socialMind.base.dto.AuthDTO;
import com.socialMind.base.dto.CredentialDTO;
import com.socialMind.base.enums.ApiErrorEnum;
import com.socialMind.base.security.impl.KeyToken;
import com.socialMind.base.security.impl.TokenBuilder;
import com.socialMind.base.service.IUserProviderService;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private IUserProviderService userProviderService;

    @Value("${api.security.jwt.token-expire-in:600}")
    private Long tokenExpireIn;

    @Value("${api.security.jwt.token-refresh-in:600}")
    private Long tokenRefreshExpireIn;

    @Autowired
    private KeyToken keyToken;

    public CredentialDTO login(AuthDTO authDTO) {
        validateFields(authDTO);
        CredentialDTO credential = fetchAndValidateCredential(authDTO);
        return generateTokens(credential);
    }

    public CredentialDTO refresh(final String refreshToken) {
        AuthClaimResolve resolve = extractClaims(refreshToken);
        validateTokenType(resolve, true);
        CredentialDTO credential = buildCredential(resolve);
        return generateTokens(credential);
    }

    public void logout(final String token) {
        try {
            CredentialDTO credential = getInfoByToken(token);
            userProviderService.recordLog(credential, Constants.ACTION_LOGOUT);
        } catch (Exception ignored) {}
        SecurityContextHolder.clearContext();
    }

    public CredentialDTO getInfoByToken(final String token) {
        AuthClaimResolve resolve = extractClaims(token);
        validateTokenType(resolve, false);
        return buildCredential(resolve);
    }

    private void validateFields(final AuthDTO authDTO) {
        if (Strings.isEmpty(authDTO.getLogin()) || Strings.isEmpty(authDTO.getPassword())) {
            throw new SecurityException(String.valueOf(ApiErrorEnum.LOGIN_INVALID));
        }
    }

    private CredentialDTO fetchAndValidateCredential(AuthDTO authDTO) {
        CredentialDTO credential = userProviderService.getCredentialByLogin(authDTO.getLogin());
        if (credential == null || !credential.isActiveState() || !UserPasswordService.loginByPassword(authDTO, credential)) {
            throw new SecurityException(String.valueOf(ApiErrorEnum.USER_PASSWORD_NOT_MATCH));
        }
        return credential;
    }

    private CredentialDTO generateTokens(CredentialDTO credential) {
        TokenBuilder builder = new TokenBuilder(keyToken);
        populateTokenBuilder(builder, credential);

        credential.setAccessToken(builder.buildAccess(tokenExpireIn).getToken());
        credential.setExpiresIn(tokenExpireIn);
        credential.setRefreshToken(builder.buildRefresh(tokenRefreshExpireIn).getToken());
        credential.setRoles(Optional.ofNullable(credential.getRoles()).orElse(Collections.emptyList()));

        registerCredentialInSecurityContext(credential);
        credential.setPassword(null);
        userProviderService.recordLog(credential, Constants.ACTION_LOGIN);
        return credential;
    }

    private void populateTokenBuilder(TokenBuilder builder, CredentialDTO credential) {
        builder.addName(credential.getName())
                .addLogin(credential.getLogin())
                .addParam(Constants.PARAM_EMAIL, credential.getEmail())
                .addParam(Constants.PARAM_USER_ID, credential.getId())
                .addParam(Constants.PARAM_EXPIRES_IN, tokenExpireIn)
                .addParam(Constants.PARAM_REFRESH_EXPIRES_IN, tokenRefreshExpireIn);
    }

    private AuthClaimResolve extractClaims(final String token) {
        return AuthClaimResolve.newInstance(new TokenBuilder(keyToken).getClaims(getAccessToken(token)));
    }

    private void validateTokenType(AuthClaimResolve resolve, boolean isRefresh) {
        if ((isRefresh && !resolve.isTokenTypeRefresh()) || (!isRefresh && !resolve.isTokenTypeAccess())) {
            throw new SecurityException(String.valueOf(ApiErrorEnum.INVALID_TOKEN));
        }
    }

    private CredentialDTO buildCredential(AuthClaimResolve resolve) {
        return CredentialDTO.builder()
                .id(resolve.getUserId())
                .login(resolve.getLogin())
                .email(resolve.getEmail())
                .name(resolve.getName())
                .roles(Optional.ofNullable(userProviderService.getCredentialByLogin(resolve.getLogin()))
                        .map(CredentialDTO::getRoles)
                        .orElse(Collections.emptyList()))
                .password(null)
                .build();
    }

    private void registerCredentialInSecurityContext(CredentialDTO credential) {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(credential.getLogin(), credential)
        );
    }

    private String getAccessToken(final String value) {
        return Strings.isEmpty(value) ? null : value.replaceAll(Constants.HEADER_AUTHORIZATION_BEARER, "").trim();
    }
}

