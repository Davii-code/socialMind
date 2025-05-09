package com.socialMind.base.service.impl;

import com.auth0.jwt.interfaces.Claim;
import com.socialMind.base.config.Constants;
import com.socialMind.base.security.impl.TokenBuilder;

import java.util.Map;

public class AuthClaimResolve {

    private final Map<String, Claim> claims;

    private AuthClaimResolve(final Map<String, Claim> claims) {
        this.claims = claims;
    }

    public static AuthClaimResolve newInstance(final Map<String, Claim> claims) {
        return new AuthClaimResolve(claims);
    }

    private String getStringClaim(String key) {
        Claim claim = claims.get(key);
        return (claim != null && !claim.isNull()) ? claim.asString() : null;
    }

    private Long getLongClaim(String key) {
        Claim claim = claims.get(key);
        return (claim != null && !claim.isNull()) ? claim.asLong() : null;
    }

    public String getLogin() {
        return getStringClaim(Constants.PARAM_LOGIN);
    }

    public String getEmail() {
        return getStringClaim(Constants.PARAM_EMAIL);
    }

    public String getName() {
        return getStringClaim(Constants.PARAM_NAME);
    }

    public Long getExpiresIn() {
        return getLongClaim(Constants.PARAM_EXPIRES_IN);
    }

    public Long getRefreshExpiresIn() {
        return getLongClaim(Constants.PARAM_REFRESH_EXPIRES_IN);
    }

    public Long getUserId() {
        return getLongClaim(Constants.PARAM_USER_ID);
    }

    public TokenBuilder.TokenType getTokenType() {
        String type = getStringClaim(Constants.PARAM_TYPE);
        return (type != null) ? TokenBuilder.TokenType.valueOf(type) : null;
    }

    public boolean isTokenTypeAccess() {
        return TokenBuilder.TokenType.ACCESS.equals(getTokenType());
    }

    public boolean isTokenTypeRefresh() {
        return TokenBuilder.TokenType.REFRESH.equals(getTokenType());
    }
}
