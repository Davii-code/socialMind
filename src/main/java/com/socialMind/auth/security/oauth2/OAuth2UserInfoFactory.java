package com.socialMind.auth.security.oauth2;

import com.socialMind.auth.exception.BusinessException;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase("google")) {
            return new GoogleOAuth2UserInfo(attributes);
        }  else {
            throw new BusinessException("Login com " + registrationId + " não é suportado.");
        }
    }
}
