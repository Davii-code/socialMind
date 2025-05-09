package com.socialMind.base.security;

public interface IAuthenticationProvider {
    Credential getAuthentication(final String token);
}
