package com.socialMind.base.security.impl;


import com.doc.easyschedulefeedback.base.dto.CredentialDTO;
import com.doc.easyschedulefeedback.base.security.Credential;
import com.doc.easyschedulefeedback.base.security.IAuthenticationProvider;
import com.doc.easyschedulefeedback.base.service.impl.AuthService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationProvider implements IAuthenticationProvider {

    private final Log logger = LogFactory.getLog(getClass());

    @Autowired
    private AuthService authService;

    @Override
    public Credential getAuthentication(final String accessToken) {
        CredentialDTO credentialDTO;

        try {
            credentialDTO = authService.getInfoByToken(accessToken);
        } catch (SecurityException e) {
            logger.error("Acesso negado.", e);
            throw e;
        }
        return credentialDTO;
    }
}
