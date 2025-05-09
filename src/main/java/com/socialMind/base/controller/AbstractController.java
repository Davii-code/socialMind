package com.socialMind.base.controller;

import com.doc.easyschedulefeedback.base.dto.CredentialDTO;
import com.doc.easyschedulefeedback.base.security.impl.CredentialProvider;

public abstract class AbstractController {

    protected CredentialDTO getCredential() {
        return (CredentialDTO) CredentialProvider.newInstance().getCurrentInstance();
    }

    protected Long getIdFromLoggedUser() {
        CredentialDTO credential = getCredential();
        return credential != null ? credential.getId() : null;
    }

    protected String getUserNameFromLoggedUser() {
        CredentialDTO credential = getCredential();
        return credential != null ? credential.getLogin() : null;
    }
}
