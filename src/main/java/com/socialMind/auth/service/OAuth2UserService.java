package com.socialMind.auth.service;

import com.socialMind.auth.domain.AuthProvider;
import com.socialMind.auth.domain.User;
import com.socialMind.auth.repository.UserRepository;
import com.socialMind.auth.security.oauth2.OAuth2UserInfo;
import com.socialMind.auth.security.oauth2.OAuth2UserInfoFactory;
import com.socialMind.auth.security.oauth2.UserPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class OAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Autowired
    public OAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        try {
            return processOAuth2User(userRequest, oAuth2User);
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        String registrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, oAuth2User.getAttributes());

        if(oAuth2UserInfo.getEmail() == null || oAuth2UserInfo.getEmail().isEmpty()) {
            throw new OAuth2AuthenticationException("Email não encontrado no OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        User user;

        if(userOptional.isPresent()) {
            user = userOptional.get();

            if(!user.getProvider().toString().equalsIgnoreCase(registrationId)) {
                throw new OAuth2AuthenticationException(
                        "Você já está cadastrado com " + user.getProvider() + ". Por favor, use sua conta " + user.getProvider() + " para fazer login.");
            }

            user = updateExistingUser(user, oAuth2UserInfo);
        } else {
            user = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
        }

        // Retorna um UserPrincipal em vez de User diretamente
        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
        User user = new User();

        user.setProvider(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId().toUpperCase()));
        user.setProviderId(oAuth2UserInfo.getId());
        user.setEmail(oAuth2UserInfo.getEmail());
        user.setEmailVerified(true);
        user.setFirstName(oAuth2UserInfo.getName());
        user.setImageUrl(oAuth2UserInfo.getImageUrl());

        return userRepository.save(user);
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {
        existingUser.setFirstName(oAuth2UserInfo.getName());
        existingUser.setImageUrl(oAuth2UserInfo.getImageUrl());
        return userRepository.save(existingUser);
    }
}