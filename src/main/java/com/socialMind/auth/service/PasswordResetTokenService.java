package com.socialMind.auth.service;

import com.socialMind.auth.domain.PasswordResetToken;
import com.socialMind.auth.domain.User;
import com.socialMind.auth.exception.BusinessException;
import com.socialMind.auth.repository.PasswordResetTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
public class PasswordResetTokenService {

    private final PasswordResetTokenRepository tokenRepository;
    
    @Autowired
    public PasswordResetTokenService(PasswordResetTokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }
    
    public void createPasswordResetTokenForUser(User user, String token) {
        PasswordResetToken myToken = new PasswordResetToken();
        myToken.setToken(token);
        myToken.setUser(user);
        myToken.setExpiryDate(LocalDateTime.now().plusHours(24));
        tokenRepository.save(myToken);
    }
    
    public User validatePasswordResetToken(String token) {
        PasswordResetToken passToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new BusinessException("Token inválido"));
        
        if (passToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            tokenRepository.delete(passToken);
            throw new BusinessException("Token expirado");
        }
        
        return passToken.getUser();
    }
    
    @Transactional
    public void deletePasswordResetToken(String token) {
        tokenRepository.deleteByToken(token);
    }
}
