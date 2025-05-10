package com.socialMind.auth.service;

import com.socialMind.auth.domain.User;
import com.socialMind.auth.dto.PasswordResetRequest;
import com.socialMind.auth.dto.PasswordUpdateRequest;
import com.socialMind.auth.dto.SignUpRequest;
import com.socialMind.auth.dto.UserProfileDTO;
import com.socialMind.auth.exception.BusinessException;
import com.socialMind.auth.exception.ResourceNotFoundException;
import com.socialMind.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final PasswordResetTokenService tokenService;

    @Autowired
    public UserService(UserRepository userRepository, 
                      PasswordEncoder passwordEncoder,
                      EmailService emailService,
                      PasswordResetTokenService tokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.tokenService = tokenService;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado com email: " + email));
    }
    
    public UserDetails loadUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));
    }

    public User registerUser(SignUpRequest signUpRequest) {
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new BusinessException("Email já está em uso");
        }

        User user = new User();
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
        user.setFirstName(signUpRequest.getFirstName());
        user.setLastName(signUpRequest.getLastName());
        user.setBusinessName(signUpRequest.getBusinessName());
        
        return userRepository.save(user);
    }

    public User findById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));
    }

    public UserProfileDTO getUserProfile(Long userId) {
        User user = findById(userId);
        return mapToUserProfileDTO(user);
    }

    public UserProfileDTO updateUserProfile(Long userId, UserProfileDTO profileDTO) {
        User user = findById(userId);
        
        user.setFirstName(profileDTO.getFirstName());
        user.setLastName(profileDTO.getLastName());
        user.setBusinessName(profileDTO.getBusinessName());
        user.setBusinessDescription(profileDTO.getBusinessDescription());
        user.setPhoneNumber(profileDTO.getPhoneNumber());
        user.setAddress(profileDTO.getAddress());
        user.setCity(profileDTO.getCity());
        user.setState(profileDTO.getState());
        
        if (profileDTO.getImageUrl() != null) {
            user.setImageUrl(profileDTO.getImageUrl());
        }
        
        User updatedUser = userRepository.save(user);
        return mapToUserProfileDTO(updatedUser);
    }

    public void initiatePasswordReset(PasswordResetRequest request) {
        Optional<User> userOpt = userRepository.findByEmail(request.getEmail());
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            String token = UUID.randomUUID().toString();
            tokenService.createPasswordResetTokenForUser(user, token);
            emailService.sendPasswordResetEmail(user.getEmail(), token);
        }
        // Não informamos ao usuário se o email existe ou não por questões de segurança
    }

    @Transactional
    public void resetPassword(PasswordUpdateRequest request) {
        User user = tokenService.validatePasswordResetToken(request.getToken());
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        tokenService.deletePasswordResetToken(request.getToken());
    }

    private UserProfileDTO mapToUserProfileDTO(User user) {
        UserProfileDTO dto = new UserProfileDTO();
        dto.setId(user.getId());
        dto.setEmail(user.getEmail());
        dto.setFirstName(user.getFirstName());
        dto.setLastName(user.getLastName());
        dto.setBusinessName(user.getBusinessName());
        dto.setBusinessDescription(user.getBusinessDescription());
        dto.setPhoneNumber(user.getPhoneNumber());
        dto.setAddress(user.getAddress());
        dto.setCity(user.getCity());
        dto.setState(user.getState());
        dto.setProvider(user.getProvider());
        dto.setImageUrl(user.getImageUrl());
        return dto;
    }
}
