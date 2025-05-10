#!/bin/bash

# Criar diretório raiz
mkdir -p src/main/java/com/socialMind/auth/{config,controller,domain,dto,exception,repository,security/oauth2,service}
mkdir -p src/main/resources

# Arquivos de domínio
cat > src/main/java/com/socialMind/auth/domain/User.java << 'EOF'
package com.socialMind.auth.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Data
@Entity
@Table(name = "users")
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String email;
    
    private String password;
    
    private String firstName;
    
    private String lastName;
    
    private String businessName;
    
    private String businessDescription;
    
    private String phoneNumber;
    
    private String address;
    
    private String city;
    
    private String state;
    
    @Enumerated(EnumType.STRING)
    private AuthProvider provider = AuthProvider.LOCAL;
    
    private String providerId;
    
    private String imageUrl;
    
    private boolean emailVerified = false;
    
    @Enumerated(EnumType.STRING)
    private Role role = Role.USER;
    
    private boolean enabled = true;
    
    private LocalDateTime createdAt;
    
    private LocalDateTime updatedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
EOF

cat > src/main/java/com/socialMind/auth/domain/AuthProvider.java << 'EOF'
package com.socialMind.auth.domain;

public enum AuthProvider {
    LOCAL,
    GOOGLE,
    FACEBOOK
}
EOF

cat > src/main/java/com/socialMind/auth/domain/Role.java << 'EOF'
package com.socialMind.auth.domain;

public enum Role {
    USER,
    ADMIN
}
EOF

cat > src/main/java/com/socialMind/auth/domain/PasswordResetToken.java << 'EOF'
package com.socialMind.auth.domain;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "password_reset_tokens")
@NoArgsConstructor
@AllArgsConstructor
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true)
    private String token;
    
    @OneToOne(targetEntity = User.class, fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "user_id")
    private User user;
    
    @Column(nullable = false)
    private LocalDateTime expiryDate;
    
    private LocalDateTime createdAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
EOF

# DTOs
cat > src/main/java/com/socialMind/auth/dto/SignUpRequest.java << 'EOF'
package com.socialMind.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class SignUpRequest {
    
    @NotBlank(message = "Email é obrigatório")
    @Email(message = "Email deve ser válido")
    private String email;
    
    @NotBlank(message = "Senha é obrigatória")
    @Size(min = 6, message = "Senha deve ter pelo menos 6 caracteres")
    private String password;
    
    private String firstName;
    
    private String lastName;
    
    private String businessName;
}
EOF

cat > src/main/java/com/socialMind/auth/dto/LoginRequest.java << 'EOF'
package com.socialMind.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {
    
    @NotBlank(message = "Email é obrigatório")
    @Email(message = "Email deve ser válido")
    private String email;
    
    @NotBlank(message = "Senha é obrigatória")
    private String password;
}
EOF

cat > src/main/java/com/socialMind/auth/dto/AuthResponse.java << 'EOF'
package com.socialMind.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthResponse {
    private String accessToken;
    private String tokenType = "Bearer";
    
    public AuthResponse(String accessToken) {
        this.accessToken = accessToken;
    }
}
EOF

cat > src/main/java/com/socialMind/auth/dto/UserProfileDTO.java << 'EOF'
package com.socialMind.auth.dto;

import com.socialMind.auth.domain.AuthProvider;
import lombok.Data;

@Data
public class UserProfileDTO {
    
    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private String businessName;
    private String businessDescription;
    private String phoneNumber;
    private String address;
    private String city;
    private String state;
    private AuthProvider provider;
    private String imageUrl;
}
EOF

cat > src/main/java/com/socialMind/auth/dto/PasswordResetRequest.java << 'EOF'
package com.socialMind.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PasswordResetRequest {
    
    @NotBlank(message = "Email é obrigatório")
    @Email(message = "Email deve ser válido")
    private String email;
}
EOF

cat > src/main/java/com/socialMind/auth/dto/PasswordUpdateRequest.java << 'EOF'
package com.socialMind.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class PasswordUpdateRequest {
    
    @NotBlank(message = "Token é obrigatório")
    private String token;
    
    @NotBlank(message = "Nova senha é obrigatória")
    @Size(min = 6, message = "Senha deve ter pelo menos 6 caracteres")
    private String newPassword;
}
EOF

# Repositórios
cat > src/main/java/com/socialMind/auth/repository/UserRepository.java << 'EOF'
package com.socialMind.auth.repository;

import com.socialMind.auth.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByEmail(String email);
    
    Boolean existsByEmail(String email);
    
    Optional<User> findByProviderAndProviderId(String provider, String providerId);
}
EOF

cat > src/main/java/com/socialMind/auth/repository/PasswordResetTokenRepository.java << 'EOF'
package com.socialMind.auth.repository;

import com.socialMind.auth.domain.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    
    Optional<PasswordResetToken> findByToken(String token);
    
    void deleteByToken(String token);
}
EOF

# Exceções
cat > src/main/java/com/socialMind/auth/exception/BusinessException.java << 'EOF'
package com.socialMind.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class BusinessException extends RuntimeException {
    
    public BusinessException(String message) {
        super(message);
    }
    
    public BusinessException(String message, Throwable cause) {
        super(message, cause);
    }
}
EOF

cat > src/main/java/com/socialMind/auth/exception/ResourceNotFoundException.java << 'EOF'
package com.socialMind.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class ResourceNotFoundException extends RuntimeException {
    
    private final String resourceName;
    private final String fieldName;
    private final Object fieldValue;
    
    public ResourceNotFoundException(String resourceName, String fieldName, Object fieldValue) {
        super(String.format("%s não encontrado com %s : '%s'", resourceName, fieldName, fieldValue));
        this.resourceName = resourceName;
        this.fieldName = fieldName;
        this.fieldValue = fieldValue;
    }
    
    public String getResourceName() {
        return resourceName;
    }
    
    public String getFieldName() {
        return fieldName;
    }
    
    public Object getFieldValue() {
        return fieldValue;
    }
}
EOF

cat > src/main/java/com/socialMind/auth/exception/ApiError.java << 'EOF'
package com.socialMind.auth.exception;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Data
public class ApiError {
    
    private HttpStatus status;
    
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "dd-MM-yyyy hh:mm:ss")
    private LocalDateTime timestamp;
    
    private String message;
    private String debugMessage;
    private List<String> errors = new ArrayList<>();
    
    private ApiError() {
        timestamp = LocalDateTime.now();
    }
    
    public ApiError(HttpStatus status) {
        this();
        this.status = status;
    }
    
    public ApiError(HttpStatus status, String message) {
        this();
        this.status = status;
        this.message = message;
    }
    
    public ApiError(HttpStatus status, String message, Throwable ex) {
        this();
        this.status = status;
        this.message = message;
        this.debugMessage = ex.getLocalizedMessage();
    }
    
    public void addError(String error) {
        this.errors.add(error);
    }
}
EOF

cat > src/main/java/com/socialMind/auth/exception/ApiExceptionHandler.java << 'EOF'
package com.socialMind.auth.exception;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {
    
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Object> handleResourceNotFoundException(ResourceNotFoundException ex, WebRequest request) {
        ApiError apiError = new ApiError(HttpStatus.NOT_FOUND, ex.getMessage(), ex);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }
    
    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<Object> handleBusinessException(BusinessException ex, WebRequest request) {
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }
    
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Object> handleBadCredentialsException(BadCredentialsException ex, WebRequest request) {
        ApiError apiError = new ApiError(HttpStatus.UNAUTHORIZED, "Credenciais inválidas", ex);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }
    
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, 
                                                                 HttpHeaders headers, 
                                                                 HttpStatus status, 
                                                                 WebRequest request) {
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST);
        apiError.setMessage("Erro de validação");
        
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            apiError.addError(error.getField() + ": " + error.getDefaultMessage());
        }
        
        for (ObjectError error : ex.getBindingResult().getGlobalErrors()) {
            apiError.addError(error.getObjectName() + ": " + error.getDefaultMessage());
        }
        
        return new ResponseEntity<>(apiError, headers, apiError.getStatus());
    }
    
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Object> handleConstraintViolation(ConstraintViolationException ex, WebRequest request) {
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST);
        apiError.setMessage("Erro de validação");
        
        for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
            apiError.addError(violation.getRootBeanClass().getName() + " " + 
                    violation.getPropertyPath() + ": " + violation.getMessage());
        }
        
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleAll(Exception ex, WebRequest request) {
        ApiError apiError = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, "Erro interno do servidor", ex);
        return new ResponseEntity<>(apiError, new HttpHeaders(), apiError.getStatus());
    }
}
EOF

# Segurança
cat > src/main/java/com/socialMind/auth/security/JwtTokenProvider.java << 'EOF'
package com.socialMind.auth.security;

import com.socialMind.auth.domain.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenProvider {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration}")
    private int jwtExpirationInMs;
    
    private Key key;
    
    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public String generateToken(Authentication authentication) {
        User userPrincipal = (User) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

        return Jwts.builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .claim("email", userPrincipal.getEmail())
                .claim("role", userPrincipal.getRole().name())
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(key)
                .compact();
    }

    public Long getUserIdFromJWT(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return Long.parseLong(claims.getSubject());
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException ex) {
            System.out.println("Token JWT inválido");
        } catch (ExpiredJwtException ex) {
            System.out.println("Token JWT expirado");
        } catch (UnsupportedJwtException ex) {
            System.out.println("Token JWT não suportado");
        } catch (IllegalArgumentException ex) {
            System.out.println("JWT claims string está vazia");
        }
        return false;
    }
}
EOF

cat > src/main/java/com/socialMind/auth/security/JwtAuthenticationFilter.java << 'EOF'
package com.socialMind.auth.security;

import com.socialMind.auth.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwt = getJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                Long userId = tokenProvider.getUserIdFromJWT(jwt);

                UserDetails userDetails = userService.loadUserById(userId);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            logger.error("Não foi possível autenticar o usuário", ex);
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
EOF

# OAuth2
mkdir -p src/main/java/com/socialMind/auth/security/oauth2

cat > src/main/java/com/socialMind/auth/security/oauth2/OAuth2UserInfo.java << 'EOF'
package com.socialMind.auth.security.oauth2;

import java.util.Map;

public abstract class OAuth2UserInfo {
    protected Map<String, Object> attributes;

    public OAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public abstract String getId();

    public abstract String getName();

    public abstract String getEmail();

    public abstract String getImageUrl();
}
EOF

cat > src/main/java/com/socialMind/auth/security/oauth2/GoogleOAuth2UserInfo.java << 'EOF'
package com.socialMind.auth.security.oauth2;

import java.util.Map;

public class GoogleOAuth2UserInfo extends OAuth2UserInfo {

    public GoogleOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("sub");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("picture");
    }
}
EOF

cat > src/main/java/com/socialMind/auth/security/oauth2/FacebookOAuth2UserInfo.java << 'EOF'
package com.socialMind.auth.security.oauth2;

import java.util.Map;

public class FacebookOAuth2UserInfo extends OAuth2UserInfo {

    public FacebookOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        if(attributes.containsKey("picture")) {
            Map<String, Object> pictureObj = (Map<String, Object>) attributes.get("picture");
            if(pictureObj.containsKey("data")) {
                Map<String, Object> dataObj = (Map<String, Object>) pictureObj.get("data");
                if(dataObj.containsKey("url")) {
                    return (String) dataObj.get("url");
                }
            }
        }
        return null;
    }
}
EOF

cat > src/main/java/com/socialMind/auth/security/oauth2/OAuth2UserInfoFactory.java << 'EOF'
package com.socialMind.auth.security.oauth2;

import com.socialMind.auth.exception.BusinessException;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase("google")) {
            return new GoogleOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase("facebook")) {
            return new FacebookOAuth2UserInfo(attributes);
        } else {
            throw new BusinessException("Login com " + registrationId + " não é suportado.");
        }
    }
}
EOF

cat > src/main/java/com/socialMind/auth/security/oauth2/OAuth2AuthenticationSuccessHandler.java << 'EOF'
package com.socialMind.auth.security.oauth2;

import com.socialMind.auth.security.JwtTokenProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Value("${app.oauth2.redirectUri}")
    private String redirectUri;
    
    private final JwtTokenProvider tokenProvider;

    @Autowired
    public OAuth2AuthenticationSuccessHandler(JwtTokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) 
            throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String token = tokenProvider.generateToken(authentication);

        return UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("token", token)
                .build().toUriString();
    }
}
EOF

# Serviços
cat > src/main/java/com/socialMind/auth/service/UserService.java << 'EOF'
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
EOF

cat > src/main/java/com/socialMind/auth/service/EmailService.java << 'EOF'
package com.socialMind.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender mailSender;
    
    @Value("${app.frontend.url}")
    private String frontendUrl;
    
    @Autowired
    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }
    
    public void sendPasswordResetEmail(String to, String token) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Recuperação de Senha - SocialMind");
        message.setText("Para redefinir sua senha, clique no link abaixo:\n\n" +
                frontendUrl + "/reset-password?token=" + token + "\n\n" +
                "Este link expira em 24 horas.\n\n" +
                "Se você não solicitou a redefinição de senha, ignore este e-mail.");
        
        mailSender.send(message);
    }
}
EOF

cat > src/main/java/com/socialMind/auth/service/PasswordResetTokenService.java << 'EOF'
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
EOF

cat > src/main/java/com/socialMind/auth/service/OAuth2UserService.java << 'EOF'
package com.socialMind.auth.service;

import com.socialMind.auth.domain.AuthProvider;
import com.socialMind.auth.domain.User;
import com.socialMind.auth.repository.UserRepository;
import com.socialMind.auth.security.oauth2.OAuth2UserInfo;
import com.socialMind.auth.security.oauth2.OAuth2UserInfoFactory;
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

        return user;
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
EOF

# Controladores
cat > src/main/java/com/socialMind/auth/controller/AuthController.java << 'EOF'
package com.socialMind.auth.controller;

import com.socialMind.auth.dto.*;
import com.socialMind.auth.security.JwtTokenProvider;
import com.socialMind.auth.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JwtTokenProvider tokenProvider;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager,
                         UserService userService,
                         JwtTokenProvider tokenProvider) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.tokenProvider = tokenProvider;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = tokenProvider.generateToken(authentication);
        
        return ResponseEntity.ok(new AuthResponse(token));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        userService.registerUser(signUpRequest);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/password/reset-request")
    public ResponseEntity<?> requestPasswordReset(@Valid @RequestBody PasswordResetRequest request) {
        userService.initiatePasswordReset(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/password/reset")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody PasswordUpdateRequest request) {
        userService.resetPassword(request);
        return ResponseEntity.ok().build();
    }
}
EOF

cat > src/main/java/com/socialMind/auth/controller/UserController.java << 'EOF'
package com.socialMind.auth.controller;

import com.socialMind.auth.domain.User;
import com.socialMind.auth.dto.UserProfileDTO;
import com.socialMind.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    public ResponseEntity<UserProfileDTO> getCurrentUser(@AuthenticationPrincipal User currentUser) {
        UserProfileDTO userProfile = userService.getUserProfile(currentUser.getId());
        return ResponseEntity.ok(userProfile);
    }

    @PutMapping("/me")
    public ResponseEntity<UserProfileDTO> updateUserProfile(
            @AuthenticationPrincipal User currentUser,
            @RequestBody UserProfileDTO profileDTO) {
        UserProfileDTO updatedProfile = userService.updateUserProfile(currentUser.getId(), profileDTO);
        return ResponseEntity.ok(updatedProfile);
    }
}
EOF

# Configuração
cat > src/main/java/com/socialMind/auth/config/SecurityConfig.java << 'EOF'
package com.socialMind.auth.config;

import com.socialMind.auth.security.JwtAuthenticationFilter;
import com.socialMind.auth.security.oauth2.OAuth2AuthenticationSuccessHandler;
import com.socialMind.auth.service.OAuth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final OAuth2UserService oAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    @Autowired
    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                         OAuth2UserService oAuth2UserService,
                         OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.oAuth2UserService = oAuth2UserService;
        this.oAuth2AuthenticationSuccessHandler = oAuth2AuthenticationSuccessHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors().and().csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/auth/**", "/oauth2/**").permitAll()
                .requestMatchers("/api/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login()
                .authorizationEndpoint()
                    .baseUri("/oauth2/authorize")
                    .and()
                .redirectionEndpoint()
                    .baseUri("/oauth2/callback/*")
                    .and()
                .userInfoEndpoint()
                    .userService(oAuth2UserService)
                    .and()
                .successHandler(oAuth2AuthenticationSuccessHandler)
            .and()
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
EOF

cat > src/main/java/com/socialMind/auth/config/WebConfig.java << 'EOF'
package com.socialMind.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("*")
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .maxAge(3600);
    }
}
EOF

# Arquivo de propriedades
cat > src/main/resources/application.properties << 'EOF'
# JWT Configuration
app.jwt.secret=sua-chave-secreta-muito-longa-e-segura-para-jwt-tokens-socialMind-app
app.jwt.expiration=86400000

# OAuth2 Configuration
spring.security.oauth2.client.registration.google.client-id=your-google-client-id
spring.security.oauth2.client.registration.google.client-secret=your-google-client-secret
spring.security.oauth2.client.registration.google.redirect-uri={baseUrl}/oauth2/callback/{registrationId}
spring.security.oauth2.client.registration.google.scope=email,profile

spring.security.oauth2.client.registration.facebook.client-id=your-facebook-client-id
spring.security.oauth2.client.registration.facebook.client-secret=your-facebook-client-secret
spring.security.oauth2.client.registration.facebook.redirect-uri={baseUrl}/oauth2/callback/{registrationId}
spring.security.oauth2.client.registration.facebook.scope=email,public_profile

# Frontend URL
app.frontend.url=http://localhost:3000
app.oauth2.redirectUri=${app.frontend.url}/oauth2/redirect

# Email Configuration
spring.mail.host=smtp.gmail.com
spring.mail.port=587
spring.mail.username=your-email@gmail.com
spring.mail.password=your-app-password
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true

# Database Configuration
spring.datasource.url=jdbc:mysql://localhost:3306/socialmind?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true
spring.datasource.username=root
spring.datasource.password=root
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver

# JPA Configuration
spring.jpa.hibernate.ddl-auto=update
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQL8Dialect
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.format_sql=true
EOF

# Aplicação principal
cat > src/main/java/com/socialMind/SocialMindApplication.java << 'EOF'
package com.socialMind;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SocialMindApplication {

    public static void main(String[] args) {
        SpringApplication.run(SocialMindApplication.class, args);
    }
}
EOF

echo "Estrutura de diretórios e arquivos criada com sucesso!"