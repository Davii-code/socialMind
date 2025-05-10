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
