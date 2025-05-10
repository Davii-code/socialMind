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
