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
