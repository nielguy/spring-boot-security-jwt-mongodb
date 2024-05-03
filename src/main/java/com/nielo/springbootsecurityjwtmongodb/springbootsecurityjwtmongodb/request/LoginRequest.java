package com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@EqualsAndHashCode
public class LoginRequest {

    @NotBlank
    private String username;

    @NotBlank
    private String password;
}
