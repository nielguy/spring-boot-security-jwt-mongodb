package com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.controller;

import com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.config.JwtUtils;
import com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.model.ERole;
import com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.model.Role;
import com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.model.User;
import com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.repository.RoleRepository;
import com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.repository.UserRepository;
import com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.request.LoginRequest;
import com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.request.SignupRequest;
import com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.response.JwtResponse;
import com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.response.MessageResponse;
import com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.service.UserDetailsImpl;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private AuthenticationManager authenticationManager;

    private UserRepository userRepository;

    private RoleRepository roleRepository;

    private PasswordEncoder encoder;

    private JwtUtils jwtUtils;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder encoder, JwtUtils jwtUtils) {
        this.authenticationManager=authenticationManager;
        this.userRepository=userRepository;
        this.roleRepository=roleRepository;
        this.encoder=encoder;
        this.jwtUtils=jwtUtils;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream().map(
                item -> item.getAuthority()
        ).collect(Collectors.toList());

        return ResponseEntity.status(HttpStatus.OK).body(
                new JwtResponse(jwt,
                        userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        roles)
        );
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        User user = new User(signupRequest.getUsername(),
                signupRequest.getEmail(), encoder.encode(signupRequest.getPassword()));
        Set<String> strRoles = signupRequest.getRoles();
        Set<Role> roles = new HashSet<>();
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: role is not found."));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: role is not found."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: role is not found."));
                        roles.add(userRole);
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(new MessageResponse("User registered successfully!"));
    }
}
