package com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.service;

import com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.model.User;
import com.nielo.springbootsecurityjwtmongodb.springbootsecurityjwtmongodb.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private UserRepository userRepository;

    @Autowired
    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository=userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: "+username));

        return UserDetailsImpl.build(user);
    }
}
