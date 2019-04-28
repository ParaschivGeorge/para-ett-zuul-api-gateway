package com.paraett.zuulapigateway.service;

import com.paraett.zuulapigateway.model.JwtUserFactory;
import com.paraett.zuulapigateway.model.entities.User;
import com.paraett.zuulapigateway.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    public JwtUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByEmail(email);

        if (!user.isPresent()) {
            throw new UsernameNotFoundException(String.format("No user found with email '%s'.", email));
        } else {
            return JwtUserFactory.create(user.get());
        }
    }
}