package com.tkd.oauth2.security.service;

import com.tkd.oauth2.model.User;
import com.tkd.oauth2.repository.UserRepository;
import com.tkd.oauth2.security.model.AppUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.info("User Getting loaded by CustomUserDetailsService with Email");
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with Email:"+ email));
        return AppUser.create(user);
    }

    public UserDetails loadByUserid(Long id) {
        log.info("User Getting loaded by CustomUserDetailsService with Id");
        User user = userRepository.findById(id).orElseThrow(() -> new UsernameNotFoundException("User not found with Id:"+ id));
        return AppUser.create(user);
    }
}
