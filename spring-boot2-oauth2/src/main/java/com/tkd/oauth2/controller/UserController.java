package com.tkd.oauth2.controller;

import com.tkd.oauth2.model.User;
import com.tkd.oauth2.repository.UserRepository;
import com.tkd.oauth2.security.exception.ResourceNotFoundException;
import com.tkd.oauth2.security.model.AppUser;
import com.tkd.oauth2.security.model.CurrentUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/user/me")
    @PreAuthorize("hasRole('USER')")
    public User getCurrentUser(@CurrentUser AppUser userPrincipal) {
        return userRepository.findById(userPrincipal.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userPrincipal.getId()));
    }
}




/*@RequestMapping("/user")
@RestController
public class UserController {

    @GetMapping("/detail")
    public String getUser() {
        return "Tarun";
    }

    @GetMapping("/loginfail")
    public String failure() {
        return "Login Failed";
    }
}*/
