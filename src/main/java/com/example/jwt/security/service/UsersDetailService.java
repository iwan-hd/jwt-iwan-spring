package com.example.jwt.security.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface UsersDetailService {
    UserDetails loadUsersByUsername(String username) throws UsernameNotFoundException;
}
