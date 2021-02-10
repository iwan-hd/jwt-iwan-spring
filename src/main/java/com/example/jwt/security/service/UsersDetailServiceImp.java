package com.example.jwt.security.service;

import com.example.jwt.model.User;
import com.example.jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
public class UsersDetailServiceImp implements UsersDetailService {

    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUsersByUsername(String username) throws UsernameNotFoundException {
        User user= userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Data user " + username+  " tidak ditemukan"));

        return UserDetailsImp.build(user);
    }
}
