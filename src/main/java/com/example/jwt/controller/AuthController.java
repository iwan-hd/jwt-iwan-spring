package com.example.jwt.controller;

import com.example.jwt.model.ERole;
import com.example.jwt.model.Role;
import com.example.jwt.model.User;
import com.example.jwt.payload.requests.LoginRequest;
import com.example.jwt.payload.requests.SignUpRequest;
import com.example.jwt.payload.respones.JwtRespones;
import com.example.jwt.payload.respones.MessageRespones;
import com.example.jwt.repository.RoleRepository;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.security.jwt.JwtUtils;
import com.example.jwt.security.service.UserDetailsImp;
import com.example.jwt.security.service.UsersDetailServiceImp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(value = "*", maxAge = 3600)
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?>  authenticateUser(@Valid @RequestBody LoginRequest loginRequest){
        //authenticate {username, password}
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );

        //update SecurityContext using Authenticate obj
        SecurityContextHolder.getContext().setAuthentication(authentication);

        //generate JWT
        String jwt = jwtUtils.generateJwtToken(authentication);

        //get userDetails from Authenticate obj
        UserDetailsImp usersDetails = (UserDetailsImp) authentication.getPrincipal();

        //response contain JWT and userDetails data
        List<String> roles = usersDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(
            new JwtRespones(jwt,
                    usersDetails.getId(),
                    usersDetails.getUsername(),
                    usersDetails.getEmail(),
                    roles));
    }


    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest){
        //cek exists email/username
        if (userRepository.existsByUsername(signUpRequest.getUsername())){
            return ResponseEntity.badRequest().body(new MessageRespones("Error : user already exists !"));
        }

        if (userRepository.exitsByEmail(signUpRequest.getEmail())){
            return ResponseEntity.badRequest().body(new MessageRespones("Error : email already exists !"));
        }

        //create user ( kalau gak roles default ROLE_USER)
        User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));
                Set<String> strRoles = signUpRequest.getRole();
                Set<Role> roles = new HashSet<>();

                if (strRoles == null){
                    Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                            .orElseThrow(()-> new RuntimeException("Error : Role is not found"));
                    roles.add(userRole);
                } else {
                    strRoles.forEach(role -> {
                        switch (role){
                            case "admin" :
                                Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                        .orElseThrow(()-> new RuntimeException("Error : Role is not found"));
                                roles.add(adminRole);

                            case "mod" :
                                Role moderatorRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                        .orElseThrow(()-> new RuntimeException("Error : Role is not found"));
                                roles.add(moderatorRole);

                            default:
                                Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                        .orElseThrow(()-> new RuntimeException("Error : Role is not found"));
                                roles.add(userRole);

                        }
                    });
                }

        //SAVE KE model USER pake methode save UserRepository
        user.setRoles(roles);
        userRepository.save(user);

        return  ResponseEntity.ok(new MessageRespones("Register user successfully !!"));
    }



}
