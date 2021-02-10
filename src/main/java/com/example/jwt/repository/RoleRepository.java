package com.example.jwt.repository;

import com.example.jwt.model.ERole;
import com.example.jwt.model.Role;
import org.springframework.context.support.BeanDefinitionDsl;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository <Role, Long >{

    Optional<Role> findByName(ERole name);
}
