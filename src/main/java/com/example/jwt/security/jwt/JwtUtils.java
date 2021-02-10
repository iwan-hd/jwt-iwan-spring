package com.example.jwt.security.jwt;

import com.example.jwt.security.service.UserDetailsImp;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;

import java.util.Date;

public class JwtUtils {
//username,date,expiration,key
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${test.app.jwtSecret}")
    private String jwtSecret;

    @Value("${test.app.jwtExpirationMs}")
    private  int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication){

        UserDetailsImp userPrincipal = (UserDetailsImp) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.ES256,jwtSecret)
                .compact();
    }

    public String getUserNameFromJwtToken(String token){
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJwt(token).getBody().getSubject();
    }

    public Boolean validateJwtToken(String authToken){
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJwt(authToken);
            return true;
        } catch (SignatureException e){
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException f) {
            logger.error("Invalid JWT token: {}", f.getMessage());
        } catch (ExpiredJwtException h) {
            logger.error("JWT token is expired: {}", h.getMessage());
        } catch (UnsupportedJwtException j) {
            logger.error("JWT token is unsupported: {}", j.getMessage());
        } catch (IllegalArgumentException u) {
            logger.error("JWT claims string is empty: {}", u.getMessage());
        }


        return false;
    }
}
