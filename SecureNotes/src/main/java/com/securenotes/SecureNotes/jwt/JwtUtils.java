package com.securenotes.SecureNotes.jwt;


//import org.hibernate.annotations.Comments;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

//import static jdk.internal.org.jline.keymap.KeyMap.key;

@Component
public class JwtUtils {
    private  final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String getJwtHeader(HttpServletRequest request){
        String bearerToken=request.getHeader("Authorization");
        logger.debug("Authorization header: {}",bearerToken);
        if(bearerToken!=null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);

        }
        return null;
    }

    public String generateTokenFromUsername(UserDetails userDetails){
                String username=userDetails.getUsername();
                return Jwts.builder()
                        .subject(username)
                        .issuedAt(new Date())
                        .expiration(new Date((new Date()).getTime()+jwtExpirationMs))
                        .signWith(key())
                        .compact();


    }
        public String getUserNameFromJwtToken(String token){
        return Jwts.parser()
                .verifyWith((SecretKey) key()).build().parseSignedClaims(token)
                .getPayload().getSubject();
        }


        public boolean validateJwtToken(String authToken){
        try {
        Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
        return true;
        }catch (MalformedJwtException e){
            System.out.println(e);
            return false;
        }
        }

    private Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }




}
