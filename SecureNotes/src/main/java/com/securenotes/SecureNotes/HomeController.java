package com.securenotes.SecureNotes;


import com.securenotes.SecureNotes.jwt.JwtUtils;
import com.securenotes.SecureNotes.jwt.LoginRequest;
import com.securenotes.SecureNotes.jwt.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class HomeController {

    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private AuthenticationManager authenticationManager;



    @GetMapping("/hello")
    public  String hello(){
        return "hello";

    }
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndpoint(){
        return "hey, user";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint(){
        return "hey admin";
    }


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser (@RequestBody LoginRequest loginRequest){
        Authentication authentication;
        try {
            authentication=authenticationManager.
                    authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword()));
        }catch (AuthenticationException e){
            Map<String,Object> map=new HashMap<>();
            map.put("message","Bad credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails=(UserDetails) authentication.getPrincipal();

        String jwtToken=jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles=userDetails.getAuthorities().stream()
                .map(item-> item.getAuthority())
                .collect(Collectors.toList());

        LoginResponse response=new LoginResponse(userDetails.getUsername(),jwtToken,roles);


        return ResponseEntity.ok(response);

    }





}
