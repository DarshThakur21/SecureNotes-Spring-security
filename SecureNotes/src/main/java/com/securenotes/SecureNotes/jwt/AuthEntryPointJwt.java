package com.securenotes.SecureNotes.jwt;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.io.IOException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.naming.AuthenticationException;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {
    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

//    @Override
//    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
//            throws IOException, ServletException, java.io.IOException {
//
//    }


    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, org.springframework.security.core.AuthenticationException authException) throws java.io.IOException, ServletException {
        logger.error("unauthorized error:{}",authException.getMessage());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        final Map<String,Object > body=new HashMap<>();
        body.put("Status",HttpServletResponse.SC_UNAUTHORIZED);
        body.put("Error","Unauthorized");
        body.put("message",authException.getMessage());
        body.put("Path",request.getServletPath());

        final ObjectMapper mapper=new ObjectMapper();
        mapper.writeValue(response.getOutputStream(),body);

    }
}
