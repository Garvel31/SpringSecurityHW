package ru.pobeda.springsecurityhw.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@AllArgsConstructor
@RequiredArgsConstructor
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final ru.pobeda.springsecurityhw.jwt.JwtProvider jwtProvider;
    private final static String BEARER_PREFIX = "Bearer ";

    @Autowired
    ObjectMapper objectMapper;




    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            ru.pobeda.springsecurityhw.jwt.UsernamePasswordAuthRequest usernamePasswordAuthRequest =
                    new ObjectMapper().readValue(request.getInputStream(), ru.pobeda.springsecurityhw.jwt.UsernamePasswordAuthRequest.class);
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(usernamePasswordAuthRequest.getUsername(),
                            usernamePasswordAuthRequest.getPassword());

            return authenticationManager.authenticate(authentication);
        } catch (IOException e) {
            log.error("Unexpected error", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        TokensPair tokensPair = new TokensPair();
        tokensPair.setAccessToken(jwtProvider.createToken(authResult).replace(BEARER_PREFIX, ""));
        tokensPair.setRefreshToken(jwtProvider.createRefreshToken(authResult).replace(BEARER_PREFIX, ""));
        response.addHeader(HttpHeaders.AUTHORIZATION, jwtProvider.createToken(authResult));
        response.setContentType("text/json");
        String jsonToken =new ObjectMapper().writeValueAsString(tokensPair);
        PrintWriter writer = response.getWriter();
        writer.print(jsonToken);
        writer.flush();


    }
}
