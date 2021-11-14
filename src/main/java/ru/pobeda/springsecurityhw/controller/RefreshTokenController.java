package ru.pobeda.springsecurityhw.controller;

import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.pobeda.springsecurityhw.jwt.TokensPair;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@AllArgsConstructor
@RestController
@RequestMapping("/update")
public class RefreshTokenController {

    private final static String BEARER_PREFIX = "Bearer ";

    @Autowired
    TokensPair tokensPair;

    @Autowired
    private final ru.pobeda.springsecurityhw.jwt.JwtProvider jwtProvider;

    @GetMapping("/token")
    public TokensPair refreshTokens(Authentication authentication, HttpServletResponse response) throws IOException {

        tokensPair.setAccessToken(jwtProvider.createToken(authentication).replace(BEARER_PREFIX, ""));
        tokensPair.setRefreshToken(jwtProvider.createRefreshToken(authentication).replace(BEARER_PREFIX, ""));
        response.addHeader(HttpHeaders.AUTHORIZATION, tokensPair.getAccessToken());
        response.setContentType("text/json");
//        String newtoken = jwtProvider.createToken(authentication);
//        String newrefreshToken = jwtProvider.createRefreshToken(authentication);
//        PrintWriter writer = response.getWriter();
//        writer.println(newtoken);
//        writer.println(newrefreshToken);
        return tokensPair;

    }

}
