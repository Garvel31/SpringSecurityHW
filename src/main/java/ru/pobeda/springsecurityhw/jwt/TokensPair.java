package ru.pobeda.springsecurityhw.jwt;

import org.springframework.stereotype.Component;

@Component
public class TokensPair {

    String accessToken, refreshToken;

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
