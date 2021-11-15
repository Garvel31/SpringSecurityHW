package ru.pobeda.springsecurityhw.model;

import lombok.Data;


@Data
public class TokensPair {

    String accessToken, refreshToken;


}
