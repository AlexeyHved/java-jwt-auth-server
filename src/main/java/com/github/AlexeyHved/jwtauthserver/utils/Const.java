package com.github.AlexeyHved.jwtauthserver.utils;

import java.time.format.DateTimeFormatter;

public class Const {
    private Const() {}
    public static final String AUTH = "/auth";
    public static final String REGISTER = "/registerUser";
    public static final String TOKEN = "/token";
    public static final String REFRESH = "/refresh";
    public static final DateTimeFormatter DTF = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

}
