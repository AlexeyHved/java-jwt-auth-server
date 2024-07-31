package com.github.AlexeyHved.jwtauthserver.utils;

import com.github.AlexeyHved.jwtauthserver.exception.PasswordValidationEx;


public class PassUtils {
    private PassUtils() {}

    public static void validate(String pass) {
        boolean invalid = pass.contains(" ") || pass.length() < 4;
        if (invalid) throw new PasswordValidationEx("Invalid password on registry");
    }
}
