package com.github.AlexeyHved.jwtauthserver.exception;

public class PasswordValidationEx extends RuntimeException {
    public PasswordValidationEx(String msg) {
        super(msg);
    }
}
