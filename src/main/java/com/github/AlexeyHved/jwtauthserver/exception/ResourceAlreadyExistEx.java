package com.github.AlexeyHved.jwtauthserver.exception;

public class ResourceAlreadyExistEx extends RuntimeException {
    public ResourceAlreadyExistEx(String msg) {
        super(msg);
    }
}

