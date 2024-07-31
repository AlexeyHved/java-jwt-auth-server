package com.github.AlexeyHved.jwtauthserver.domain;

import lombok.Builder;
import lombok.Getter;

import java.util.Set;
@Builder
@Getter
public class User {

    private String login;
    private String password;
    private Set<Role> roles;

}
