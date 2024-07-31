package com.github.AlexeyHved.jwtauthserver.utils;

import com.github.AlexeyHved.jwtauthserver.domain.Role;
import com.github.AlexeyHved.jwtauthserver.domain.User;
import com.github.AlexeyHved.jwtauthserver.dto.JwtRequest;
import com.github.AlexeyHved.jwtauthserver.entity.RoleEntity;
import com.github.AlexeyHved.jwtauthserver.entity.UserEntity;

import java.util.Set;
import java.util.stream.Collectors;

public class Builder {
    private Builder() {}
    public static UserEntity buildUserEntity(User user, Set<RoleEntity> roles, String refresh) {
        UserEntity userEntity = new UserEntity();
        userEntity.setLogin(user.getLogin());
        userEntity.setPassword(user.getPassword());
        userEntity.setRoles(roles);
        userEntity.setRefreshToken(refresh);
        return userEntity;
    }

    public static RoleEntity buildRoleEntity(Role role) {
        RoleEntity roleEntity = new RoleEntity();
        roleEntity.setRole(role);
        return roleEntity;
    }

    public static User buildUser(JwtRequest authRequest, String pass) {
        return User.builder()
                .login(authRequest.getLogin())
                .password(pass)
                .roles(Set.of(Role.USER))
                .build();
    }

    public static User mapToUser(UserEntity userEntity) {
        return User.builder()
                .login(userEntity.getLogin())
                .password(userEntity.getPassword())
                .roles(userEntity.getRoles().stream()
                        .map(RoleEntity::getRole)
                        .collect(Collectors.toUnmodifiableSet()))
                .build();
    }
}
