package com.github.AlexeyHved.jwtauthserver.repo;

import com.github.AlexeyHved.jwtauthserver.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepo extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByLogin(String login);

    boolean existsByLogin(String login);

    Void deleteByLogin(String login);
}
