package com.github.AlexeyHved.jwtauthserver.repo;

import com.github.AlexeyHved.jwtauthserver.domain.Role;
import com.github.AlexeyHved.jwtauthserver.entity.RoleEntity;
import jakarta.persistence.criteria.CriteriaBuilder;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<RoleEntity, Integer> {
    RoleEntity findByRole(Role role);
}
