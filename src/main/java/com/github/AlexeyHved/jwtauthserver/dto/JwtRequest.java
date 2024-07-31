package com.github.AlexeyHved.jwtauthserver.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.validator.constraints.Length;

@Getter
@Setter
@NoArgsConstructor
public class JwtRequest {
    @NotBlank
    @Length(min = 2)
    private String login;
    @NotBlank
    @Length(min = 4)
    private String pass;
}
