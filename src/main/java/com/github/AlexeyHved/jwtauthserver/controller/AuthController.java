package com.github.AlexeyHved.jwtauthserver.controller;

import com.github.AlexeyHved.jwtauthserver.dto.JwtRequest;
import com.github.AlexeyHved.jwtauthserver.dto.JwtResponse;
import com.github.AlexeyHved.jwtauthserver.dto.RefreshJwtRequest;
import com.github.AlexeyHved.jwtauthserver.service.AuthService;
import com.github.AlexeyHved.jwtauthserver.utils.PassUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
@Validated
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<JwtResponse> register(@Validated @RequestBody JwtRequest authRequest) {
        PassUtils.validate(authRequest.getPass());
        final JwtResponse token = authService.registerUser(authRequest);
        return ResponseEntity.ok(token);
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Void> delete(@RequestHeader("Authorization") String bearer) {
        authService.deleteUser(bearer);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest authRequest) {
        final JwtResponse token = authService.login(authRequest);
        return ResponseEntity.ok(token);
    }

    @PostMapping("/token")
    public ResponseEntity<JwtResponse> updateToken(@RequestBody RefreshJwtRequest request) {
        final JwtResponse token = authService.updateToken(request.getRefreshToken());
        return ResponseEntity.ok(token);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtResponse> getNewRefreshToken(@RequestBody RefreshJwtRequest request) {
        final JwtResponse token = authService.refresh(request.getRefreshToken());
        return ResponseEntity.ok(token);
    }
}
