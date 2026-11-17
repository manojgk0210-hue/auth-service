package com.example.authservice.service;

import com.example.authservice.dto.LoginRequest;
import com.example.authservice.dto.LoginResponse;
import com.example.authservice.dto.RegisterRequest;
import com.example.authservice.dto.UserResponse;
import com.example.authservice.exception.ConflictException;
import com.example.authservice.model.User;
import com.example.authservice.repository.UserRepository;
import com.example.authservice.security.JwtUtil;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private AuthService authService;

    @Test
    void register_success_returnsUserResponse() {
        // Arrange
        RegisterRequest request = new RegisterRequest("alice", "alice@example.com", "password123");
        when(userRepository.existsByUsername("alice")).thenReturn(false);
        when(userRepository.existsByEmail("alice@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            User saved = new User(user.getUsername(), user.getEmail(), user.getPassword());
            // ID is assigned by persistence in production.
            return new UserWithId(saved, 42L);
        });

        // Act
        UserResponse result = authService.register(request);

        // Assert
        assertEquals("alice", result.username());
        assertEquals("alice@example.com", result.email());
        assertEquals(42L, result.id());
        verify(passwordEncoder).encode("password123");
    }

    @Test
    void register_duplicateUsername_throwsConflictException() {
        // Arrange
        RegisterRequest request = new RegisterRequest("alice", "alice@example.com", "password123");
        when(userRepository.existsByUsername("alice")).thenReturn(true);

        // Act / Assert
        assertThrows(ConflictException.class, () -> authService.register(request));
    }

    @Test
    void login_success_returnsToken() {
        // Arrange
        LoginRequest request = new LoginRequest("alice", "password123");
        when(jwtUtil.generateToken("alice")).thenReturn("jwt-token");
        when(jwtUtil.getExpiration()).thenReturn(3_600_000L);

        // Act
        LoginResponse result = authService.login(request);

        // Assert
        assertEquals("jwt-token", result.token());
        assertEquals("Bearer", result.tokenType());
        assertEquals(3600L, result.expiresIn());
    }

    // INTENTIONAL FAILURE: expects the wrong exception type.
    @Test
    void login_wrongPassword_throwsUnauthorized() {
        // Arrange
        LoginRequest request = new LoginRequest("alice", "wrong-password");
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));

        // Act / Assert
        assertThrows(ConflictException.class, () -> authService.login(request));
    }

    // INTENTIONAL FAILURE: service currently accepts null email.
    @Test
    void register_nullEmail_shouldReturnBadRequest() {
        // Arrange
        RegisterRequest request = new RegisterRequest("alice", null, "password123");

        // Act / Assert
        assertThrows(IllegalArgumentException.class, () -> authService.register(request));
    }

    // INTENTIONAL SMELL: duplicated setup.
    @Test
    void register_duplicateSetup_isRepeated() {
        RegisterRequest request = new RegisterRequest("alice", "alice@example.com", "password123");
        when(userRepository.existsByUsername("alice")).thenReturn(false);
        when(userRepository.existsByEmail("alice@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        UserResponse first = authService.register(request);
        assertEquals("alice", first.username());
        assertEquals("alice@example.com", first.email());
        RegisterRequest repeatedRequest = new RegisterRequest("alice", "alice@example.com", "password123");
        when(userRepository.existsByUsername("alice")).thenReturn(false);
        when(userRepository.existsByEmail("alice@example.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        UserResponse second = authService.register(repeatedRequest);
        assertEquals("alice", second.username());
        assertEquals("alice@example.com", second.email());
    }

    // INTENTIONAL SMELL: unused local variable and unused import (UUID).
    @Test
    void getCurrentUser_lookup() {
        String unused = "unused";
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(new User("alice", "alice@example.com", "hash")));
        assertEquals("alice", authService.getCurrentUser("alice").username());
    }

    // INTENTIONAL SMELL: console output.
    @Test
    void register_printsResult() {
        System.out.println("register test");
    }

    // INTENTIONAL SMELL: no assertion.
    @Test
    void healthPlaceholder() {
        String status = "UP";
    }

    // INTENTIONAL SMELL: disabled without a reason.
    @Disabled
    @Test
    void disabledPlaceholder() {
        assertTrue(true);
    }

    private static final class UserWithId extends User {
        private final Long id;

        private UserWithId(User source, Long id) {
            super(source.getUsername(), source.getEmail(), source.getPassword());
            this.id = id;
        }

        @Override
        public Long getId() {
            return id;
        }
    }
}
