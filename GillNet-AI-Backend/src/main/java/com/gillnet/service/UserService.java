package com.gillnet.service;

import java.io.File;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.gillnet.dto.GoogleAuthRequest;
import com.gillnet.dto.RegisterRequest;
import com.gillnet.dto.UserResponseDTO;
import com.gillnet.model.User;
import com.gillnet.repository.UserRepository;

import jakarta.annotation.PostConstruct;

@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);
    private static final String STORE_FILE = "data/users_store.json";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ObjectMapper objectMapper;

    // Instant-access store
    private final Map<String, User> inMemoryUsers = new ConcurrentHashMap<>();
    private volatile boolean mongoOnline = false;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
    }

    @PostConstruct
    public void init() {
        // 1. Load users from durable file storage if present
        loadUsersFromFile();

        // 2. Ensure default demo user exists
        seedDefaultUser();

        // 3. Connect to MongoDB asynchronously if reachable
        CompletableFuture.runAsync(() -> {
            try {
                userRepository.count();
                mongoOnline = true;
                log.info("MongoDB connection verified — operating with database persistence");
                List<User> dbUsers = userRepository.findAll();
                for (User u : dbUsers) {
                    if (u.getEmail() != null) {
                        inMemoryUsers.put(u.getEmail().toLowerCase().trim(), u);
                    }
                }
                saveUsersToFile();
            } catch (Exception e) {
                mongoOnline = false;
                log.info("MongoDB not reachable — operating with durable file-backed storage ({} users active)", inMemoryUsers.size());
            }
        });
    }

    private void seedDefaultUser() {
        String defaultEmail = "alex@gillnet.ai";
        if (!inMemoryUsers.containsKey(defaultEmail)) {
            User demoUser = new User();
            demoUser.setId("usr-alex-001");
            demoUser.setName("Alex Rivera");
            demoUser.setEmail(defaultEmail);
            demoUser.setPassword(passwordEncoder.encode("StrongSecurePassword123!"));
            demoUser.setCreatedAt(LocalDateTime.now());
            inMemoryUsers.put(defaultEmail, demoUser);
            saveUsersToFile();
        }
    }

    private synchronized void loadUsersFromFile() {
        try {
            File file = new File(STORE_FILE);
            if (file.exists() && file.length() > 0) {
                List<User> users = objectMapper.readValue(file, new TypeReference<List<User>>() {});
                boolean needsSave = false;
                for (User u : users) {
                    if (u.getEmail() != null) {
                        String emailKey = u.getEmail().toLowerCase().trim();
                        // Fix legacy users that had passwords dropped by earlier serialization bug:
                        if (u.getPassword() == null || u.getPassword().isBlank()) {
                            u.setPassword(passwordEncoder.encode("Password123!"));
                            needsSave = true;
                            log.info("Repaired missing password hash for legacy user account: {}", emailKey);
                        }
                        inMemoryUsers.put(emailKey, u);
                    }
                }
                log.info("Loaded {} user accounts from {}", inMemoryUsers.size(), STORE_FILE);
                if (needsSave) {
                    saveUsersToFile();
                }
            }
        } catch (Exception e) {
            log.warn("Failed to load users from {}: {}", STORE_FILE, e.getMessage());
        }
    }

    private synchronized void saveUsersToFile() {
        try {
            File file = new File(STORE_FILE);
            File parent = file.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(file, new ArrayList<>(inMemoryUsers.values()));
        } catch (Exception e) {
            log.warn("Failed to persist users to {}: {}", STORE_FILE, e.getMessage());
        }
    }

    public UserResponseDTO loginWithGoogle(GoogleAuthRequest request) {
        String email = null;
        String name = null;
        String picture = null;
        String googleId = null;

        if (request.getCredential() != null && !request.getCredential().isBlank()) {
            try {
                String[] parts = request.getCredential().split("\\.");
                if (parts.length >= 2) {
                    byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
                    Map<String, Object> claims = objectMapper.readValue(decoded, new TypeReference<Map<String, Object>>() {});
                    if (claims.containsKey("email")) {
                        email = String.valueOf(claims.get("email"));
                    }
                    if (claims.containsKey("name")) {
                        name = String.valueOf(claims.get("name"));
                    }
                    if (claims.containsKey("picture")) {
                        picture = String.valueOf(claims.get("picture"));
                    }
                    if (claims.containsKey("sub")) {
                        googleId = String.valueOf(claims.get("sub"));
                    }
                }
            } catch (Exception ex) {
                log.warn("Failed to decode Google JWT token: {}", ex.getMessage());
            }
        }

        // Fallback to direct fields
        if (email == null && request.getEmail() != null) email = request.getEmail();
        if (name == null && request.getName() != null) name = request.getName();
        if (picture == null && request.getPicture() != null) picture = request.getPicture();
        if (googleId == null && request.getGoogleId() != null) googleId = request.getGoogleId();

        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("Google authentication failed: Email address was not provided.");
        }

        String normalizedEmail = email.toLowerCase().trim();
        Optional<User> existing = findByEmail(normalizedEmail);
        User user;

        if (existing.isPresent()) {
            user = existing.get();
            if (name != null && !name.isBlank()) {
                user.setName(name.trim());
            }
            if (picture != null) {
                user.setPicture(picture);
            }
            user.setAuthProvider("GOOGLE");
            log.info("Existing user {} logged in via Google OAuth", normalizedEmail);
        } else {
            user = new User();
            user.setId(UUID.randomUUID().toString());
            user.setName(name != null && !name.isBlank() ? name.trim() : normalizedEmail.split("@")[0]);
            user.setEmail(normalizedEmail);
            user.setPicture(picture);
            user.setAuthProvider("GOOGLE");
            user.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
            user.setCreatedAt(LocalDateTime.now());
            log.info("Created new user account via Google OAuth: {}", normalizedEmail);
        }

        saveUser(user);
        return UserResponseDTO.fromEntity(user);
    }

    public UserResponseDTO register(RegisterRequest request) {
        String email = request.getEmail().toLowerCase().trim();

        Optional<User> existing = findByEmail(email);
        if (existing.isPresent()) {
            User user = existing.get();
            // If the returning user enters their existing correct password, allow them to log in smoothly!
            if (passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                log.info("Returning user {} authenticated via register/signup flow", email);
                return UserResponseDTO.fromEntity(user);
            } else {
                throw new IllegalArgumentException("An account with this email already exists. Please sign in with your password.");
            }
        }

        User user = new User();
        user.setId(UUID.randomUUID().toString());
        user.setName(request.getName().trim());
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setCreatedAt(LocalDateTime.now());

        User savedUser = saveUser(user);
        return UserResponseDTO.fromEntity(savedUser);
    }

    public User registerUser(User user) {
        String email = user.getEmail().toLowerCase().trim();

        if (findByEmail(email).isPresent()) {
            throw new IllegalArgumentException("Email is already registered");
        }

        if (user.getId() == null) {
            user.setId(UUID.randomUUID().toString());
        }
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setCreatedAt(LocalDateTime.now());

        return saveUser(user);
    }

    public Optional<User> authenticate(String email, String rawPassword) {
        if (email == null || rawPassword == null) {
            return Optional.empty();
        }
        Optional<User> userOpt = findByEmail(email.toLowerCase().trim());
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            if (passwordEncoder.matches(rawPassword, user.getPassword())) {
                return Optional.of(user);
            }
        }
        return Optional.empty();
    }

    public void resetPassword(String email, String newPassword) {
        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("Email is required");
        }
        if (newPassword == null || newPassword.trim().length() < 6) {
            throw new IllegalArgumentException("Password must be at least 6 characters long");
        }

        String normalizedEmail = email.toLowerCase().trim();
        Optional<User> userOpt = findByEmail(normalizedEmail);
        if (userOpt.isEmpty()) {
            throw new IllegalArgumentException("No account found with this email address (" + email + ").");
        }

        User user = userOpt.get();
        user.setPassword(passwordEncoder.encode(newPassword));
        saveUser(user);
        log.info("Password successfully reset and updated for user {}", normalizedEmail);
    }

    public Optional<User> findByEmail(String email) {
        if (email == null) return Optional.empty();
        String normalizedEmail = email.toLowerCase().trim();
        User memUser = inMemoryUsers.get(normalizedEmail);
        if (memUser != null) {
            return Optional.of(memUser);
        }

        if (mongoOnline) {
            try {
                Optional<User> fromDb = userRepository.findByEmail(normalizedEmail);
                if (fromDb.isPresent()) {
                    inMemoryUsers.put(normalizedEmail, fromDb.get());
                    saveUsersToFile();
                    return fromDb;
                }
            } catch (Exception e) {
                mongoOnline = false;
            }
        }

        return Optional.empty();
    }

    public Optional<User> findById(String id) {
        if (id == null) return Optional.empty();
        for (User u : inMemoryUsers.values()) {
            if (id.equals(u.getId())) {
                return Optional.of(u);
            }
        }

        if (mongoOnline) {
            try {
                Optional<User> fromDb = userRepository.findById(id);
                if (fromDb.isPresent()) {
                    inMemoryUsers.put(fromDb.get().getEmail().toLowerCase().trim(), fromDb.get());
                    saveUsersToFile();
                    return fromDb;
                }
            } catch (Exception e) {
                mongoOnline = false;
            }
        }

        return Optional.empty();
    }

    private User saveUser(User user) {
        if (user.getId() == null) {
            user.setId(UUID.randomUUID().toString());
        }
        inMemoryUsers.put(user.getEmail().toLowerCase().trim(), user);
        saveUsersToFile();

        if (mongoOnline) {
            CompletableFuture.runAsync(() -> {
                try {
                    userRepository.save(user);
                } catch (Exception e) {
                    mongoOnline = false;
                }
            });
        }

        return user;
    }
}
