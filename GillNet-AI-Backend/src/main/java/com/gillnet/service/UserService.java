package com.gillnet.service;

import java.io.File;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
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
import com.gillnet.security.GoogleTokenVerifier;
import com.gillnet.security.JwtUtils;
import com.mongodb.client.MongoClient;
import org.springframework.boot.mongodb.autoconfigure.MongoProperties;
import jakarta.annotation.PostConstruct;

@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);
    private static final String STORE_FILE = "data/users_store.json";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final GoogleTokenVerifier googleTokenVerifier;
    private final JwtUtils jwtUtils;
    private final int signupCreditBonus;
    private final ObjectMapper objectMapper;
    private final String resolvedMongoUri;
    private final MongoProperties mongoProperties;
    private final MongoClient mongoClient;

    // Instant-access store
    private final Map<String, User> inMemoryUsers = new ConcurrentHashMap<>();
    private volatile boolean mongoOnline = false;

    public UserService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       GoogleTokenVerifier googleTokenVerifier,
                       JwtUtils jwtUtils,
                       @org.springframework.beans.factory.annotation.Value("${app.credits.signup-bonus:100}") int signupCreditBonus,
                       @org.springframework.beans.factory.annotation.Value("${spring.mongodb.uri:}") String resolvedMongoUri,
                       MongoProperties mongoProperties,
                       MongoClient mongoClient) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.googleTokenVerifier = googleTokenVerifier;
        this.jwtUtils = jwtUtils;
        this.signupCreditBonus = signupCreditBonus;
        this.resolvedMongoUri = resolvedMongoUri == null ? "" : resolvedMongoUri;
        this.mongoProperties = mongoProperties;
        this.mongoClient = mongoClient;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
    }

    @PostConstruct
    public void init() {
        // 0. Diagnostic: does the process actually see the Mongo env var, and what
        //    URI did Spring resolve? Credentials are never logged — only the host.
        boolean mongoEnvPresent = System.getenv("SPRING_DATA_MONGODB_URI") != null;
        log.info("MONGO DIAG — SPRING_DATA_MONGODB_URI present in process env: {}", mongoEnvPresent);
        // Never log credentials: keep only scheme + host.
        String maskedUri = resolvedMongoUri.replaceAll("://[^@]*@", "://***@");
        log.info("MONGO DIAG — resolved spring.mongodb.uri: {}", maskedUri.isEmpty() ? "<empty>" : maskedUri);
        // What do Spring Boot's MongoProperties and the actual driver client see?
        // (No credentials: hosts never contain userinfo.)
        try {
            String propsUri = mongoProperties.getUri();
            String maskedProps = propsUri == null ? "<null>"
                    : propsUri.replaceAll("://[^@]*@", "://***@");
            log.info("MONGO DIAG — MongoProperties.uri: {}", maskedProps.isEmpty() ? "<empty>" : maskedProps);
        } catch (Exception e) {
            log.info("MONGO DIAG — MongoProperties unreadable: {}", e.toString());
        }
        try {
            log.info("MONGO DIAG — MongoClient hosts: {}",
                    mongoClient.getClusterDescription().getClusterSettings().getHosts());
        } catch (Exception e) {
            log.info("MONGO DIAG — MongoClient hosts unreadable: {}", e.toString());
        }

        // 1. Load users from durable file storage if present
        loadUsersFromFile();

        // 2. Connect to MongoDB asynchronously if reachable
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
                // Log the cause (never includes credentials — driver exceptions
                // describe auth/network/timeout failures, not secrets).
                log.warn("MongoDB not reachable — operating with durable file-backed storage ({} users active). Cause: {}",
                        inMemoryUsers.size(), e.toString());
            }
        });
    }

    private synchronized void loadUsersFromFile() {
        try {
            File file = new File(STORE_FILE);
            if (file.exists() && file.length() > 0) {
                List<User> users = objectMapper.readValue(file, new TypeReference<List<User>>() {});
                for (User u : users) {
                    if (u.getEmail() != null) {
                        String emailKey = u.getEmail().toLowerCase().trim();
                        if (u.getPassword() == null || u.getPassword().isBlank()) {
                            // Never silently assign a known password. Force a proper reset instead.
                            log.warn("User {} has no password hash — account locked until password is reset", emailKey);
                        }
                        inMemoryUsers.put(emailKey, u);
                    }
                }
                log.info("Loaded {} user accounts from {}", inMemoryUsers.size(), STORE_FILE);
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

    /**
     * Real Google OAuth login: the ID token is cryptographically verified
     * against Google's public keys (signature, expiry, issuer, audience).
     * Claims are taken ONLY from the verified token — never from raw
     * client-supplied fields.
     */
    public UserResponseDTO loginWithGoogle(GoogleAuthRequest request) {
        String credential = request.getCredential();
        if (credential == null || credential.isBlank()) {
            throw new IllegalArgumentException("Google authentication failed: missing ID token.");
        }

        com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload payload =
                googleTokenVerifier.verify(credential);
        if (payload == null) {
            throw new IllegalArgumentException("Google authentication failed: invalid or expired Google credential.");
        }

        String email = payload.getEmail();
        boolean emailVerified = Boolean.TRUE.equals(payload.getEmailVerified());
        if (email == null || email.isBlank() || !emailVerified) {
            throw new IllegalArgumentException("Google authentication failed: email not verified by Google.");
        }

        String name = (String) payload.get("name");
        String picture = (String) payload.get("picture");

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
            log.info("Existing user {} logged in via verified Google OAuth", normalizedEmail);
        } else {
            user = new User();
            user.setId(UUID.randomUUID().toString());
            user.setName(name != null && !name.isBlank() ? name.trim() : normalizedEmail.split("@")[0]);
            user.setEmail(normalizedEmail);
            user.setPicture(picture);
            user.setAuthProvider("GOOGLE");
            user.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
            user.setCreatedAt(LocalDateTime.now());
            user.setCredits(signupCreditBonus);
            log.info("Created new user account via verified Google OAuth: {} ({} signup credits)", normalizedEmail, signupCreditBonus);
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
        user.setCredits(signupCreditBonus);

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
        user.setCredits(signupCreditBonus);

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

    /**
     * Resolve the authenticated user from an {@code Authorization: Bearer <token>} header.
     */
    public Optional<User> userFromAuthHeader(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return Optional.empty();
        }
        String token = authHeader.substring(7);
        if (!jwtUtils.validateToken(token)) {
            return Optional.empty();
        }
        String email = jwtUtils.getEmailFromToken(token);
        if (email == null) {
            return Optional.empty();
        }
        return findByEmail(email);
    }

    /**
     * Current credit balance. Legacy users that predate the credits system
     * are granted the signup bonus once, lazily.
     */
    public synchronized int getCredits(User user) {
        if (user.getCredits() == null) {
            user.setCredits(signupCreditBonus);
            saveUser(user);
        }
        return user.getCredits();
    }

    /**
     * Atomically consume credits. Returns {@code false} when the balance is
     * insufficient — the caller must then STOP the operation and tell the
     * user they are out of credits. There is no unlimited/permanent fallback.
     */
    public synchronized boolean tryConsumeCredits(User user, int amount) {
        int balance = getCredits(user);
        if (balance < amount) {
            return false;
        }
        user.setCredits(balance - amount);
        saveUser(user);
        return true;
    }

    public synchronized void addCredits(User user, int amount) {
        int balance = getCredits(user);
        user.setCredits(balance + amount);
        saveUser(user);
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
