package vn.edu.hcmuaf.cdw.ShopThoiTrang.service.impl;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.JWT.JwtUtils;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.entity.RefreshToken;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.entity.Role;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.entity.User;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.entity.UserInfo;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.model.dto.GoogleAccountDto;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.model.dto.JwtResponse;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.reponsitory.UserInfoRepository;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.reponsitory.UserRepository;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.service.GoogleService;
import com.google.api.client.json.JsonFactory;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.service.RefreshTokenService;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.Date;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class GoogleServiceImpl implements GoogleService {
    private static final Logger Log = Logger.getLogger(GoogleServiceImpl.class.getName());
    @Autowired
    private JwtUtils jwtUtils;
    private final GoogleIdTokenVerifier verifier;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private UserInfoRepository userInfoRepository;
    @Autowired
    private RefreshTokenService refreshTokenService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public GoogleServiceImpl(@Value("${spring.security.oauth2.client.registration.google.client-id}") String clientId) {
        NetHttpTransport transport = new NetHttpTransport();
        JsonFactory jsonFactory = new JacksonFactory();
        verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
                .setAudience(Collections.singletonList(clientId))
                .build();
    }

    @Override
    public ResponseEntity<?> login_google(String token) {
        try {
            Log.info("Received Google login request with token length: " + (token != null ? token.length() : 0));
            GoogleAccountDto user = verifyIDToken(token);
            if (user == null) {
                Log.error("Failed to verify Google ID token");
                throw new IllegalArgumentException("Invalid Google ID token");
            }
            Log.info("Successfully verified Google ID token, creating/updating user");
            createOrUpdateUser(user);
            User userDetails = userRepository.findByUsername(user.getEmail()).get();
            if (!userDetails.getRole().getName().equals("USER")) {
                Log.warn(user.getEmail() + " unauthorized to login with google account");
                return new ResponseEntity<>("unauthorized ", HttpStatus.NOT_ACCEPTABLE);
            }
            List<String> permissions = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

            ResponseCookie jwtRefreshCookie = jwtUtils.generateRefreshJwtCookie(refreshToken.getToken(), "shop2h_refresh");
            ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails, "shop2h");
            
            Log.info("Successfully generated JWT tokens for user: " + user.getEmail());
            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                    .header(HttpHeaders.SET_COOKIE, jwtRefreshCookie.toString()).body(new JwtResponse(
                            userDetails.getId(),
                            userDetails.getUsername(),
                            permissions));
        } catch (IllegalArgumentException e) {
            Log.error("Error in login_google: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    @Transactional
    public void createOrUpdateUser(GoogleAccountDto user) {
        try {
            // First try to find user by username (email)
            User existingUser = userRepository.findByUsername(user.getEmail()).orElse(null);
            
            if (existingUser == null) {
                // Create new user if not found
                existingUser = new User();
                existingUser.setUserInfo(new UserInfo());
                existingUser.getUserInfo().setEmail(user.getEmail());
                existingUser.getUserInfo().setFullName(user.getLastName() + " " + user.getFirstName());
                existingUser.getUserInfo().setAvtUrl(user.getPictureUrl());
                existingUser.setRole(new Role(2L, "USER"));
                existingUser.setEnabled(true);
                existingUser.setUsername(user.getEmail());
                // Set a default encrypted password for Google-authenticated users
                existingUser.setPasswordEncrypted(passwordEncoder.encode("GOOGLE_AUTH_" + user.getEmail()));
                existingUser.getUserInfo().setUser(existingUser);
                Date date = new Date(System.currentTimeMillis());
                existingUser.setCreatedDate(date);
                existingUser.setUpdateDate(date);
                userRepository.save(existingUser);
            }
        } catch (Exception e) {
            Log.error("Error in createOrUpdateUser: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private GoogleAccountDto verifyIDToken(String idToken) {
        try {
            Log.info("Attempting to verify Google ID token");
            GoogleIdToken idTokenObj = verifier.verify(idToken);
            if (idTokenObj == null) {
                Log.error("Failed to verify Google ID token - token is null");
                return null;
            }
            GoogleIdToken.Payload payload = idTokenObj.getPayload();
            String firstName = (String) payload.get("given_name");
            String lastName = (String) payload.get("family_name");
            String email = payload.getEmail();
            String pictureUrl = (String) payload.get("picture");

            Log.info("Successfully verified Google ID token for email: " + email);
            return new GoogleAccountDto(firstName, lastName, email, pictureUrl);
        } catch (GeneralSecurityException | IOException e) {
            Log.error("Error in verifyIDToken at GoogleServiceImpl: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
}
