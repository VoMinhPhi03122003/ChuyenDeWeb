package vn.edu.hcmuaf.cdw.ShopThoiTrang.filters;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.JWT.JwtUtils;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.config.FrontendProperties;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.entity.RefreshToken;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.exception.TokenRefreshException;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.service.RefreshTokenService;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.service.UserService;
import vn.edu.hcmuaf.cdw.ShopThoiTrang.service.impl.UserDetailsServiceImpl;


public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private FrontendProperties frontendProperties;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @Autowired
    RefreshTokenService refreshTokenService;
    @Autowired
    UserService userService;
    private static final Logger logger = Logger.getLogger(AuthTokenFilter.class.getName());

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            // Skip JWT validation for Google login endpoint
            if (request.getRequestURI().equals("/api/auth/google")) {
                logger.debug("Skipping JWT validation for Google login request");
                filterChain.doFilter(request, response);
                return;
            }

            String requestOrigin = request.getHeader("origin");
            String jwtName = (requestOrigin.equals(frontendProperties.getUrl()) || requestOrigin.equals("http://localhost:3000")) ? "shop2h" :
                    (requestOrigin.equals(frontendProperties.getAdmin()) || requestOrigin.equals("http://localhost:3001")) ? "shop2h_admin" : null;
            if (jwtName == null) {
                logger.error("Unknown origin: " + requestOrigin);
                throw new RuntimeException("Unknown site");
            }

            String jwt = parseJwt(request, jwtName);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                String username = jwtUtils.getUserNameFromJwtToken(jwt);
                logger.debug("Valid JWT token found for user: " + username);

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                logger.debug("JWT token invalid or missing, checking refresh token");
                String refreshToken = jwtUtils.getJwtRefreshFromCookies(request, jwtName + "_refresh");
                
                if (refreshToken != null) {
                    try {
                        RefreshToken token = refreshTokenService.findByToken(refreshToken)
                                .map(refreshTokenService::verifyExpiration)
                                .orElseThrow(() -> new TokenRefreshException(refreshToken, "Refresh token is not valid or expired!"));

                        UserDetails userDetails = userDetailsService.loadUserByUsername(token.getUser().getUsername());
                        ResponseCookie newJwtToken = jwtUtils.generateJwtCookie(userService.getUserByUsername(userDetails.getUsername()), jwtName);
                        response.addHeader(HttpHeaders.SET_COOKIE, newJwtToken.toString());

                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        
                        logger.debug("Successfully refreshed token for user: " + userDetails.getUsername());
                    } catch (TokenRefreshException e) {
                        logger.warn("Failed to refresh token: " + e.getMessage());
                        // Clear the invalid refresh token cookie
                        ResponseCookie cleanRefreshToken = jwtUtils.getCleanJwtRefreshCookie(jwtName + "_refresh");
                        response.addHeader(HttpHeaders.SET_COOKIE, cleanRefreshToken.toString());
                    }
                } else {
                    logger.debug("No refresh token found in cookies");
                }
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: " + e.getMessage(), e);
        }
        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request, String jwtCookie_name) {
        return jwtUtils.getJwtFromCookies(request, jwtCookie_name);
    }
}