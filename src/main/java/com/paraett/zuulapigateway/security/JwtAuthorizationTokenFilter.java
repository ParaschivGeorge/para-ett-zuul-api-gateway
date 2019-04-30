package com.paraett.zuulapigateway.security;

import com.paraett.zuulapigateway.exception.AuthenticationException;
import com.paraett.zuulapigateway.model.entities.User;
import com.paraett.zuulapigateway.model.enums.UserType;
import com.paraett.zuulapigateway.repository.UserRepository;
import io.jsonwebtoken.ExpiredJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.NoSuchElementException;
import java.util.Optional;

public class JwtAuthorizationTokenFilter extends OncePerRequestFilter {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private UserDetailsService userDetailsService;
    private JwtTokenUtil jwtTokenUtil;
    private String tokenHeader;
    private UserRepository userRepository;

    public JwtAuthorizationTokenFilter(UserDetailsService userDetailsService, JwtTokenUtil jwtTokenUtil, String tokenHeader, UserRepository userRepository) {
        this.userDetailsService = userDetailsService;
        this.jwtTokenUtil = jwtTokenUtil;
        this.tokenHeader = tokenHeader;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        logger.info("processing authentication for '{}'", request.getRequestURL());

        final String requestHeader = request.getHeader(this.tokenHeader);

        String username = null;
        String authToken = null;

        logger.info("Header is: {}", requestHeader);

        if (requestHeader != null && requestHeader.startsWith("Bearer ")) {
            authToken = requestHeader.substring(7);
            try {
                username = jwtTokenUtil.getUsernameFromToken(authToken);
            } catch (IllegalArgumentException e) {
                logger.error("an error occured during getting username from token", e);
            } catch (ExpiredJwtException e) {
                logger.warn("the token is expired and not valid anymore", e);
            }
        } else {
            logger.warn("couldn't find bearer string, will ignore the header");
        }

        logger.debug("checking authentication for user '{}'", username);
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            logger.debug("security context was null, so authorizating user");

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            if (jwtTokenUtil.validateToken(authToken, userDetails)) {

                /* Add rules here */
                Optional<User> optionalUser = userRepository.findByEmail(username);
                try {
                    User user = optionalUser.get();

                    // allow admin all actions
                    if (user.getType() != UserType.ADMIN) {

                        String uri = "/companies-service/companies";

                        if (request.getRequestURI().substring(0, uri.length()).equals(uri)) {

                            Long companyId = null;
                            if (request.getRequestURI().length() > uri.length()) {
                                companyId = Long.valueOf(request.getRequestURI().substring(uri.length() + 1));
                            }

                            if (companyId == null) {
                                throw new AuthenticationException("You must provide a company id");
                            } else {
                                if (user.getCompanyId() != companyId) {
                                    throw new AuthenticationException("This is not your company");
                                } else if (request.getMethod().equals(HttpMethod.PUT.name()) || request.getMethod().equals(HttpMethod.DELETE.name())) {
                                    if (user.getType() != UserType.OWNER) {
                                        throw new AuthenticationException("Only the owner can modify/delete the company");
                                    }
                                }
                            }
                        }
                    }

                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    logger.info("authorizated user '{}', setting security context", username);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } catch (NoSuchElementException e) {
                    logger.error("invalid username email", e);
                } catch (AuthenticationException e) {
                    logger.error("error while checking authorization", e);
                } catch (Exception e) {
                    logger.error("error while checking authorization", e);
                }
            }
        }

        chain.doFilter(request, response);
    }
}
