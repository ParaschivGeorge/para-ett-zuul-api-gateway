package com.paraett.zuulapigateway.security;

import com.paraett.zuulapigateway.exception.AuthenticationException;
import com.paraett.zuulapigateway.exception.ForbiddenException;
import com.paraett.zuulapigateway.model.entities.Project;
import com.paraett.zuulapigateway.model.entities.User;
import com.paraett.zuulapigateway.model.enums.UserType;
import com.paraett.zuulapigateway.repository.ProjectRepository;
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
    private ProjectRepository projectRepository;

    public JwtAuthorizationTokenFilter(UserDetailsService userDetailsService, JwtTokenUtil jwtTokenUtil, String tokenHeader, UserRepository userRepository, ProjectRepository projectRepository) {
        this.userDetailsService = userDetailsService;
        this.jwtTokenUtil = jwtTokenUtil;
        this.tokenHeader = tokenHeader;
        this.userRepository = userRepository;
        this.projectRepository = projectRepository;
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

                        if (request.getRequestURI().length() >= uri.length() && request.getRequestURI().substring(0, uri.length()).equals(uri)) {

                            Long companyId = null;
                            if (request.getRequestURI().length() > uri.length()) {
                                companyId = Long.valueOf(request.getRequestURI().substring(uri.length() + 1));
                            }

                            if (companyId == null) {
                                throw new ForbiddenException("You must provide a company id");
                            } else {
                                if (!user.getCompanyId().equals(companyId)) {
                                    throw new ForbiddenException("This is not your company");
                                } else if (request.getMethod().equals(HttpMethod.PUT.name()) || request.getMethod().equals(HttpMethod.DELETE.name())) {
                                    if (user.getType() != UserType.OWNER) {
                                        throw new ForbiddenException("Only the owner can modify/delete the company");
                                    }
                                }
                            }
                        }

                        uri = "/free-days-service/free-days";

                        if (request.getRequestURI().length() >= uri.length() && request.getRequestURI().substring(0, uri.length()).equals(uri)) {
                            if (request.getMethod().equals(HttpMethod.POST.name()) || request.getMethod().equals(HttpMethod.PUT.name()) || request.getMethod().equals(HttpMethod.DELETE.name())) {
                                if (user.getType() != UserType.OWNER) {
                                    throw new ForbiddenException("Only the owner can add/mofidy/delete free days");
                                }
                                String companyId = request.getParameter("companyId");
                                if (companyId != null) {
                                    if (!Long.valueOf(companyId).equals(user.getCompanyId())) {
                                        throw new ForbiddenException("This is not your company");
                                    }
                                }
                            } else if (request.getMethod().equals(HttpMethod.GET.name())) {
                                if (request.getRequestURI().length() == uri.length()) {
                                    String companyId = request.getParameter("companyId");
                                    if (companyId != null) {
                                        if (!Long.valueOf(companyId).equals(user.getCompanyId())) {
                                            throw new ForbiddenException("This is not your company");
                                        }
                                    } else {
                                        throw new ForbiddenException("You must provide a company id");
                                    }
                                }
                            }
                        }

                        uri = "/requests-service/requests";

                        if (request.getRequestURI().length() >= uri.length() && request.getRequestURI().substring(0, uri.length()).equals(uri)) {
                            if (request.getMethod().equals(HttpMethod.GET.name()) || request.getMethod().equals(HttpMethod.DELETE.name())) {
                                if (request.getRequestURI().length() == uri.length()) {
                                    String companyId = request.getParameter("companyId");
                                    if (companyId != null) {
                                        if (!Long.valueOf(companyId).equals(user.getCompanyId())) {
                                            throw new ForbiddenException("This is not your company");
                                        }
                                    } else {
                                        throw new ForbiddenException("You must provide a company id");
                                    }
                                }
                            }
                        }

                        uri = "/timesheet-records-service/timesheet-records";

                        if (request.getRequestURI().length() >= uri.length() && request.getRequestURI().substring(0, uri.length()).equals(uri)) {
                            if (request.getMethod().equals(HttpMethod.GET.name()) || request.getMethod().equals(HttpMethod.DELETE.name())) {
                                if (request.getRequestURI().length() == uri.length()) {
                                    String companyId = request.getParameter("companyId");
                                    if (companyId != null) {
                                        if (!Long.valueOf(companyId).equals(user.getCompanyId())) {
                                            throw new ForbiddenException("This is not your company");
                                        }
                                    } else {
                                        throw new ForbiddenException("You must provide a company id");
                                    }
                                }
                            }
                        }

                        uri = "/users-service/users";

                        if (request.getRequestURI().length() >= uri.length() && request.getRequestURI().substring(0, uri.length()).equals(uri)) {
                            // GET and DELETE without ID
                            if (request.getRequestURI().length() == uri.length()) {
                                String companyId = request.getParameter("companyId");
                                if (companyId != null) {
                                    if (!Long.valueOf(companyId).equals(user.getCompanyId())) {
                                        throw new ForbiddenException("This is not your company");
                                    }
                                } else {
                                    throw new ForbiddenException("You must provide a company id");
                                }
                                if (request.getMethod().equals(HttpMethod.DELETE.name())) {
                                    if (user.getType() != UserType.OWNER) {
                                        throw new ForbiddenException("Only the company owner can do this");
                                    }
                                }
                            } else if (!request.getRequestURI().contains("/email")) {
                                Long userId = null;
                                if (request.getRequestURI().length() > uri.length()) {
                                    userId = Long.valueOf(request.getRequestURI().substring(uri.length() + 1));
                                }

                                if (userId == null) {
                                    throw new ForbiddenException("You must provide an user id");
                                } else {
                                    User requestUser = userRepository.findById(userId).get();
                                    if (request.getMethod().equals(HttpMethod.GET.name())) {
                                        if (!user.getCompanyId().equals(requestUser.getCompanyId())) {
                                            throw new ForbiddenException("This user is not part of your company");
                                        }
                                    } else if (request.getMethod().equals(HttpMethod.DELETE.name())) {
                                        if (!user.getCompanyId().equals(requestUser.getCompanyId()) || user.getType() != UserType.OWNER) {
                                            throw new ForbiddenException("Only the company owner can delete an employee");
                                        }
                                    } else if (request.getMethod().equals(HttpMethod.PUT.name())) {
                                        if (!user.getCompanyId().equals(requestUser.getCompanyId())) {
                                            throw new ForbiddenException("This is not your company");
                                        }
                                    }
                                }
                            }
                        }

                        uri = "/users-service/projects";

                        if (request.getRequestURI().length() >= uri.length() && request.getRequestURI().substring(0, uri.length()).equals(uri)) {
                            if (request.getRequestURI().length() == uri.length()) {
                                // POST
                                if (request.getMethod().equals(HttpMethod.POST.name())) {
                                    if (user.getType() != UserType.OWNER) {
                                        throw new ForbiddenException("Only the company owner can add projects");
                                    }
                                } else {
                                    // GET and DELETE without ID
                                    String companyId = request.getParameter("companyId");
                                    if (companyId != null) {
                                        if (!Long.valueOf(companyId).equals(user.getCompanyId())) {
                                            throw new ForbiddenException("This is not your company");
                                        }
                                    } else {
                                        throw new ForbiddenException("You must provide a company id");
                                    }
                                    if (request.getMethod().equals(HttpMethod.DELETE.name())) {
                                        if (user.getType() != UserType.OWNER) {
                                            throw new ForbiddenException("Only the company owner can do this");
                                        }
                                    }
                                }
                            } else {
                                Long projectId = null;
                                if (request.getRequestURI().length() > uri.length()) {
                                    projectId = Long.valueOf(request.getRequestURI().substring(uri.length() + 1));
                                }

                                if (projectId == null) {
                                    throw new ForbiddenException("You must provide a project id");
                                } else {
                                    Project project = projectRepository.findById(projectId).get();
                                    if (request.getMethod().equals(HttpMethod.GET.name())) {
                                        if (!user.getCompanyId().equals(project.getCompanyId())) {
                                            throw new ForbiddenException("This project is not from your company");
                                        }
                                    } else if (request.getMethod().equals(HttpMethod.DELETE.name())) {
                                        if (user.getType() != UserType.OWNER || !project.getCompanyId().equals(user.getCompanyId())) {
                                            throw new ForbiddenException("Only the company owner can delete the project");
                                        }
                                    } else if (request.getMethod().equals(HttpMethod.PUT.name())) {
                                        if ((!user.getId().equals(project.getResponsibleId())) && ((user.getType() != UserType.OWNER || !project.getCompanyId().equals(user.getCompanyId())))) {
                                            throw new ForbiddenException("Only the company owner and project responsible can update the project");
                                        }
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
                    logger.error("invalid username/email/userId/projectId", e);
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
