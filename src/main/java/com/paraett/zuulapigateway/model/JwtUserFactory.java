package com.paraett.zuulapigateway.model;

import com.paraett.zuulapigateway.model.dtos.JwtGrantedAuthority;
import com.paraett.zuulapigateway.model.dtos.JwtUser;
import com.paraett.zuulapigateway.model.entities.User;
import com.paraett.zuulapigateway.model.enums.UserType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;

public final class JwtUserFactory {

    private JwtUserFactory() {
    }

    public static JwtUser create(User user) {
        return new JwtUser(
                user.getId(),
                user.getFirstName() + " " + user.getLastName(),
                user.getEmail(),
                user.getPassword(),
                mapToGrantedAuthorities(user.getType()),
                user.isEnabled(),
                user.getLastPasswordResetDate()
        );
    }

    private static List<JwtGrantedAuthority> mapToGrantedAuthorities(UserType type) {
        ArrayList<JwtGrantedAuthority> authorities = new ArrayList<JwtGrantedAuthority>();
        authorities.add(new JwtGrantedAuthority(type.name()));
        return authorities;
    }
}
