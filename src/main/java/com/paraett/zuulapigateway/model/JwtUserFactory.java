package com.paraett.zuulapigateway.model;

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
                user.getEmail(),
                user.getPassword(),
                mapToGrantedAuthorities(user.getType()),
                user.isEnabled(),
                user.getLastPasswordResetDate()
        );
    }

    private static List<GrantedAuthority> mapToGrantedAuthorities(UserType type) {
        ArrayList<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority(type.name()));
        return authorities;
    }
}
