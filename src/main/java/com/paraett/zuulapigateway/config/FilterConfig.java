package com.paraett.zuulapigateway.config;

import com.paraett.zuulapigateway.security.BasicAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {
    @Bean
    public BasicAuthFilter getAuthenticatedFilter () {
        return new BasicAuthFilter();
    }
}
