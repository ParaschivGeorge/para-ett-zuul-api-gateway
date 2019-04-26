package com.paraett.zuulapigateway.security;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;

public class BasicAuthFilter extends ZuulFilter {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request =
                ctx.getRequest();
        logger.info("request -> {} request uri -> {}",
                request, request.getRequestURI());
        ctx.addZuulRequestHeader("Authorization", "Basic cGFyYS1ldHQtZ2F0ZXdheTphc2QxMjNnaGo1NjdBU0QhQCNHSEolXiY=");
        return null;
    }
}
