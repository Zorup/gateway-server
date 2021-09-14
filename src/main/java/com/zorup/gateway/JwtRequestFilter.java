package com.zorup.gateway;

import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import reactor.core.publisher.Mono;

@Component
public class JwtRequestFilter extends AbstractGatewayFilterFactory<JwtRequestFilter.Config> {
    private static final Logger logger = LogManager.getLogger(JwtRequestFilter.class);

    public JwtRequestFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) { //토큰의 존재여부는 잡음 
        return ((exchange, chain) -> {
            logger.info("JwtRequestFilter : " + config.getBaseMessage());
            String uri = getRequestUri(exchange);
            logger.info("Request Uri :: " + uri);

            if(isResouceRequest(uri)){
                logger.info(uri + " is web static Resource Request");
                return chain.filter(exchange);
            }
            if (isJwtRequest(uri)) {
                String token = getAccessToken(exchange);
                if (token == "") {
                    logger.info("X_auth_token not Exist");
                    exchange.getResponse().setStatusCode(HttpStatus.valueOf(401));
                    return Mono.empty();
                }
                logger.info("token value : " + token);
            }
            return chain.filter(exchange);
        });
    }

    private String getRequestUri(org.springframework.web.server.ServerWebExchange exchange) {
        String uri = exchange.getRequest().getURI().toString().substring(21);
        return uri;
    }

    private String getAccessToken(org.springframework.web.server.ServerWebExchange exchange) {
        final int validIndex = 14;
        MultiValueMap<String, HttpCookie> cookie = exchange.getRequest().getCookies();
        String a = "";
        if (cookie.get("X-Auth-Token") != null) {
            a = cookie.get("X-Auth-Token").toString();
            a = a.substring(validIndex, a.length() - 1);
        }
        return a;
    }

    private boolean isJwtRequest(String uri) {
        switch (uri) {
            case "/":
            case "/login":
            case "/register":
            case "/forgot":
            case "/v1/signin":
            case "/v1/login":
                return false;
            default:
                return true;
        }
    }

    private boolean isResouceRequest(String uri){
        if(uri.length()<4) return false;
        String s = uri.substring(0, 4);
        logger.info("substring : " + s);
        switch (s){
            case "/img":
            case"/js/":
            case"/ven":
            case"/css":
                return true;
            default:
                return false;
        }
    }

    @Data
    public static class Config {
        private String baseMessage;
    }
}
