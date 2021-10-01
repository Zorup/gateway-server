package com.zorup.gateway;

import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import java.nio.charset.StandardCharsets;
import java.util.Date;


@Component
public class JwtRequestFilter extends AbstractGatewayFilterFactory<JwtRequestFilter.Config> {
    private static final Logger logger = LogManager.getLogger(JwtRequestFilter.class);
    @Value("${jwt.secret}")
    private String secretKey;

    public JwtRequestFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
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
                if(!validateToken(token)){
                    logger.info("Error : token is not valid");
                    return handleUnAuthorized(exchange);
                }
                logger.info("Current Request token is Valid");
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
            logger.info(a);
        }
        return a;
    }

    private boolean isJwtRequest(String uri) {
        // 후에 인증서버 추가시 그쪽 uri에 맞게 수정 필요, 현재는 main서버쪽 uri로 되어있음
        switch (uri) {
            case "/":
            case "/login":
            case "/register":
            case "/forgot":
            case "/auth/v1/signin":
            case "/auth/v1/login":
            case "/auth/v1/refresh":    // TODO refresh토큰 검증로직 추가 후 이 case는 삭제해야함
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

    private boolean validateToken(String jwtToken){
        try{
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey.getBytes(StandardCharsets.UTF_8)).parseClaimsJws(jwtToken);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception e){
            return false;
        }
    }

    private Mono<Void> handleUnAuthorized(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }


    @Data
    public static class Config {
        private String baseMessage;
    }
}
