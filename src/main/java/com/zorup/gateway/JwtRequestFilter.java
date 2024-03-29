package com.zorup.gateway;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Optional;


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

            if(isRefreshRequest(uri)){
                logger.info(uri + " is token refresh request");

                String token = getRefreshToken(exchange).orElse(null);
                if (token == null)
                    return handleForbidden(exchange);

                if (validateToken(token) != 1){
                    logger.info("Error : token is not valid");
                    return handleUnAuthorized(exchange, null);
                }

                logger.info("Refresh-token is Valid, pass the token to auth-server");
                return chain.filter(exchange);
            }

            if (isJwtRequest(uri)) {
                String token = getAccessToken(exchange).orElse(null);
                int isValid = validateToken(token);
                if(token == null || isValid != 1){
                    logger.info("Error : token is not valid");
                    return handleUnAuthorized(exchange, isValid);
                }
                logger.info("Current Request token is Valid");
            }
            return chain.filter(exchange);
        });
    }

    private String getRequestUri(ServerWebExchange exchange) {
        String uri = exchange.getRequest().getURI().toString();
        logger.info("original uri: " + uri);
        int startIdx = uri.indexOf('/', 7); // skip "http://" and find index of '/'
        uri = uri.substring(startIdx);
        return uri;
    }

    private Optional<String> getAccessToken(ServerWebExchange exchange) {
        final int validIndex = 14;
        MultiValueMap<String, HttpCookie> cookie = exchange.getRequest().getCookies();
        if (cookie.get("X-Auth-Token") != null) {
            String a = cookie.get("X-Auth-Token").toString();
            a = a.substring(validIndex, a.length() - 1);
            logger.info(a);
            return Optional.of(a);
        }
        return Optional.empty();
    }

    private Optional<String> getRefreshToken(ServerWebExchange exchange) {
        List<String> headers = exchange.getRequest().getHeaders().get("Authorization");
        if (headers == null) {
            logger.info("No Authorization header");
            return Optional.empty();
        }

        for(String header: headers){
            String type = "refresh";
            if (header.toLowerCase().startsWith(type.toLowerCase()))
                return Optional.of(header.substring(type.length()).trim());
        }

        logger.info("No refresh-token inside Authorization header");
        return Optional.empty();
    }

    private boolean isJwtRequest(String uri) {
        switch (uri) {
            case "/":
            case "/login":
            case "/register":
            case "/forgot":
            case "/auth/v1/signin":
            case "/auth/v1/login":
                return false;
            default:
                return true;
        }
    }

    private boolean isRefreshRequest(String uri) {
        if (uri.equals("/auth/v1/refresh"))
            return true;
        else
            return false;
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

    private int validateToken(String jwtToken){
        try{
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey.getBytes(StandardCharsets.UTF_8)).parseClaimsJws(jwtToken);
            //토큰이 유효한 경우
            return 1;
        } catch(ExpiredJwtException e){
            //유효한 토큰이나 시간이 만료된 경우
            return 2;
        } catch (Exception e){
            //토큰 서명 자체에 문제가 있는 경우
            return 3;
        }
    }

    private Mono<Void> handleUnAuthorized(ServerWebExchange exchange, Integer isValid) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        if(isValid != null && isValid == 2){
            byte[] bytes = "Expired".getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            return exchange.getResponse().writeWith(Flux.just(buffer));
        } else {
            return response.setComplete();
        }
    }

    private Mono<Void> handleForbidden(ServerWebExchange exchange){
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();  // 처리 끝을 알리고 반환
    }

    @Data
    public static class Config {
        private String baseMessage;
    }
}
