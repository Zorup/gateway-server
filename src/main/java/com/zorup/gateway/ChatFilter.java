package com.zorup.gateway;


import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;


@Component
public class ChatFilter extends AbstractGatewayFilterFactory<ChatFilter.Config> {
    private static final Logger logger = LogManager.getLogger(PostFilter.class);
    public ChatFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            logger.info("ChatFilter baseMessage>>>>>>" + config.getBaseMessage());
            if (config.isPreLogger()) {
                logger.info("ChatFilter Start>>>>>>" + exchange.getRequest());
            }
            return chain.filter(exchange).then(Mono.fromRunnable(()->{
                if (config.isPostLogger()) {
                    logger.info("ChatFilter End>>>>>>" + exchange.getResponse());
                }
            }));
        });
    }

    @Data
    public static class Config {
        private String baseMessage;
        private boolean preLogger;
        private boolean postLogger;
    }
}