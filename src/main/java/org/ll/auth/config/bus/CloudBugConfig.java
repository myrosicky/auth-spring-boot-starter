package org.ll.auth.config.bus;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnProperty("cloudms.bus.enabled")
@Slf4j
public class CloudBugConfig {

    @Bean
    String what(){
        return "";
    }
}
