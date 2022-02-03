package org.ll.auth.config.web.reactive;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.asm.TypeReference;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.ConversionService;
import org.springframework.http.HttpMethod;
import org.springframework.util.ClassUtils;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.web.reactive.function.server.RequestPredicates.GET;

@Configuration
@ConditionalOnProperty("cloudms.web.reactive.enabled")
@Slf4j
public class ReactiveConfig {

    private ObjectMapper om = new ObjectMapper();

    @Bean @ConfigurationProperties("cloudms.web")
    public WebConfigProperties webConfigProperties(){
        return new WebConfigProperties();
    }

    @Bean
    public RouterFunction<ServerResponse> routerFunction(WebConfigProperties webConfigProperties) {
        RouterFunctions.Builder b = RouterFunctions.route();
        for(WebConfigProperties.Path path: webConfigProperties.getPaths()) {
            if(path.getMethod()== HttpMethod.GET) {
                b.GET(path.getUri(), req -> {
                    Map<String, String> headers = req.headers().asHttpHeaders().entrySet().stream().collect(Collectors.toMap(
                            Map.Entry::getKey, e-> String.join(",", e.getValue())));
//                    Object reqVO = ClassUtils.forName(webConfigProperties.getReqVO(), ClassUtils.getDefaultClassLoader());
//                    reqVO = om.convertValue(headers, reqVO.getClass());
//                    path.getControllerFunc();
                });
            }

        }
        return b.build();
    }

}
