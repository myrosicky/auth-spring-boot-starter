package org.ll.auth.config.web.reactive;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpMethod;

import java.util.List;

@Getter @Setter @ToString
public class WebConfigProperties {
    private String reqVO;
    private String respVO;
    private List<Path> paths;

    @Getter @Setter @ToString
    public  static class Path{
        private String uri;
        private HttpMethod method;
        private String controllerFunc;
        private String reqVO;
        private String respVO;
    }
}
