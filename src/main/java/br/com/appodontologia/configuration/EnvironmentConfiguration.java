package br.com.appodontologia.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "configuration")
public class EnvironmentConfiguration {

    private int jwtTimeExpiration;
    private String jwtSecret;

    private String swaggerHome;
    private String swaggerTitle;
    private String swaggerDescription;
    private String swaggerContactEmail;
    private String swaggerAppVersion;

    private List<String> allowedEndpoints;

}