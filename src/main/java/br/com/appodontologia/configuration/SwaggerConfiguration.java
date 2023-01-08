package br.com.appodontologia.configuration;

import br.com.appodontologia.util.Constants;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RestController;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.*;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;

import java.util.Collections;
import java.util.List;

@Configuration
@AllArgsConstructor
public class SwaggerConfiguration {

    private final EnvironmentConfiguration env;

    public static final String USER_TAG = Constants.USER_TAG_NAME;

    private ApiKey apiKey() {
        return new ApiKey(Constants.FIELD_JWT, Constants.AUTHORIZATION_HEADER, Constants.HEADER);
    }

    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title(env.getSwaggerTitle())
                .description(env.getSwaggerDescription())
                .version(env.getSwaggerAppVersion())
                .build();
    }

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(apiInfo())
                .securityContexts(Collections.singletonList(securityContext()))
                .useDefaultResponseMessages(false)
                .securitySchemes(List.of(apiKey()))
                .select()
                .apis(RequestHandlerSelectors.withClassAnnotation(RestController.class))
                .paths(PathSelectors.any())
                .build()
                .tags(
                    new Tag(USER_TAG, Constants.USER_TAG_DESCRIPTION)
                 );
    }

    private SecurityContext securityContext() {
        return SecurityContext.builder().securityReferences(defaultAuth()).build();
    }

    private List<SecurityReference> defaultAuth() {
        AuthorizationScope authorizationScope = new AuthorizationScope(Constants.SCOPE, Constants.DESCRIPTION);
        AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
        authorizationScopes[0] = authorizationScope;
        return List.of(new SecurityReference(Constants.FIELD_JWT, authorizationScopes));
    }
}
