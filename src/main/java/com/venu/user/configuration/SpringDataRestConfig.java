package com.venu.user.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;
import org.springframework.data.rest.webmvc.config.RepositoryRestConfigurer;
import org.springframework.http.HttpMethod;
import org.springframework.web.servlet.config.annotation.CorsRegistry;

@Configuration
public class SpringDataRestConfig implements RepositoryRestConfigurer {

    @Override
    public void configureRepositoryRestConfiguration(
            RepositoryRestConfiguration config,
            CorsRegistry cors) {

        config.getExposureConfiguration()
            .withCollectionExposure((metadata, methods) ->
                methods.disable(
                    HttpMethod.POST,
                    HttpMethod.PUT,
                    HttpMethod.PATCH,
                    HttpMethod.DELETE
                )
            )
            .withItemExposure((metadata, methods) ->
                methods.disable(
                    HttpMethod.PUT,
                    HttpMethod.PATCH,
                    HttpMethod.DELETE
                )
            )
            .withAssociationExposure((metadata, methods) ->
                methods.disable(
                    HttpMethod.POST,
                    HttpMethod.PUT,
                    HttpMethod.PATCH,
                    HttpMethod.DELETE
                )
            );
    }
}
