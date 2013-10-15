package org.osiam.security.authorization;

import org.codehaus.jackson.map.ObjectMapper;
import org.osiam.helper.HttpClientHelper;
import org.osiam.security.OAuth2AuthenticationSpring;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class AccessTokenValidationService implements ResourceServerTokenServices {

    private ObjectMapper mapper;
    private HttpClientHelper httpClient;

    public AccessTokenValidationService() {
        mapper = new ObjectMapper();
        httpClient = new HttpClientHelper();
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) {

        String result = httpClient.executeHttpGet("http://localhost:8080/osiam-auth-server/token/validate/" + accessToken);

        OAuth2AuthenticationSpring oAuth2AuthenticationSpring;
        try {
            oAuth2AuthenticationSpring = mapper.readValue(result, OAuth2AuthenticationSpring.class);
        } catch (IOException e) {
            throw new RuntimeException(e); //NOSONAR : Need only wrapping to a runtime exception
        }

        return new OAuth2Authentication(oAuth2AuthenticationSpring.getAuthorizationRequestSpring(), oAuth2AuthenticationSpring.getAuthenticationSpring());
    }

    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {

        String response = httpClient.executeHttpGet("http://localhost:8080/osiam-auth-server/token/" + accessToken);

        OAuth2AccessToken oAuth2AccessToken;
        try {
            oAuth2AccessToken = mapper.readValue(response, OAuth2AccessToken.class);
        } catch (IOException e) {
            throw new RuntimeException(e); //NOSONAR : Need only wrapping to a runtime exception
        }
        return oAuth2AccessToken;
    }
}