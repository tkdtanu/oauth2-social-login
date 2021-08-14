package com.tkd.oauth2.security.factory;

import com.tkd.oauth2.enums.AuthProvider;
import com.tkd.oauth2.security.exception.OAuth2AuthenticationProcessingException;
import com.tkd.oauth2.security.model.FacebookOAuth2UserInfo;
import com.tkd.oauth2.security.model.GithubOAuth2UserInfo;
import com.tkd.oauth2.security.model.GoogleOAuth2UserInfo;
import com.tkd.oauth2.security.model.OAuth2UserInfo;
import org.apache.commons.lang3.StringUtils;

import java.util.Map;

public class OAuth2userInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if (StringUtils.equalsIgnoreCase(registrationId, AuthProvider.google.toString())) {
            return new GoogleOAuth2UserInfo(attributes);
        } else if (StringUtils.equalsIgnoreCase(registrationId, AuthProvider.facebook.toString())) {
            return new FacebookOAuth2UserInfo(attributes);
        } else if (StringUtils.equalsIgnoreCase(registrationId, AuthProvider.github.toString())) {
            return new GithubOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationProcessingException("Sorry! Login With " + registrationId + " is not supported yet.");
        }
    }
}
