package com.algafood.auth.core;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

public class JwtCustomClaimsTokenEnhancer implements TokenEnhancer {

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		if (authentication.getPrincipal() instanceof AuthUser) {
			AuthUser authUser = (AuthUser) authentication.getPrincipal();

			Map<String, Object> customInfo = new HashMap<>();
			customInfo.put("nome_completo", authUser.getFullName());
			customInfo.put("usuario_id", authUser.getUserId());
			
			DefaultOAuth2AccessToken oAuth2AccesToken = (DefaultOAuth2AccessToken) accessToken;
			oAuth2AccesToken.setAdditionalInformation(customInfo);
		}

		return accessToken;
	}

}
