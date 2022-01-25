package com.intuit.developer.helloworld.controller;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

import com.intuit.developer.helloworld.client.OAuth2PlatformClientFactory;
import com.intuit.oauth2.config.OAuth2Config;
import com.intuit.oauth2.config.Scope;
import com.intuit.oauth2.exception.InvalidRequestException;

/**
 * @author dderose
 *
 */
@Controller
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class HomeController {
	
	private static final Logger logger = LogManager.getLogger(HomeController.class);
	
	@Autowired
	OAuth2PlatformClientFactory factory;
	
	/**
	 * Controller mapping for connectToQuickbooks button
	 * @return
	 */
	@RequestMapping("/connectToQuickbooks")
	public View connectToQuickbooks(HttpSession session) {
		logger.info("inside connectToQuickbooks ");
		OAuth2Config oauth2Config = factory.getOAuth2Config();
		
		String redirectUri = factory.getPropertyValue("OAuth2AppRedirectUri"); 
		
		String csrf = oauth2Config.generateCSRFToken();
		session.setAttribute("csrfToken", csrf);
		try {
			List<Scope> scopes = new ArrayList<Scope>();
			scopes.add(Scope.Accounting);
			return new RedirectView(oauth2Config.prepareUrl(scopes, redirectUri, csrf), true, true, false);
		} catch (InvalidRequestException e) {
			logger.error("Exception calling connectToQuickbooks ", e);
		}
		return null;
	}

}
