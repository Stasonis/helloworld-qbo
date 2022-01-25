package com.intuit.developer.helloworld.controller;

import java.util.List;
import java.util.Locale;

import javax.servlet.http.HttpSession;

import com.intuit.ipp.core.IEntity;
import com.intuit.ipp.data.Bill;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intuit.developer.helloworld.client.OAuth2PlatformClientFactory;
import com.intuit.developer.helloworld.helper.QBOServiceHelper;
import com.intuit.ipp.data.CompanyInfo;
import com.intuit.ipp.data.Error;
import com.intuit.ipp.exception.FMSException;
import com.intuit.ipp.exception.InvalidTokenException;
import com.intuit.ipp.services.DataService;
import com.intuit.ipp.services.QueryResult;
import com.intuit.oauth2.client.OAuth2PlatformClient;
import com.intuit.oauth2.data.BearerTokenResponse;
import com.intuit.oauth2.exception.OAuthException;

/**
 * @author dderose
 *
 */
@Controller
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class QBOController {
	
	@Autowired
	OAuth2PlatformClientFactory factory;
	
	@Autowired
    public QBOServiceHelper helper;
	
	private static final Logger logger = LogManager.getLogger(QBOController.class);
	private static final String failureMsg="Failed";

	@ResponseBody
	@RequestMapping("/authCode")
	public String authCode(@RequestParam("code") String authCode, @RequestParam("state") String state, @RequestParam(value = "realmId", required = false) String realmId, HttpSession session) {
		logger.info("inside oauth2redirect of sample"  );
		try {
			String csrfToken = (String) session.getAttribute("csrfToken");
			if (csrfToken.equals(state)) {
				session.setAttribute("realmId", realmId);
				session.setAttribute("auth_code", authCode);

				OAuth2PlatformClient client  = factory.getOAuth2PlatformClient();
				String redirectUri = factory.getPropertyValue("OAuth2AppRedirectUri");
				logger.info("inside oauth2redirect of sample -- redirectUri " + redirectUri  );

				BearerTokenResponse bearerTokenResponse = client.retrieveBearerTokens(authCode, redirectUri);

				session.setAttribute("access_token", bearerTokenResponse.getAccessToken());
				session.setAttribute("refresh_token", bearerTokenResponse.getRefreshToken());

				// Update your Data store here with user's AccessToken and RefreshToken along with the realmId

				return new JSONObject().put("connected", true).toString();
			}
			logger.info("csrf token mismatch " );
		} catch (OAuthException e) {
			logger.error("Exception in callback handler ", e);
		}

		return new JSONObject().put("connected", false).toString();
	}

	@ResponseBody
	@RequestMapping("/isConnected")
	public String isConnected(HttpSession session) {

		JSONObject notConnectedStatus = new JSONObject().put("connected", false);
		String query = "select * from companyInfo";

		String realmId = (String)session.getAttribute("realmId");
		if (StringUtils.isEmpty(realmId)) {
			return notConnectedStatus.toString();
		}
		String accessToken = (String)session.getAttribute("access_token");

		try {
			//get DataService
			DataService service = helper.getDataService(realmId, accessToken);

			QueryResult queryResult = service.executeQuery(query);
			return new JSONObject().put("connected", true).toString();
		}
		/*
		 * Handle 401 status code -
		 * If a 401 response is received, refresh tokens should be used to get a new access token,
		 * and the API call should be tried again.
		 */
		catch (InvalidTokenException e) {
			logger.error("Error while calling executeQuery :: " + e.getMessage());

			//refresh tokens
			logger.info("received 401 during companyinfo call, refreshing tokens now");
			OAuth2PlatformClient client  = factory.getOAuth2PlatformClient();
			String refreshToken = (String)session.getAttribute("refresh_token");

			try {
				BearerTokenResponse bearerTokenResponse = client.refreshToken(refreshToken);
				session.setAttribute("access_token", bearerTokenResponse.getAccessToken());
				session.setAttribute("refresh_token", bearerTokenResponse.getRefreshToken());

				//call query again using new tokens
				logger.info("calling query using new tokens");
				DataService service = helper.getDataService(realmId, accessToken);

				// get all companyinfo
				QueryResult queryResult = service.executeQuery(query);
				return new JSONObject().put("connected", true).toString();

			} catch (Exception e1) {
				logger.error("Error while checking connection status :: " + e.getMessage());
				return notConnectedStatus.toString();
			}

		} catch (Exception e) {
			logger.error("Error while checking connection status :: " + e.getMessage());
			return notConnectedStatus.toString();
		}
	}

	@ResponseBody
	@RequestMapping("/query/{objectType:(?:bill|vendor|companyInfo)}")
	public String queryForType(HttpSession session, @PathVariable String objectType) {
		String sql = "select * from " + objectType.toLowerCase(Locale.ROOT);
		return queryQBOJson(session, sql);
	}


	private String queryQBOJson(HttpSession session, String query) {
		try {
			List<? extends IEntity> bills = queryQBO(session, query);

			ObjectMapper mapper = new ObjectMapper();
			try {
				String jsonInString = mapper.writeValueAsString(bills);
				return jsonInString;
			} catch (JsonProcessingException e) {
				logger.error("Exception while getting company info ", e);
				return new JSONObject().put("response",failureMsg).toString();
			}
		}
		catch(Exception e) {
			logger.error("Error while calling executeQuery :: " + e.getMessage());
			return new JSONObject().put("response",failureMsg).toString();
		}
	}

    private List<? extends IEntity> queryQBO(HttpSession session, String query) throws Exception {
		String realmId = (String)session.getAttribute("realmId");
		if (StringUtils.isEmpty(realmId)) {
			throw new Exception("No realm ID.  QBO calls only work if the accounting scope was passed!");
		}
		String accessToken = (String)session.getAttribute("access_token");

		try {

			//get DataService
			DataService service = helper.getDataService(realmId, accessToken);

			QueryResult queryResult = service.executeQuery(query);
			return queryResult.getEntities();

		}
		/*
		 * Handle 401 status code -
		 * If a 401 response is received, refresh tokens should be used to get a new access token,
		 * and the API call should be tried again.
		 */
		catch (InvalidTokenException e) {
			logger.error("Error while calling executeQuery :: " + e.getMessage());

			//refresh tokens
			logger.info("received 401 during companyinfo call, refreshing tokens now");
			OAuth2PlatformClient client  = factory.getOAuth2PlatformClient();
			String refreshToken = (String)session.getAttribute("refresh_token");

			try {
				BearerTokenResponse bearerTokenResponse = client.refreshToken(refreshToken);
				session.setAttribute("access_token", bearerTokenResponse.getAccessToken());
				session.setAttribute("refresh_token", bearerTokenResponse.getRefreshToken());

				//call company info again using new tokens
				logger.info("calling companyinfo using new tokens");
				DataService service = helper.getDataService(realmId, accessToken);

				//Retry query
				QueryResult queryResult = service.executeQuery(query);
				return queryResult.getEntities();

			} catch (OAuthException e1) {
				logger.error("Error while calling bearer token :: " + e.getMessage());
				throw new Exception("Error while calling bearer token :: " + e.getMessage());
			} catch (FMSException e1) {
				logger.error("Error while calling company currency :: " + e.getMessage());
				throw new Exception("Error while calling company currency :: " + e.getMessage());
			}

		} catch (FMSException e) {
			List<Error> list = e.getErrorList();
			list.forEach(error -> logger.error("Error while calling executeQuery :: " + error.getMessage()));
			throw e;
		}
	}
}
