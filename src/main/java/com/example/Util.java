package com.example;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.impl.AbstractNameIDType;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.util.SAMLUtil;


public class Util {

	private static final boolean SHOW_SAML_ASSERTION = false;

	/**
	 * Writes details about the logged in user to stderr
	 */
	public static void log(String endpointName) {

		final String principleStr;
		final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication == null) {
			principleStr = "No session";
		} else if ((authentication instanceof AnonymousAuthenticationToken)) {
			principleStr = "Anonymous session";
		} else {
			if (authentication.getCredentials() != null && authentication.getCredentials() instanceof SAMLCredential) {
				try {
					final SAMLCredential credential = (SAMLCredential) authentication.getCredentials();
					final Assertion authenticationAssertion = credential.getAuthenticationAssertion();
					final String xmlStr = XMLHelper.nodeToString(SAMLUtil.marshallMessage(authenticationAssertion));
					if(SHOW_SAML_ASSERTION) System.out.println("\n\n" + xmlStr + "\n\n");
				} catch (MessageEncodingException e) {
					throw new RuntimeException(e);
				}
			}

			final Object principal = authentication.getPrincipal();

			if (principal instanceof AbstractNameIDType) {
				final AbstractNameIDType p = (AbstractNameIDType) principal;
				principleStr = p.getValue();
			} else {
				principleStr = authentication.getName();
			}
		}

		String msg = "endpoint='" + endpointName + "', principle='" + principleStr + "'";
		if (authentication != null) msg += ", authorities='" + authentication.getAuthorities() + "'";

		System.err.println(msg);
	}
}
