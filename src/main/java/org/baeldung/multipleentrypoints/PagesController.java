package org.baeldung.multipleentrypoints;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.impl.AbstractNameIDType;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
public class PagesController {

	@RequestMapping("/multipleHttpLinks")
	public String getMultipleHttpLinksPage() {
		log("/multipleHttpLinks");
		return "multipleHttpElems/multipleHttpLinks";
	}

	@RequestMapping("/admin/myAdminPage")
	public String getAdminPage(Principal principal) {
		log("/admin/myAdminPage");
		return "multipleHttpElems/myAdminPage";
	}

	@RequestMapping("/user/general/myUserPage")
	public String getUserPage() {
		log("/user/general/myUserPage");
		return "multipleHttpElems/myUserPage";
	}

	@RequestMapping("/user/private/myPrivateUserPage")
	public String getPrivateUserPage() {
		log("/user/private/myPrivateUserPage");
		return "multipleHttpElems/myPrivateUserPage";
	}

	@RequestMapping("/guest/myGuestPage")
	public String getGuestPage() {
		log("/guest/myGuestPage");
		return "multipleHttpElems/myGuestPage";
	}

	@RequestMapping("/userLogin")
	public String getUserLoginPage() {
		log("/userLogin");
		return "multipleHttpElems/login";
	}

	@RequestMapping("/userLoginWithWarning")
	public String getUserLoginPageWithWarning() {
		log("/userLoginWithWarning");
		return "multipleHttpElems/loginWithWarning";
	}

	@RequestMapping("/403")
	public String getAccessDeniedPage() {
		log("/403");
		return "403";
	}

	private void log(String endpoint) {

		final String principleStr;
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			principleStr = "(No session)";
		} else if (!(authentication instanceof AnonymousAuthenticationToken)) {

			if (authentication.getCredentials() != null && authentication.getCredentials() instanceof SAMLCredential) {
				try {
					final SAMLCredential credential = (SAMLCredential) authentication.getCredentials();
					final Assertion authenticationAssertion = credential.getAuthenticationAssertion();
					final String xmlStr = XMLHelper.nodeToString(SAMLUtil.marshallMessage(authenticationAssertion));
					System.out.println("\n\n" + xmlStr + "\n\n");
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
		} else {
			principleStr = "AnonymousAuthenticationToken";
		}

		String msg = "endpoint='" + endpoint + "', principle='" + principleStr + "'";
		if (authentication != null) msg += ", authorities='" + authentication.getAuthorities() + "'";
		System.err.println(msg);
	}
}
