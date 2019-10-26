package org.baeldung.multipleentrypoints;

import org.opensaml.saml2.core.impl.NameIDImpl;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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
			final Object principal = authentication.getPrincipal();

			if (principal instanceof NameIDImpl) {
				principleStr = ((NameIDImpl) principal).getValue();
			} else {
				principleStr = authentication.getName();
			}
		} else {
			principleStr = "AnonymousAuthenticationToken";
		}


		System.err.println("endpoint:'" + endpoint + "', principle='" + principleStr + "'");
	}


}
