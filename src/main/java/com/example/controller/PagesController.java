package com.example.controller;

import com.example.Util;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;


@Controller
public class PagesController {

	@RequestMapping("/user/general/myUserPage")
	public String getUserPage() {
		Util.log("/user/general/myUserPage");
		return "myUserPage";
	}


	@RequestMapping("/guest/myGuestPage")
	public String getGuestPage() {
		Util.log("/guest/myGuestPage");
		return "myGuestPage";
	}


	@RequestMapping("/userLogin")
	public String getUserLoginPage() {
		Util.log("/userLogin");
		return "login";
	}


	@RequestMapping("/403")
	public String getAccessDeniedPage() {
		Util.log("/403");
		return "403";
	}

}
