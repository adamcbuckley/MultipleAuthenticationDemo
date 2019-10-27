package com.example.controller;

import com.example.Util;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;


@Controller
public class PagesController {

	@RequestMapping("/login")
	public String getLoginPage() {
		Util.log("/login");
		return "login";
	}
}
