package com.example.controller;

import com.example.Util;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/admin")
public class AdminController {

	@RequestMapping("/myAdminPage")
	public String getAdminPage(Principal principal) {
		Util.log("/admin/myAdminPage");

		// Returns REST response
		return "{\n" +
				"  \"message\": \"Welcome admin\",\n" +
				"  \"secret\": \"12345\"\n" +
				"}\n";
	}
}
