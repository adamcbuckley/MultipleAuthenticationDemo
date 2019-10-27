package com.example.controller;

import com.example.Util;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


@RestController
@RequestMapping("/admin")
public class AdminController {

	private final ObjectMapper MAPPER = new ObjectMapper();

	@RequestMapping("/admin-profile")
	public JsonNode getAdminPage(final Authentication authentication) {
		Util.log("/admin/admin-profile");

		final Map<String, Object> response = new HashMap<>();
		response.put("message", "Welcome admin");
		response.put("secret", 12345);

		final Set<String> permissions = new HashSet<>();
		authentication.getAuthorities().forEach(p -> permissions.add(p.getAuthority()));
		response.put("permissions", permissions);

		return MAPPER.valueToTree(response);
	}
}
