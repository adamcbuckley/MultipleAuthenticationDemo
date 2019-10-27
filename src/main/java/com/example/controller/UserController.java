package com.example.controller;

import com.example.Util;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserController {

	private final ObjectMapper MAPPER = new ObjectMapper();

	@RequestMapping("/user-profile")
	public JsonNode getUserPage() {
		Util.log("/user/user-profile");

		final Map<String, Object> response = new HashMap<>();
		response.put("message", "Welcome user");
		response.put("balance", 123.45);
		response.put("alerts", 2);

		return MAPPER.valueToTree(response);
	}
}
