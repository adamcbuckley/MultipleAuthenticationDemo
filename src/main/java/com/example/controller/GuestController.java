package com.example.controller;

import com.example.Util;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/guest")
public class GuestController {

	private final ObjectMapper MAPPER = new ObjectMapper();

	@RequestMapping("/news")
	public JsonNode getGuestPage() {
		Util.log("/guest/news");

		final Map<String, Object> response = new HashMap<>();
		response.put("message", "Welcome guest");
		response.put("weather", "Cloudy");
		response.put("temperature", 9);

		return MAPPER.valueToTree(response);
	}
}
