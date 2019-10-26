package org.baeldung.multipleentrypoints;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.PropertySource;

@SpringBootApplication
public class MultipleEntryPointsApplication {
	public static void main(String[] args) {
		SpringApplication.run(MultipleEntryPointsApplication.class, args);
	}
}
