package com.cuidatuslukas;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class CuidaTusLukasApplication {

    public static void main(String[] args) {
        SpringApplication.run(CuidaTusLukasApplication.class, args);
    }
}
