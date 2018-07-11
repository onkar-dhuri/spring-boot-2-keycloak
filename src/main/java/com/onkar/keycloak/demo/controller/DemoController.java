package com.onkar.keycloak.demo.controller;


import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.logging.Logger;


@RestController
public class DemoController {

    @Autowired
    private AccessToken accessToken;

    private static final Logger LOGGER = Logger.getLogger(DemoController.class.getName());

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/hello")
    public String sayHelloToAdmin() {
        LOGGER.info("AccessToken : " + accessToken);
        return "Hello Admin";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user/hello")
    public String sayHelloToUser() {
        return "Hello User";
    }

    @GetMapping("/open")
    public String welcome() {
        return "It Works !!";
    }

}
