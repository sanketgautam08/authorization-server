package com.sanketgautam.authorirzation.server.controller;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class DemoController {

    @GetMapping("/debug")
    public ResponseEntity<Map<String, String>> authorization(@RequestParam String code){
        return new ResponseEntity<>(Map.of("code",code), HttpStatusCode.valueOf(200));
    }
}
