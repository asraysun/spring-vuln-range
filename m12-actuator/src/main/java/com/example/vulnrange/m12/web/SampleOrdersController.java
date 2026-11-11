package com.example.vulnrange.m12.web;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Ordinary business endpoint, so the module has something legitimate to serve. */
@RestController
@RequestMapping("/api/orders")
public class SampleOrdersController {

    @GetMapping
    public List<Map<String, Object>> orders() {
        return List.of(
                Map.of("id", "ORD-1", "plan", "ESPD-BASIC", "status", "PAID"),
                Map.of("id", "ORD-2", "plan", "ESPD-PRO", "status", "PENDING"));
    }
}
