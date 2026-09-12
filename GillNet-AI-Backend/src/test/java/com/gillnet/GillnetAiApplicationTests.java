package com.gillnet;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.gillnet.repository.ScanRecordRepository;
import com.gillnet.repository.UserRepository;

@SpringBootTest
class GillnetAiApplicationTests {

    @MockitoBean
    private UserRepository userRepository;

    @MockitoBean
    private ScanRecordRepository scanRecordRepository;

    @Test
    void contextLoads() {
        // Verifies the Spring application context boots up successfully
    }
}
