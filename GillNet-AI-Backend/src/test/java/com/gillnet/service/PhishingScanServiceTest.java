package com.gillnet.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.gillnet.dto.PhishingScanDto;

/**
 * Locks in the accuracy repairs for the text and screenshot scanners:
 *  - text engine catches prize/OTP/shortcode lures (tuned on labeled SMS data)
 *  - weak signals + spammy vocabulary escalate via the statistical model
 *  - screenshot verdicts come from OCR-extracted text, never the file name
 *  - without OCR text the service reports a coverage gap instead of inventing
 *    pixel/visual-inspection claims
 */
@ExtendWith(MockitoExtension.class)
class PhishingScanServiceTest {

    @Mock
    private UrlScanService urlScanService;

    @Mock
    private HistoryService historyService;

    private PhishingScanService service;

    @BeforeEach
    void setUp() {
        service = new PhishingScanService(urlScanService, historyService);
    }

    private PhishingScanDto.Response scanText(String text) {
        // analyzeTextPhishing tries the (unreachable in tests) ML service first and
        // falls back to the heuristic engine; connection refused is immediate.
        return service.analyzeTextPhishing(text, "test-user");
    }

    @Test
    void prizeLureWithPremiumCallbackIsPhishing() {
        PhishingScanDto.Response r = scanText(
                "Congratulations! You've won a $1000 gift card. Claim now - call 09061701461.");
        assertEquals("PHISHING", r.getThreatLevel());
        assertTrue(r.getRiskScore() >= 70);
    }

    @Test
    void otpHarvestingLureIsPhishing() {
        PhishingScanDto.Response r = scanText(
                "URGENT: Your bank account has been locked. Provide your OTP verification code now to unlock.");
        assertEquals("PHISHING", r.getThreatLevel());
    }

    @Test
    void legitOtpNotificationStaysSafe() {
        PhishingScanDto.Response r = scanText(
                "Your OTP for login is 482913. Do not share it with anyone.");
        assertEquals("SAFE", r.getThreatLevel());
    }

    @Test
    void legitCongratulationsStaysSafe() {
        PhishingScanDto.Response r = scanText(
                "Congratulations on your promotion! Lunch tomorrow to celebrate?");
        assertEquals("SAFE", r.getThreatLevel());
    }

    @Test
    void greySpamEscalatedByStatisticalModel() {
        // Weak rule signals (risk 34) but spammy vocabulary -> SUSPICIOUS via NB tiebreaker
        PhishingScanDto.Response r = scanText(
                "Free tones for your mobile phone, click here to download.");
        assertEquals("SUSPICIOUS", r.getThreatLevel());
        assertEquals(45, r.getRiskScore());
        assertTrue(r.getIndicators().stream().anyMatch(i -> i.contains("Statistical Language Model")));
    }

    @Test
    void screenshotVerdictComesFromOcrTextNotFilename() {
        String ocr = "Dear customer, your account has been suspended. Call now on 09061701461 to verify your password immediately.";
        PhishingScanDto.Response r = service.analyzeImagePhishing("base64data", "timetable-class-schedule.png", ocr, "test-user");
        assertEquals("PHISHING", r.getThreatLevel());
        assertTrue(r.getSummary().startsWith("Screenshot (OCR text analysis)"));
        assertEquals(ocr, r.getExtractedText());
    }

    @Test
    void benignOcrTextWithSensitiveFilenameStaysSafe() {
        // File name is context only: benign OCR text must not be overruled by the name
        String ocr = "Team meeting tomorrow at 10am in room 204. Bring the quarterly report.";
        PhishingScanDto.Response r = service.analyzeImagePhishing("base64data", "paypal-login-screenshot.png", ocr, "test-user");
        assertEquals("SAFE", r.getThreatLevel());
    }

    @Test
    void screenshotWithoutOcrTextIsHonestAboutCoverageGap() {
        PhishingScanDto.Response r = service.analyzeImagePhishing("base64data", "paypal-login-screenshot.png", null, "test-user");
        assertEquals("SUSPICIOUS", r.getThreatLevel());
        List<String> indicators = r.getIndicators();
        assertTrue(indicators.stream().anyMatch(i -> i.contains("No on-screen text")));
        assertFalse(makesVisualInspectionClaims(indicators));
    }

    @Test
    void screenshotWithoutOcrTextAndBenignNameIsLowConfidence() {
        PhishingScanDto.Response r = service.analyzeImagePhishing("base64data", "timetable-class-schedule.png", "   ", "test-user");
        assertEquals("SAFE", r.getThreatLevel());
        assertTrue(r.getConfidence() <= 65.0);
        assertFalse(makesVisualInspectionClaims(r.getIndicators()));
    }

    /**
     * Fails if any indicator falsely claims the service performed pixel-level
     * visual inspection (honest "no pixel inspection available" disclosures pass).
     */
    private static boolean makesVisualInspectionClaims(List<String> indicators) {
        return indicators.stream().anyMatch(i -> {
            String l = i.toLowerCase();
            return (l.contains("visual inspection") && !l.contains("no ")) && !l.contains("cannot perform")
                    || l.contains("pixel analysis") || l.contains("image analysis detected")
                    || l.contains("scanned the image pixels") || l.contains("visually inspected");
        });
    }

    @Test
    void imageScansAreRecordedAsImageType() {
        service.analyzeImagePhishing("base64data", "shot.png",
                "Team meeting tomorrow at 10am in room 204.", "test-user");
        verify(historyService).addRecord(argThat(record ->
                "PHISHING_IMAGE".equals(record.getScanType())));
    }
}
