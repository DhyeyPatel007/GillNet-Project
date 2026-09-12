package com.gillnet.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.springframework.stereotype.Service;

import com.gillnet.dto.ChatDto;

@Service
public class ChatService {

    public ChatDto.Response answerQuestion(ChatDto.Request request) {
        String message = request.getMessage();
        if (message == null || message.trim().isEmpty()) {
            return new ChatDto.Response(
                    "Hello! I am your GillNet AI Cybersecurity Assistant. Ask me anything about phishing links, suspicious messages, OTP scams, or password safety.",
                    List.of("What should I do if I clicked a phishing link?", "How do I recognize an OTP scam?", "How can I create a strong master password?"),
                    "GENERAL_SAFETY"
            );
        }

        String query = message.toLowerCase(Locale.ENGLISH);
        String reply;
        String category;
        List<String> suggestions = new ArrayList<>();

        if (query.contains("hr") || query.contains("workplace alert") || query.contains("usage policy")
                || query.contains("inappropriate material") || query.contains("recorded evidence")
                || query.contains("extortion") || query.contains("disciplinary") || query.contains("contoso")) {
            category = "ENTERPRISE_SPEAR_PHISHING";
            reply = "CRITICAL ALERT — Highly Probable Spear-Phishing / Disciplinary Extortion:\n\n"
                    + "Attack Pattern Analysis:\n"
                    + "• Attackers impersonate 'HR Team', 'Compliance', or 'Management' with alarming accusations (e.g., 'Device & Internet Usage Policy violation' or 'viewing inappropriate material').\n"
                    + "• The urgent lure 'View Recorded Evidence' or 'Review Evidence' is designed to cause panic and coerce you into clicking a credential harvesting or malware delivery link.\n\n"
                    + "Immediate Protocol:\n"
                    + "1. DO NOT CLICK 'View Recorded Evidence' or download any attachments.\n"
                    + "2. Inspect the sender domain: Legitimate internal HR never emails from external domains like '@webnotifications.net' or '@mail-alert.com'.\n"
                    + "3. Forward the raw email with headers to your company's official IT Security / SOC department.\n"
                    + "4. If you already clicked or entered credentials, disconnect from the corporate VPN/network and alert IT immediately.";
            suggestions.add("How do I verify the true sender email header?");
            suggestions.add("What should I do if I entered credentials on a fake HR portal?");
            suggestions.add("Report this incident to IT Security");
        } else if (query.contains("phishing") || query.contains("clicked") || query.contains("fake link")) {
            category = "PHISHING";
            reply = "If you clicked a suspicious or phishing link, take these immediate actions:\n\n"
                    + "1. Disconnect your device from the internet or Wi-Fi if an unexpected file downloaded.\n"
                    + "2. If you entered login credentials, immediately change your password from another secure device.\n"
                    + "3. Enable Two-Factor Authentication (2FA/MFA) on that account right away.\n"
                    + "4. Check your account activity logs and active sessions, revoking unfamiliar devices.\n"
                    + "5. Run a full antivirus/anti-malware scan on your computer or phone.";
            suggestions.add("How do I identify a deceptive domain name?");
            suggestions.add("What is two-factor authentication?");
        } else if (query.contains("otp") || query.contains("verification code") || query.contains("pin")) {
            category = "SCAM";
            reply = "Golden Rule: Never share your OTP (One-Time Password) with ANYONE — not even someone claiming to be bank staff, police, or tech support.\n\n"
                    + "Real banks and customer service agents will NEVER call or message asking for your OTP. OTPs are meant exclusively for authorising actions you personally initiated.";
            suggestions.add("What are signs of an urgency phone scam?");
            suggestions.add("How to report a fraudulent caller?");
        } else if (query.contains("cvv") || query.contains("credit card") || query.contains("debit card") || query.contains("banking")) {
            category = "FINANCIAL";
            reply = "Never share your card CVV, ATM PIN, or card expiration date via chat, email, or over the phone.\n\n"
                    + "When purchasing online:\n"
                    + "• Only enter card details on secure pages (check for 'https://' and matching domain name).\n"
                    + "• Use virtual or single-use burner cards if available.\n"
                    + "• Keep card spending alerts enabled on your banking app.";
            suggestions.add("Is it safe to store credit card info in browsers?");
            suggestions.add("What to do if money was debited unexpectedly?");
        } else if (query.contains("password") || query.contains("credentials") || query.contains("hack")) {
            category = "PASSWORD";
            reply = "To create uncrackable, resilient passwords:\n\n"
                    + "• Use passphrases made of 4+ random words (e.g., 'cactus-orbit-velvet-parade').\n"
                    + "• Never reuse passwords across multiple sites. If one service suffers a data breach, all your accounts become vulnerable.\n"
                    + "• Use a reputable password manager (e.g., Bitwarden, 1Password) to generate and store 16+ character unique passwords.";
            suggestions.add("Why is password reuse so dangerous?");
            suggestions.add("How does a password manager protect against phishing?");
        } else {
            category = "GENERAL_SAFETY";
            reply = "I'm here to help you stay safe online! Here are 3 core cybersecurity practices you can apply today:\n\n"
                    + "1. Verify URLs before entering passwords — look for suspicious hyphens or misspellings.\n"
                    + "2. Beware of messages creating fake urgency or threatening account closures.\n"
                    + "3. Always turn on Multi-Factor Authentication (2FA) wherever supported.";
            suggestions.add("What should I do if I received a suspicious HR email?");
            suggestions.add("What should I do if I clicked a phishing link?");
            suggestions.add("How can I recognize an OTP scam?");
        }

        return new ChatDto.Response(reply, suggestions, category);
    }
}
