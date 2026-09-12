package com.gillnet.dto;

import java.util.List;

public class ChatDto {

    public static class Request {
        private String message;
        private String conversationId;

        public Request() {}
        public Request(String message) {
            this.message = message;
        }

        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        public String getConversationId() { return conversationId; }
        public void setConversationId(String conversationId) { this.conversationId = conversationId; }
    }

    public static class Response {
        private String reply;
        private List<String> suggestions;
        private String category; // PHISHING, SCAM, PASSWORD, GENERAL_SAFETY

        public Response() {}
        public Response(String reply, List<String> suggestions, String category) {
            this.reply = reply;
            this.suggestions = suggestions;
            this.category = category;
        }

        public String getReply() { return reply; }
        public void setReply(String reply) { this.reply = reply; }
        public List<String> getSuggestions() { return suggestions; }
        public void setSuggestions(List<String> suggestions) { this.suggestions = suggestions; }
        public String getCategory() { return category; }
        public void setCategory(String category) { this.category = category; }
    }
}
