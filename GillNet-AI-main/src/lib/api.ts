/**
 * GillNet AI — Centralized REST API Client
 * Connects frontend to the Java Spring Boot backend on http://localhost:8080
 */

const API_BASE_URL = (import.meta as any).env?.VITE_API_URL || "http://localhost:8081";

export interface UserResponseDTO {
  id: string;
  name: string;
  email: string;
  picture?: string | null;
  authProvider?: string;
  createdAt: string;
}

export interface AuthResponse {
  token: string | null;
  message: string;
  user: UserResponseDTO | null;
}

export interface UrlScanResult {
  url: string;
  prediction: "SAFE" | "PHISHING" | string;
  confidence: number;
  riskScore: number;
  model: string;
  reasons: string[];
  recommendation: string;
}

export interface MessageScanResult {
  classification: "SAFE" | "SUSPICIOUS" | "SCAM" | string;
  riskScore: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;
  indicators: string[];
  explanation: string;
  recommendation: string;
}

export interface PasswordScanResult {
  strength: "WEAK" | "FAIR" | "GOOD" | "STRONG" | "VERY_STRONG" | string;
  score: number;
  entropy: number;
  estimatedCrackTime: string;
  passedCriteria: string[];
  suggestions: string[];
  isCommon: boolean;
}

export interface PhishingScanResult {
  threatLevel: "SAFE" | "SUSPICIOUS" | "PHISHING" | string;
  riskScore: number;
  confidence: number;
  summary: string;
  brandImpersonated: string;
  credentialHarvesting: boolean;
  urgencyTactics: string[];
  extractedUrls: string[];
  indicators: string[];
  recommendations: string[];
  extractedText?: string;
}

export interface ChatResponse {
  reply: string;
  suggestions: string[];
  category: string;
}

export interface HistoryStats {
  totalScans: number;
  safeCount: number;
  suspiciousCount: number;
  highRiskCount: number;
  averageRiskScore: number;
}

export interface ScanRecord {
  id: string;
  userId?: string;
  scanType: string;
  sanitizedTarget: string;
  result: string;
  riskScore: number;
  riskLevel: string;
  summary: string;
  timestamp: string;
}

function getAuthHeader(): Record<string, string> {
  const token = typeof window !== "undefined" ? localStorage.getItem("gillnet_auth_token") : null;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const headers = {
    "Content-Type": "application/json",
    ...getAuthHeader(),
    ...(options.headers || {}),
  };

  const response = await fetch(url, { ...options, headers });

  if (!response.ok) {
    let errorMessage = `Request failed (${response.status})`;
    try {
      const errorJson = await response.json();
      errorMessage = errorJson.message || errorJson.error || JSON.stringify(errorJson);
    } catch {
      try {
        const errorText = await response.text();
        if (errorText) errorMessage = errorText;
      } catch {}
    }
    throw new Error(errorMessage);
  }

  // Handle empty responses
  const text = await response.text();
  return text ? JSON.parse(text) : ({} as T);
}

export const api = {
  auth: {
    login: (email: string, password: string): Promise<AuthResponse> =>
      request<AuthResponse>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      }),

    register: (name: string, email: string, password: string): Promise<AuthResponse> =>
      request<AuthResponse>("/api/auth/register", {
        method: "POST",
        body: JSON.stringify({ name, email, password }),
      }),

    googleLogin: (data: { credential?: string; email?: string; name?: string; picture?: string; googleId?: string }): Promise<AuthResponse> =>
      request<AuthResponse>("/api/auth/google", {
        method: "POST",
        body: JSON.stringify(data),
      }),

    getProfile: (): Promise<UserResponseDTO> =>
      request<UserResponseDTO>("/api/auth/me", {
        method: "GET",
      }),

    forgotPassword: (email: string): Promise<{ message: string; email?: string }> =>
      request<{ message: string; email?: string }>("/api/auth/forgot-password", {
        method: "POST",
        body: JSON.stringify({ email }),
      }),

    resetPassword: (email: string, newPassword: string): Promise<{ message: string; success: boolean }> =>
      request<{ message: string; success: boolean }>("/api/auth/reset-password", {
        method: "POST",
        body: JSON.stringify({ email, newPassword }),
      }),
  },

  urlScan: {
    analyze: (url: string, userId?: string): Promise<UrlScanResult> =>
      request<UrlScanResult>("/api/url/analyze", {
        method: "POST",
        body: JSON.stringify({ url, userId }),
      }),
  },

  messageScan: {
    analyze: (message: string, userId?: string): Promise<MessageScanResult> =>
      request<MessageScanResult>("/api/message/analyze", {
        method: "POST",
        body: JSON.stringify({ message, userId }),
      }),
  },

  phishing: {
    analyzeText: (content: string, userId?: string): Promise<PhishingScanResult> =>
      request<PhishingScanResult>("/api/phishing/analyze-text", {
        method: "POST",
        body: JSON.stringify({ type: "TEXT", content, userId }),
      }),

    analyzeImage: (content: string, fileName?: string, userId?: string): Promise<PhishingScanResult> =>
      request<PhishingScanResult>("/api/phishing/analyze-image", {
        method: "POST",
        body: JSON.stringify({ type: "IMAGE", content, fileName, userId }),
      }),
  },

  passwordScan: {
    analyze: (password: string): Promise<PasswordScanResult> =>
      request<PasswordScanResult>("/api/password/analyze", {
        method: "POST",
        body: JSON.stringify({ password }),
      }),
  },

  chat: {
    send: (message: string, conversationId?: string): Promise<ChatResponse> =>
      request<ChatResponse>("/api/chat", {
        method: "POST",
        body: JSON.stringify({ message, conversationId }),
      }),
  },

  history: {
    get: (userId?: string): Promise<ScanRecord[]> => {
      const q = userId ? `?userId=${encodeURIComponent(userId)}` : "";
      return request<ScanRecord[]>(`/api/history${q}`, { method: "GET" });
    },

    getStats: (): Promise<HistoryStats> =>
      request<HistoryStats>("/api/history/stats", { method: "GET" }),
  },
};
