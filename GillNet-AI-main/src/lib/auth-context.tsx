import React, { createContext, useContext, useEffect, useState } from "react";
import { api, type UserResponseDTO } from "./api";

interface AuthContextType {
  user: UserResponseDTO | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  isAuthModalOpen: boolean;
  authModalTab: "login" | "register" | "forgot";
  login: (email: string, password: string) => Promise<void>;
  register: (name: string, email: string, password: string) => Promise<void>;
  googleLogin: (data: { credential?: string; email?: string; name?: string; picture?: string; googleId?: string }) => Promise<void>;
  resetPassword: (email: string, newPassword: string) => Promise<string>;
  logout: () => void;
  openAuthModal: (tab?: "login" | "register" | "forgot") => void;
  closeAuthModal: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const TOKEN_KEY = "gillnet_auth_token";
const USER_KEY = "gillnet_auth_user";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserResponseDTO | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);
  const [authModalTab, setAuthModalTab] = useState<"login" | "register" | "forgot">("login");

  useEffect(() => {
    // Restore session on mount
    try {
      const savedToken = localStorage.getItem(TOKEN_KEY);
      const savedUser = localStorage.getItem(USER_KEY);

      if (savedToken) {
        setToken(savedToken);
        if (savedUser) {
          setUser(JSON.parse(savedUser));
        }
        // Verify with backend
        api.auth
          .getProfile()
          .then((profile) => {
            setUser(profile);
            localStorage.setItem(USER_KEY, JSON.stringify(profile));
          })
          .catch(() => {
            // Token may have expired or server offline; keep local user if offline or clear
            console.log("Could not refresh profile from server");
          })
          .finally(() => setIsLoading(false));
      } else {
        setIsLoading(false);
      }
    } catch {
      setIsLoading(false);
    }
  }, []);

  const login = async (email: string, password: string) => {
    const res = await api.auth.login(email, password);
    if (res.token && res.user) {
      setToken(res.token);
      setUser(res.user);
      localStorage.setItem(TOKEN_KEY, res.token);
      localStorage.setItem(USER_KEY, JSON.stringify(res.user));
      setIsAuthModalOpen(false);
    } else {
      throw new Error(res.message || "Login failed");
    }
  };

  const register = async (name: string, email: string, password: string) => {
    const res = await api.auth.register(name, email, password);
    if (res.token && res.user) {
      setToken(res.token);
      setUser(res.user);
      localStorage.setItem(TOKEN_KEY, res.token);
      localStorage.setItem(USER_KEY, JSON.stringify(res.user));
      setIsAuthModalOpen(false);
    } else {
      throw new Error(res.message || "Registration failed");
    }
  };

  const googleLogin = async (data: { credential?: string; email?: string; name?: string; picture?: string; googleId?: string }) => {
    const res = await api.auth.googleLogin(data);
    if (res.token && res.user) {
      setToken(res.token);
      setUser(res.user);
      localStorage.setItem(TOKEN_KEY, res.token);
      localStorage.setItem(USER_KEY, JSON.stringify(res.user));
      setIsAuthModalOpen(false);
    } else {
      throw new Error(res.message || "Google authentication failed");
    }
  };

  const resetPassword = async (email: string, newPassword: string): Promise<string> => {
    const res = await api.auth.resetPassword(email, newPassword);
    if (res.message) {
      return res.message;
    }
    return "Password has been successfully updated!";
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  };

  const openAuthModal = (tab: "login" | "register" | "forgot" = "login") => {
    setAuthModalTab(tab);
    setIsAuthModalOpen(true);
  };

  const closeAuthModal = () => {
    setIsAuthModalOpen(false);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!token && !!user,
        isLoading,
        isAuthModalOpen,
        authModalTab,
        login,
        register,
        googleLogin,
        resetPassword,
        logout,
        openAuthModal,
        closeAuthModal,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

const defaultAuthContext: AuthContextType = {
  user: null,
  token: null,
  isAuthenticated: false,
  isLoading: false,
  isAuthModalOpen: false,
  authModalTab: "login",
  login: async () => {},
  register: async () => {},
  googleLogin: async () => {},
  resetPassword: async () => "",
  logout: () => {},
  openAuthModal: () => {},
  closeAuthModal: () => {},
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  return context || defaultAuthContext;
}
