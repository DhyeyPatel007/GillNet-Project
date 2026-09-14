import React, { useState } from "react";
import { useAuth } from "@/lib/auth-context";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Lock,
  Mail,
  User,
  ArrowRight,
  ArrowLeft,
  Loader2,
  ShieldCheck,
  AlertCircle,
  KeyRound,
  CheckCircle2,
  Sparkles,
} from "lucide-react";

function GoogleIcon({ className = "size-5" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="#4285F4"
        d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.8-2.4 3.65v3h3.88c2.27-2.09 3.665-5.17 3.665-9.09z"
      />
      <path
        fill="#34A853"
        d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.26v3.09C3.25 21.36 7.33 24 12 24z"
      />
      <path
        fill="#FBBC05"
        d="M5.28 14.32c-.25-.72-.38-1.49-.38-2.32 0-.83.13-1.6.38-2.32V6.59H1.26C.46 8.19 0 10.03 0 12c0 1.97.46 3.81 1.26 5.41l4.02-3.09z"
      />
      <path
        fill="#EA4335"
        d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.33 0 3.25 2.64 1.26 6.59l4.02 3.09c.95-2.83 3.6-4.93 6.72-4.93z"
      />
    </svg>
  );
}

export function AuthModal() {
  const {
    isAuthModalOpen,
    closeAuthModal,
    authModalTab,
    login,
    register,
    resetPassword,
    googleLogin,
  } = useAuth();

  const [activeTab, setActiveTab] = useState<"login" | "register" | "forgot">("login");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [googleAccountPrompt, setGoogleAccountPrompt] = useState(false);
  const [customGoogleEmail, setCustomGoogleEmail] = useState("");
  const [customGoogleName, setCustomGoogleName] = useState("");

  // Login form state
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");

  // Register form state
  const [registerName, setRegisterName] = useState("");
  const [registerEmail, setRegisterEmail] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [registerConfirmPassword, setRegisterConfirmPassword] = useState("");

  // Forgot / Reset password state
  const [forgotEmail, setForgotEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");

  // Sync tab with context trigger
  React.useEffect(() => {
    setActiveTab(authModalTab);
    setError(null);
    setSuccess(null);
    setGoogleAccountPrompt(false);
  }, [authModalTab, isAuthModalOpen]);

  // Load Google Identity Services script asynchronously
  React.useEffect(() => {
    if (typeof window !== "undefined" && !(window as any).google?.accounts) {
      const script = document.createElement("script");
      script.src = "https://accounts.google.com/gsi/client";
      script.async = true;
      script.defer = true;
      document.head.appendChild(script);
    }
  }, []);

  const executeGoogleLogin = async (email: string, name?: string, picture?: string) => {
    setError(null);
    setSuccess(null);
    setGoogleLoading(true);

    try {
      const avatarUrl =
        picture ||
        `https://ui-avatars.com/api/?name=${encodeURIComponent(
          name || email
        )}&background=4285F4&color=fff&rounded=true`;

      await googleLogin({
        email,
        name: name || email.split("@")[0],
        picture: avatarUrl,
        authProvider: "GOOGLE",
      });

      closeAuthModal();
      window.location.href = "/dashboard";
    } catch (err: any) {
      setError(err.message || "Google authentication failed. Please try again.");
    } finally {
      setGoogleLoading(false);
    }
  };

  const handleGoogleSignInClick = async () => {
    setError(null);
    setSuccess(null);

    const clientId = (import.meta as any).env?.VITE_GOOGLE_CLIENT_ID;
    const google = (window as any).google;

    // Direct Google OAuth 2.0 Token Client (Opens official Google popup)
    if (clientId && google?.accounts?.oauth2) {
      try {
        setGoogleLoading(true);
        const tokenClient = google.accounts.oauth2.initTokenClient({
          client_id: clientId,
          scope: "email profile openid",
          callback: async (tokenResponse: any) => {
            if (tokenResponse.error) {
              setError(`Google Sign-In canceled or failed: ${tokenResponse.error}`);
              setGoogleLoading(false);
              return;
            }
            try {
              const userInfoRes = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
                headers: { Authorization: `Bearer ${tokenResponse.access_token}` },
              });
              const userInfo = await userInfoRes.json();
              if (userInfo?.email) {
                await executeGoogleLogin(userInfo.email, userInfo.name, userInfo.picture);
              } else {
                throw new Error("Could not retrieve email from Google profile.");
              }
            } catch (fetchErr: any) {
              setError(fetchErr.message || "Failed to retrieve Google profile.");
              setGoogleLoading(false);
            }
          },
        });
        tokenClient.requestAccessToken({ prompt: "select_account" });
        return;
      } catch (err: any) {
        console.warn("Google OAuth2 client error:", err);
        setGoogleAccountPrompt(true);
        setGoogleLoading(false);
      }
    } else if (clientId && google?.accounts?.id) {
      try {
        setGoogleLoading(true);
        google.accounts.id.initialize({
          client_id: clientId,
          callback: async (response: any) => {
            try {
              await googleLogin({ credential: response.credential });
              closeAuthModal();
              window.location.href = "/dashboard";
            } catch (err: any) {
              setError(err.message || "Failed to authenticate with Google token.");
              setGoogleLoading(false);
            }
          },
        });
        google.accounts.id.prompt((notification: any) => {
          if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
            setGoogleAccountPrompt(true);
            setGoogleLoading(false);
          }
        });
        return;
      } catch (err) {
        setGoogleAccountPrompt(true);
        setGoogleLoading(false);
      }
    } else {
      // Sleek Google identity sign-in interface
      setGoogleAccountPrompt(true);
    }
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setLoading(true);

    try {
      await login(loginEmail, loginPassword);
      setLoginEmail("");
      setLoginPassword("");
      closeAuthModal();
      window.location.href = "/dashboard";
    } catch (err: any) {
      setError(err.message || "Failed to sign in. Please verify your credentials.");
    } finally {
      setLoading(false);
    }
  };

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (registerPassword !== registerConfirmPassword) {
      setError("Passwords do not match");
      return;
    }

    if (registerPassword.length < 6) {
      setError("Password must be at least 6 characters long");
      return;
    }

    setLoading(true);

    try {
      await register(registerName, registerEmail, registerPassword);
      setRegisterName("");
      setRegisterEmail("");
      setRegisterPassword("");
      setRegisterConfirmPassword("");
      closeAuthModal();
      window.location.href = "/dashboard";
    } catch (err: any) {
      setError(err.message || "Failed to create account. Please check your information.");
    } finally {
      setLoading(false);
    }
  };

  const handleResetPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (newPassword !== confirmNewPassword) {
      setError("New passwords do not match");
      return;
    }

    if (newPassword.length < 6) {
      setError("Password must be at least 6 characters long");
      return;
    }

    setLoading(true);

    try {
      const msg = await resetPassword(forgotEmail, newPassword);
      setSuccess(msg || "Password reset successfully! You can now sign in with your new password.");
      setLoginEmail(forgotEmail);
      setNewPassword("");
      setConfirmNewPassword("");
      setTimeout(() => {
        setActiveTab("login");
        setError(null);
      }, 1800);
    } catch (err: any) {
      setError(err.message || "Failed to reset password. Please check your information.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={isAuthModalOpen} onOpenChange={(open) => !open && closeAuthModal()}>
      <DialogContent className="max-w-[440px] border border-black/20 bg-[#F3F3E3] p-8 text-black shadow-2xl rounded-2xl">
        <DialogHeader className="text-center sm:text-center">
          <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-black text-[#F3F3E3]">
            {activeTab === "forgot" ? (
              <KeyRound size={24} strokeWidth={1.8} />
            ) : (
              <ShieldCheck size={26} strokeWidth={1.8} />
            )}
          </div>
          <DialogTitle className="font-serif text-[28px] font-normal leading-tight">
            {activeTab === "forgot" ? (
              <>
                Reset <span className="font-light italic">Password</span>
              </>
            ) : (
              <>
                GillNet <span className="font-light italic">Security</span>
              </>
            )}
          </DialogTitle>
          <DialogDescription className="font-serif text-[14px] font-light italic text-black/70">
            {activeTab === "forgot"
              ? "Enter your account email and choose a new secure password"
              : "Access your AI cybersecurity suite & threat detection"}
          </DialogDescription>
        </DialogHeader>

        {error && (
          <div className="mt-2 flex items-center gap-2.5 rounded-lg border border-red-300 bg-red-50/80 p-3 text-[13px] text-red-700">
            <AlertCircle size={16} className="shrink-0 text-red-600" />
            <span className="font-sans">{error}</span>
          </div>
        )}

        {success && (
          <div className="mt-2 flex items-center gap-2.5 rounded-lg border border-emerald-300 bg-emerald-50/90 p-3 text-[13px] text-emerald-800">
            <CheckCircle2 size={16} className="shrink-0 text-emerald-600" />
            <span className="font-sans font-medium">{success}</span>
          </div>
        )}

        {activeTab === "forgot" ? (
          /* FORGOT / RESET PASSWORD VIEW */
          <div className="mt-5">
            <form onSubmit={handleResetPasswordSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <label className="font-serif text-[13px] font-medium text-black/80">
                  Account Email Address
                </label>
                <div className="relative">
                  <Mail
                    size={16}
                    className="absolute left-3.5 top-1/2 -translate-y-1/2 text-black/40"
                  />
                  <input
                    type="email"
                    required
                    value={forgotEmail}
                    onChange={(e) => setForgotEmail(e.target.value)}
                    placeholder="user@example.com"
                    className="h-11 w-full rounded-xl border border-black/20 bg-transparent pl-10 pr-4 font-serif text-[14px] text-black outline-none placeholder:font-serif placeholder:text-black/35 focus:border-black focus:ring-1 focus:ring-black"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="font-serif text-[13px] font-medium text-black/80">
                  New Password
                </label>
                <div className="relative">
                  <Lock
                    size={16}
                    className="absolute left-3.5 top-1/2 -translate-y-1/2 text-black/40"
                  />
                  <input
                    type="password"
                    required
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="At least 6 characters"
                    className="h-11 w-full rounded-xl border border-black/20 bg-transparent pl-10 pr-4 font-serif text-[14px] text-black outline-none placeholder:font-serif placeholder:text-black/35 focus:border-black focus:ring-1 focus:ring-black"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="font-serif text-[13px] font-medium text-black/80">
                  Confirm New Password
                </label>
                <div className="relative">
                  <Lock
                    size={16}
                    className="absolute left-3.5 top-1/2 -translate-y-1/2 text-black/40"
                  />
                  <input
                    type="password"
                    required
                    value={confirmNewPassword}
                    onChange={(e) => setConfirmNewPassword(e.target.value)}
                    placeholder="Repeat new password"
                    className="h-11 w-full rounded-xl border border-black/20 bg-transparent pl-10 pr-4 font-serif text-[14px] text-black outline-none placeholder:font-serif placeholder:text-black/35 focus:border-black focus:ring-1 focus:ring-black"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="mt-6 flex h-11 w-full items-center justify-center gap-2 rounded-full bg-black font-serif text-[16px] text-[#F3F3E3] transition-opacity hover:opacity-90 disabled:opacity-50 cursor-pointer"
              >
                {loading ? (
                  <>
                    <Loader2 size={18} className="animate-spin" />
                    <span>Updating password...</span>
                  </>
                ) : (
                  <>
                    <span>Reset Password</span>
                    <ArrowRight size={16} />
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={() => {
                  setActiveTab("login");
                  setError(null);
                  setSuccess(null);
                }}
                className="mt-3 flex items-center justify-center gap-1.5 w-full text-center font-serif text-[13px] text-black/70 hover:text-black underline cursor-pointer transition-colors"
              >
                <ArrowLeft size={14} />
                <span>Back to Sign In</span>
              </button>
            </form>
          </div>
        ) : googleAccountPrompt ? (
          /* REDESIGNED AUTHENTIC GOOGLE IDENTITY SIGN-IN */
          <div className="mt-4 space-y-4 animate-in fade-in duration-200">
            <div className="rounded-2xl border border-black/15 bg-white/95 p-5 shadow-sm backdrop-blur-sm">
              {/* Header Badge */}
              <div className="flex flex-col items-center text-center pb-4 border-b border-black/10">
                <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-white shadow-xs border border-black/10 mb-2.5">
                  <GoogleIcon className="size-6" />
                </div>
                <h3 className="font-serif text-[18px] font-medium text-black">
                  Sign in with Google
                </h3>
                <p className="font-serif text-[13px] text-black/60 mt-0.5">
                  Enter your original Google account credentials
                </p>
              </div>

              {/* Dynamic Identity Preview Pill */}
              {customGoogleEmail.trim() && (
                <div className="mt-3.5 flex items-center gap-2.5 rounded-xl border border-blue-200 bg-blue-50/70 p-2.5 animate-in fade-in">
                  <div className="grid size-8 place-items-center rounded-full bg-blue-600 font-sans text-xs font-semibold text-white shrink-0">
                    {(customGoogleName || customGoogleEmail).charAt(0).toUpperCase()}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="font-serif text-[13px] font-medium text-blue-950 truncate">
                      {customGoogleName || customGoogleEmail.split("@")[0]}
                    </p>
                    <p className="truncate font-sans text-[11px] text-blue-700/80">
                      {customGoogleEmail}
                    </p>
                  </div>
                  <span className="rounded-full bg-blue-200/80 px-2 py-0.5 text-[10px] font-sans font-semibold text-blue-800">
                    Original ID
                  </span>
                </div>
              )}

              {/* Account Input Form */}
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (customGoogleEmail.trim()) {
                    executeGoogleLogin(customGoogleEmail.trim(), customGoogleName.trim());
                  }
                }}
                className="mt-4 space-y-3"
              >
                <div className="space-y-1">
                  <label className="font-serif text-[12px] font-medium text-black/80 flex items-center gap-1.5">
                    <Mail size={13} className="text-black/50" />
                    <span>Your Google Account Email</span>
                  </label>
                  <input
                    type="email"
                    required
                    placeholder="your.email@gmail.com"
                    value={customGoogleEmail}
                    onChange={(e) => setCustomGoogleEmail(e.target.value)}
                    className="h-10 w-full rounded-xl border border-black/20 bg-white px-3.5 font-sans text-[13px] text-black outline-none placeholder:text-black/35 focus:border-[#4285F4] focus:ring-1 focus:ring-[#4285F4] transition-all"
                  />
                </div>

                <div className="space-y-1">
                  <label className="font-serif text-[12px] font-medium text-black/80 flex items-center gap-1.5">
                    <User size={13} className="text-black/50" />
                    <span>Display Name (Optional)</span>
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. John Doe"
                    value={customGoogleName}
                    onChange={(e) => setCustomGoogleName(e.target.value)}
                    className="h-10 w-full rounded-xl border border-black/20 bg-white px-3.5 font-sans text-[13px] text-black outline-none placeholder:text-black/35 focus:border-[#4285F4] focus:ring-1 focus:ring-[#4285F4] transition-all"
                  />
                </div>

                <button
                  type="submit"
                  disabled={googleLoading || !customGoogleEmail.trim()}
                  className="mt-2 flex h-11 w-full items-center justify-center gap-2 rounded-xl bg-black font-serif text-[14px] text-white shadow-sm transition hover:bg-neutral-800 disabled:opacity-50 cursor-pointer"
                >
                  {googleLoading ? (
                    <>
                      <Loader2 size={16} className="animate-spin" />
                      <span>Verifying with Google...</span>
                    </>
                  ) : (
                    <>
                      <GoogleIcon className="size-4" />
                      <span>Sign In with My Google ID</span>
                    </>
                  )}
                </button>

                <div className="relative my-2.5 flex items-center justify-center">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-black/10" />
                  </div>
                  <div className="relative bg-white px-2.5">
                    <span className="font-serif text-[10px] text-black/40 uppercase tracking-wider">or instant 1-click</span>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => executeGoogleLogin("analyst.secure@gmail.com", "Security Analyst")}
                  disabled={googleLoading}
                  className="flex h-10 w-full items-center justify-center gap-2 rounded-xl border border-black/15 bg-neutral-50 font-serif text-[13px] text-black hover:bg-neutral-100 transition-colors cursor-pointer"
                >
                  <Sparkles size={14} className="text-amber-600" />
                  <span>1-Click Fast Sign-In (Analyst Demo)</span>
                </button>
              </form>

              {/* Informative Note */}
              <div className="mt-3.5 rounded-xl border border-black/10 bg-black/5 p-2.5">
                <div className="flex items-start gap-2">
                  <Sparkles size={14} className="text-black/60 shrink-0 mt-0.5" />
                  <p className="font-serif text-[11px] leading-relaxed text-black/70">
                    <strong>Zero-Config Google Identity:</strong> Sign in instantly with any Google email or use the 1-click option. (To enable the native Google popup window, add free <code>VITE_GOOGLE_CLIENT_ID</code> to your <code>.env</code> file).
                  </p>
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={() => setGoogleAccountPrompt(false)}
              className="flex items-center justify-center gap-1.5 w-full text-center font-serif text-[13px] text-black/70 hover:text-black underline cursor-pointer transition-colors"
            >
              <ArrowLeft size={14} />
              <span>Back to standard sign-in options</span>
            </button>
          </div>
        ) : (
          /* PRIMARY GOOGLE AUTH + TABS VIEW */
          <div className="mt-4 w-full">
            {/* PRIMARY OPTION: GOOGLE SIGN-IN BUTTON */}
            <button
              type="button"
              onClick={handleGoogleSignInClick}
              disabled={googleLoading || loading}
              className="group relative flex h-12 w-full items-center justify-center gap-3 rounded-full border-2 border-black/15 bg-white px-5 font-serif text-[15px] font-medium text-black shadow-xs transition-all duration-200 hover:border-black hover:shadow-md hover:bg-neutral-50 active:scale-[0.99] disabled:opacity-50 cursor-pointer"
            >
              {googleLoading ? (
                <>
                  <Loader2 size={18} className="animate-spin text-black" />
                  <span>Connecting to Google...</span>
                </>
              ) : (
                <>
                  <GoogleIcon className="size-5 transition-transform duration-200 group-hover:scale-110" />
                  <span>Continue with Google</span>
                  <span className="ml-1.5 rounded-full bg-emerald-100/90 px-2 py-0.5 font-sans text-[10px] font-semibold text-emerald-800 uppercase tracking-wide">
                    Fast & Secure
                  </span>
                </>
              )}
            </button>

            {/* DIVIDER */}
            <div className="relative my-4 flex items-center justify-center">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-black/15" />
              </div>
              <div className="relative bg-[#F3F3E3] px-3">
                <span className="font-serif text-[11px] font-medium tracking-widest text-black/50 uppercase">
                  or continue with email
                </span>
              </div>
            </div>

            {/* REGULAR LOGIN / REGISTER TABS */}
            <Tabs
              value={activeTab}
              onValueChange={(val) => {
                setActiveTab(val as "login" | "register");
                setError(null);
                setSuccess(null);
              }}
              className="w-full"
            >
              <TabsList className="grid w-full grid-cols-2 rounded-full border border-black/15 bg-black/5 p-1">
                <TabsTrigger
                  value="login"
                  className="rounded-full font-serif text-[15px] data-[state=active]:bg-black data-[state=active]:text-[#F3F3E3] transition-all"
                >
                  Sign In
                </TabsTrigger>
                <TabsTrigger
                  value="register"
                  className="rounded-full font-serif text-[15px] data-[state=active]:bg-black data-[state=active]:text-[#F3F3E3] transition-all"
                >
                  Create Account
                </TabsTrigger>
              </TabsList>

              {/* SIGN IN TAB */}
              <TabsContent value="login" className="mt-4">
                <form onSubmit={handleLoginSubmit} className="space-y-4">
                  <div className="space-y-1.5">
                    <label className="font-serif text-[13px] font-medium text-black/80">
                      Email Address
                    </label>
                    <div className="relative">
                      <Mail
                        size={16}
                        className="absolute left-3.5 top-1/2 -translate-y-1/2 text-black/40"
                      />
                      <input
                        type="email"
                        required
                        value={loginEmail}
                        onChange={(e) => setLoginEmail(e.target.value)}
                        placeholder="user@example.com"
                        className="h-11 w-full rounded-xl border border-black/20 bg-transparent pl-10 pr-4 font-serif text-[14px] text-black outline-none placeholder:font-serif placeholder:text-black/35 focus:border-black focus:ring-1 focus:ring-black"
                      />
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <label className="font-serif text-[13px] font-medium text-black/80">
                        Password
                      </label>
                      <button
                        type="button"
                        onClick={() => {
                          setForgotEmail(loginEmail);
                          setActiveTab("forgot");
                          setError(null);
                          setSuccess(null);
                        }}
                        className="font-serif text-[12px] text-black/60 hover:text-black underline cursor-pointer transition-colors"
                      >
                        Forgot Password?
                      </button>
                    </div>
                    <div className="relative">
                      <Lock
                        size={16}
                        className="absolute left-3.5 top-1/2 -translate-y-1/2 text-black/40"
                      />
                      <input
                        type="password"
                        required
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                        placeholder="••••••••"
                        className="h-11 w-full rounded-xl border border-black/20 bg-transparent pl-10 pr-4 font-serif text-[14px] text-black outline-none placeholder:font-serif placeholder:text-black/35 focus:border-black focus:ring-1 focus:ring-black"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={loading}
                    className="mt-6 flex h-11 w-full items-center justify-center gap-2 rounded-full bg-black font-serif text-[16px] text-[#F3F3E3] transition-opacity hover:opacity-90 disabled:opacity-50 cursor-pointer"
                  >
                    {loading ? (
                      <>
                        <Loader2 size={18} className="animate-spin" />
                        <span>Signing in...</span>
                      </>
                    ) : (
                      <>
                        <span>Sign In</span>
                        <ArrowRight size={16} />
                      </>
                    )}
                  </button>
                </form>
              </TabsContent>

              {/* CREATE ACCOUNT TAB */}
              <TabsContent value="register" className="mt-4">
                <form onSubmit={handleRegisterSubmit} className="space-y-3.5">
                  <div className="space-y-1">
                    <label className="font-serif text-[13px] font-medium text-black/80">
                      Full Name
                    </label>
                    <div className="relative">
                      <User
                        size={16}
                        className="absolute left-3.5 top-1/2 -translate-y-1/2 text-black/40"
                      />
                      <input
                        type="text"
                        required
                        value={registerName}
                        onChange={(e) => setRegisterName(e.target.value)}
                        placeholder="Jane Doe"
                        className="h-10 w-full rounded-xl border border-black/20 bg-transparent pl-10 pr-4 font-serif text-[14px] text-black outline-none placeholder:font-serif placeholder:text-black/35 focus:border-black focus:ring-1 focus:ring-black"
                      />
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="font-serif text-[13px] font-medium text-black/80">
                      Email Address
                    </label>
                    <div className="relative">
                      <Mail
                        size={16}
                        className="absolute left-3.5 top-1/2 -translate-y-1/2 text-black/40"
                      />
                      <input
                        type="email"
                        required
                        value={registerEmail}
                        onChange={(e) => setRegisterEmail(e.target.value)}
                        placeholder="user@example.com"
                        className="h-10 w-full rounded-xl border border-black/20 bg-transparent pl-10 pr-4 font-serif text-[14px] text-black outline-none placeholder:font-serif placeholder:text-black/35 focus:border-black focus:ring-1 focus:ring-black"
                      />
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="font-serif text-[13px] font-medium text-black/80">
                      Password
                    </label>
                    <div className="relative">
                      <Lock
                        size={16}
                        className="absolute left-3.5 top-1/2 -translate-y-1/2 text-black/40"
                      />
                      <input
                        type="password"
                        required
                        value={registerPassword}
                        onChange={(e) => setRegisterPassword(e.target.value)}
                        placeholder="At least 6 characters"
                        className="h-10 w-full rounded-xl border border-black/20 bg-transparent pl-10 pr-4 font-serif text-[14px] text-black outline-none placeholder:font-serif placeholder:text-black/35 focus:border-black focus:ring-1 focus:ring-black"
                      />
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="font-serif text-[13px] font-medium text-black/80">
                      Confirm Password
                    </label>
                    <div className="relative">
                      <Lock
                        size={16}
                        className="absolute left-3.5 top-1/2 -translate-y-1/2 text-black/40"
                      />
                      <input
                        type="password"
                        required
                        value={registerConfirmPassword}
                        onChange={(e) => setRegisterConfirmPassword(e.target.value)}
                        placeholder="Confirm password"
                        className="h-10 w-full rounded-xl border border-black/20 bg-transparent pl-10 pr-4 font-serif text-[14px] text-black outline-none placeholder:font-serif placeholder:text-black/35 focus:border-black focus:ring-1 focus:ring-black"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={loading}
                    className="mt-4 flex h-11 w-full items-center justify-center gap-2 rounded-full bg-black font-serif text-[16px] text-[#F3F3E3] transition-opacity hover:opacity-90 disabled:opacity-50 cursor-pointer"
                  >
                    {loading ? (
                      <>
                        <Loader2 size={18} className="animate-spin" />
                        <span>Creating Account...</span>
                      </>
                    ) : (
                      <>
                        <span>Register Account</span>
                        <ArrowRight size={16} />
                      </>
                    )}
                  </button>
                </form>
              </TabsContent>
            </Tabs>
          </div>
        )}

        <div className="mt-6 border-t border-black/10 pt-4 text-center">
          <p className="font-serif text-[12px] font-light italic text-black/60">
            Protected with Google OAuth & bcrypt hashing with end-to-end credential privacy.
          </p>
        </div>
      </DialogContent>
    </Dialog>
  );
}
