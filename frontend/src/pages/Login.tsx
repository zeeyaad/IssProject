// Login.tsx
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { makeRequest } from '../utils/api';
import { useAuth } from '../hooks/useAuth';
import type { User } from '../hooks/useAuth';

const Login: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('admin1');
  const [password, setPassword] = useState('••••••••');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [email, setEmail] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);

  const navigate = useNavigate();
  const { login } = useAuth();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      alert('Username and password are required');
      return;
    }

    try {
      const data = await makeRequest<{ user: User; token: string }>("/api/login", {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });

      await login(data.user, data.token);
      navigate('/dashboard');
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Login failed';
      alert(message);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      alert('Username and password are required');
      return;
    }
    if (password.length < 8) {
      alert('Password must be at least 8 characters');
      return;
    }
    if (password !== confirmPassword) {
      alert('Passwords do not match');
      return;
    }

    const formData = { username, password, email: email || undefined } as { username: string; password: string; email?: string };
    try {
      const res = await makeRequest<{ userId: string }>("/api/register", {
        method: 'POST',
        body: JSON.stringify(formData)
      });
      const loginRes = await makeRequest<{ user: User; token: string }>("/api/login", {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });
      await login(loginRes.user, loginRes.token);
      navigate('/dashboard');
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Registration failed';
      alert(message);
    }
  };

  // Real Google SSO Login 
  const handleGoogleSSO = async () => {
    setGoogleLoading(true);

    try {
      // Get Google OAuth URL from backend (optionally pass login_hint if email provided)
      const hint = email?.trim() ? `?login_hint=${encodeURIComponent(email.trim())}` : '';
      const response = await makeRequest<{ authUrl: string }>(`/api/auth/google${hint}`);

      // Store current page for redirect back 
      sessionStorage.setItem('preAuthPath', window.location.pathname);

      // Redirect to Google OAuth page 
      window.location.href = response.authUrl;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Failed to initiate Google login';
      alert(message);
      setGoogleLoading(false);
    }
  };

  const securityFeatures = [
    'AES-256-GCM Encryption',
    'bcrypt Password Hashing',
    'JWT Authentication',
    'Single Sign-On (SSO)',
    'SQL Injection Prevention',
    'XSS Prevention',
    'DoS Protection',
    'Secure Headers'
  ];

  return (
    <div className="w-screen min-h-screen bg-gradient-to-br from-[#6366f1] to-[#8b5cf6] p-2 sm:p-5 overflow-x-hidden">
      <div className="bg-white rounded-2xl shadow-xl ring-1 ring-black/5 overflow-hidden w-full max-w-none grid grid-cols-1 lg:grid-cols-2 min-h-[400px] lg:min-h-[600px]">
        {/* Security Panel */}
        <div className="bg-gradient-to-br from-[#6366f1] to-[#8b5cf6] p-6 lg:p-12 text-white flex flex-col justify-center hidden lg:flex">
          <div className="p-6">
            <h2 className="text-2xl font-semibold mb-4 flex items-center gap-3">
              <span className="text-2xl">🛡️</span>
              Enterprise Security
            </h2>
            <p className="opacity-90 mb-6 text-sm leading-relaxed">
              Your data is protected by industry-leading security standards and encryption protocols.
            </p>

            <ul className="space-y-2">
              {securityFeatures.map((feature, index) => (
                <li key={index} className="flex items-center gap-3 text-sm opacity-95 border-b border-white/10 last:border-b-0 pb-2">
                  <span className="text-green-400 font-bold">✓</span>
                  <span>{feature}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Login Panel */}
        <div className="p-6 lg:p-12 flex flex-col justify-center lg:border-l lg:border-gray-200">
          <div className="mb-8">
            <h1 className="text-3xl font-semibold text-gray-800 mb-2">Welcome Back</h1>
            <p className="text-gray-500 text-sm">Sign in to your secure account</p>
          </div>

          {/* Tabs */}
          <div className="flex gap-5 mb-6 border-b-2 border-gray-200">
            <button
              className={`pb-3 font-medium transition-all duration-300 border-b-2 ${activeTab === 'login'
                ? 'text-[#6366f1] border-[#6366f1]'
                : 'text-gray-500 border-transparent'
                }`}
              onClick={() => setActiveTab('login')}
            >
              Login
            </button>
            <button
              className={`pb-3 font-medium transition-all duration-300 border-b-2 ${activeTab === 'register'
                ? 'text-[#6366f1] border-[#6366f1]'
                : 'text-gray-500 border-transparent'
                }`}
              onClick={() => setActiveTab('register')}
            >
              Register
            </button>
          </div>

          <form onSubmit={activeTab === 'register' ? handleRegister : handleLogin} className="space-y-6">
            <div className="mb-4">
              <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
                Username
              </label>
              <input
                type="text"
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-3 border-2 border-gray-200 rounded-xl text-sm transition-all duration-300 outline-none bg-white text-gray-900 placeholder-gray-400 focus:border-[#6366f1] focus:ring-4 focus:ring-[#6366f1]/10"
                placeholder="Enter your username"
              />
            </div>

            {activeTab === 'register' && (
              <div className="mb-4">
                <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                  Email (optional)
                </label>
                <input
                  type="email"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full px-4 py-3 border-2 border-gray-200 rounded-xl text-sm transition-all duration-300 outline-none bg-white text-gray-900 placeholder-gray-400 focus:border-[#6366f1] focus:ring-4 focus:ring-[#6366f1]/10"
                  placeholder="Enter your email"
                />
              </div>
            )}

            <div className="mb-4">
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pr-10 px-4 py-3 border-2 border-gray-200 rounded-xl text-sm transition-all duration-300 outline-none bg-white text-gray-900 placeholder-gray-400 focus:border-[#6366f1] focus:ring-4 focus:ring-[#6366f1]/10"
                  placeholder="Enter your password"
                />
                <button
                  type="button"
                  aria-label="Toggle password visibility"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute inset-y-0 right-3 flex items-center text-gray-500 hover:text-gray-700"
                >
                  <EyeIcon open={showPassword} />
                </button>
              </div>
            </div>

            {activeTab === 'register' && (
              <div className="mb-4">
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-1">
                  Confirm Password
                </label>
                <div className="relative">
                  <input
                    type={showConfirm ? 'text' : 'password'}
                    id="confirmPassword"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full pr-10 px-4 py-3 border-2 border-gray-200 rounded-xl text-sm transition-all duration-300 outline-none bg-white text-gray-900 placeholder-gray-400 focus:border-[#6366f1] focus:ring-4 focus:ring-[#6366f1]/10"
                    placeholder="Confirm your password"
                  />
                  <button
                    type="button"
                    aria-label="Toggle confirm password visibility"
                    onClick={() => setShowConfirm((v) => !v)}
                    className="absolute inset-y-0 right-3 flex items-center text-gray-500 hover:text-gray-700"
                  >
                    <EyeIcon open={showConfirm} />
                  </button>
                </div>
              </div>
            )}

            {activeTab === 'login' && (
              <div className="text-right mb-6">
                <a href="#forgot" className="text-sm font-medium text-[#6366f1] hover:underline">
                  Forgot password?
                </a>
              </div>
            )}


            <button
              type="submit"
              className="w-full bg-gradient-to-r from-[#6366f1] to-[#8b5cf6] text-white py-3 rounded-xl font-semibold text-sm transition-all duration-300 hover:translate-y-[-2px] hover:shadow-lg hover:shadow-[#6366f1]/30"
            >
              {activeTab === 'register' ? 'Sign Up' : 'Sign In'}
            </button>

            <div className="relative my-8">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-200"></div>
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-white text-gray-500">or</span>
              </div>
            </div>

            <button
              type="button"
              onClick={handleGoogleSSO}
              disabled={googleLoading}
              className="w-full bg-white border border-gray-300 hover:bg-gray-50 text-gray-700 py-3 px-4 rounded-lg font-medium transition-colors flex items-center justify-center space-x-3"
            >
              {googleLoading ? (
                <>
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-gray-700"></div>
                  <span>Connecting to Google...</span>
                </>
              ) : (
                <>
                  <svg className="w-5 h-5" viewBox="0 0 24 24">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                  </svg>
                  <span>Continue with Google</span>
                </>
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

const EyeIcon: React.FC<{ open: boolean }> = ({ open }) => (
  open ? (
    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
      <circle cx="12" cy="12" r="3"></circle>
    </svg>
  ) : (
    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8a20.4 20.4 0 0 1 5.06-6.06"></path>
      <path d="M1 1l22 22"></path>
      <path d="M9.88 9.88A3 3 0 0 0 12 15a3 3 0 0 0 2.12-.88"></path>
    </svg>
  )
);

export default Login;
