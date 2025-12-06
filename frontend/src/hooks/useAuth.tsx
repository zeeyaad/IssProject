import { createContext, useContext, useState, useEffect } from 'react';
import type { ReactNode } from 'react';
import { makeRequest } from '../utils/api';

export interface User {
  id?: string | number;
  username: string;
  email?: string;
  [key: string]: any;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (userData: User, authToken?: string) => Promise<void>;
  logout: () => Promise<void>;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const userData = localStorage.getItem('userData');
    const storedToken = localStorage.getItem('authToken');
    if (userData) setUser(JSON.parse(userData));
    if (storedToken) setToken(storedToken);
    setLoading(false);
  }, []);

  const login = async (userData: User, authToken?: string): Promise<void> => {
    setUser(userData);
    if (authToken) {
      setToken(authToken);
      localStorage.setItem('authToken', authToken);
    }
    localStorage.setItem('userData', JSON.stringify(userData));
  };

  const logout = async (): Promise<void> => {
    try {
      // Call logout endpoint to clear server-side session and httpOnly cookie
      await makeRequest('/api/logout', {
        method: 'POST'
      });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      setUser(null);
      setToken(null);
      localStorage.removeItem('userData');
      localStorage.removeItem('authToken');
    }
  };

  const value: AuthContextType = {
    user,
    token,
    isAuthenticated: !!token,
    login,
    logout,
    loading
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
