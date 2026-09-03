import React, { createContext, useContext, useState, useEffect } from 'react';
import { UserProfile, LoginRequest, RegisterRequest } from '@phishnetra/shared';
import { api } from '../services/api';

interface AuthContextType {
  user: UserProfile | null;
  token: string | null;
  isLoading: boolean;
  login: (credentials: LoginRequest) => Promise<void>;
  register: (data: RegisterRequest) => Promise<void>;
  logout: () => Promise<void>;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('phishnetra_token'));
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const initAuth = async () => {
      const storedToken = localStorage.getItem('phishnetra_token');
      if (storedToken) {
        try {
          const response = await api.getMe();
          setUser(response.user);
        } catch {
          // Token invalid or expired
          localStorage.removeItem('phishnetra_token');
          setToken(null);
          setUser(null);
        }
      }
      setIsLoading(false);
    };

    initAuth();
  }, []);

  const login = async (credentials: LoginRequest) => {
    const response = await api.login(credentials);
    localStorage.setItem('phishnetra_token', response.token);
    setToken(response.token);
    setUser(response.user);
  };

  const register = async (data: RegisterRequest) => {
    const response = await api.register(data);
    localStorage.setItem('phishnetra_token', response.token);
    setToken(response.token);
    setUser(response.user);
  };

  const logout = async () => {
    try {
      await api.logout();
    } catch {
      // ignore
    } finally {
      localStorage.removeItem('phishnetra_token');
      setToken(null);
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isLoading,
        login,
        register,
        logout,
        isAuthenticated: !!user
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
