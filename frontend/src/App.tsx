import React from 'react'; 
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'; 
import { AuthProvider, useAuth } from './hooks/useAuth'; 
import Login from './pages/Login'; 
import Dashboard from './pages/Dashboard'; 
import SSOCallback from './pages/SSOCallback'; 
import Layout from './components/Layout'; 
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

interface RouteProps {
  children: React.ReactNode;
}

function ProtectedRoute({ children }: RouteProps) { 
  const { isAuthenticated } = useAuth(); 
  return isAuthenticated ? children : <Navigate to="/login" />; 
} 

function PublicRoute({ children }: RouteProps) { 
  const { isAuthenticated } = useAuth(); 
  return !isAuthenticated ? children : <Navigate to="/dashboard" />; 
} 

function App() { 
  return ( 
    <AuthProvider> 
      <Router> 
        <NavGuard />
        <Routes> 
          {/* Public routes without layout */} 
          <Route path="/login" element={ 
            <PublicRoute> 
              <Login /> 
            </PublicRoute> 
          } /> 
          <Route path="/auth/callback" element={ 
            <PublicRoute> 
              <SSOCallback /> 
            </PublicRoute> 
          } /> 
          
          {/* Protected routes with layout */} 
          <Route path="/dashboard" element={ 
            <ProtectedRoute> 
              <Layout> 
                <Dashboard /> 
              </Layout> 
            </ProtectedRoute> 
          } /> 
          <Route path="/" element={<Navigate to="/dashboard" />} /> 
        </Routes> 
      </Router> 
    </AuthProvider> 
  ); 
} 

function NavGuard() {
  const { isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();
  useEffect(() => {
    const onPop = () => {
      if (isAuthenticated) {
        logout().then(() => navigate('/login', { replace: true }));
      }
    };
    const onPageShow = (e: PageTransitionEvent) => {
      if ((e as any).persisted && isAuthenticated) {
        logout().then(() => navigate('/login', { replace: true }));
      }
    };
    window.addEventListener('popstate', onPop);
    window.addEventListener('pageshow', onPageShow as any);
    return () => {
      window.removeEventListener('popstate', onPop);
      window.removeEventListener('pageshow', onPageShow as any);
    };
  }, [isAuthenticated, logout, navigate]);
  return null;
}

export default App;
