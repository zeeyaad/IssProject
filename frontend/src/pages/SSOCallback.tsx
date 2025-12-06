import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import SSOErrorHandler from '../components/SSOErrorHandler';

const SSOCallback: React.FC = () => {
  const navigate = useNavigate();
  const { login } = useAuth();
  const params = new URLSearchParams(window.location.search);
  const token = params.get('token');
  const username = params.get('username') || 'sso_user';
  const email = params.get('email') || '';
  const errParam = params.get('error') || (token ? '' : 'Missing token in callback');

  useEffect(() => {
    if (!token) return;
    const userData = { username, email } as { username: string; email?: string };
    (async () => {
      try {
        await login(userData, token);
        const preAuthPath = sessionStorage.getItem('preAuthPath') || '/dashboard';
        sessionStorage.removeItem('preAuthPath');
        navigate(preAuthPath, { replace: true });
      } catch (e) {
        const message = e instanceof Error ? e.message : 'Failed to complete SSO login';
        navigate(`/login?error=${encodeURIComponent(message)}`);
      }
    })();
  }, [email, login, navigate, token, username]);

  if (errParam) {
    return <SSOErrorHandler error={errParam} />;
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="bg-white border rounded-lg shadow-sm p-8 text-center">
        <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-600 mx-auto mb-4"></div>
        <h3 className="text-lg font-semibold text-gray-900">Completing sign in…</h3>
        <p className="text-sm text-gray-600 mt-2">Please wait while we finish authentication.</p>
      </div>
    </div>
  );
};

export default SSOCallback;
