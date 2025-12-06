import type { FC } from 'react';
import { useAuth } from '../hooks/useAuth';
import { useNavigate } from 'react-router-dom';

const Header: FC = () => {
  const { user, isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <header className="bg-white shadow-sm border-b box-border w-full">
      <div className="w-full px-0 py-4">
        <div className="flex justify-between items-center w-full">
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 bg-primary-600 rounded-full flex items-center justify-center">
              
            </div>
            <h1 className="text-xl font-bold text-gray-900">Secure Web App</h1>
          </div>
          
          {isAuthenticated && (
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-700">
                Welcome, <strong>{user?.username}</strong>
              </span>
              <button
                onClick={handleLogout}
                className="bg-gray-500 hover:bg-gray-600 text-black px-4 py-2 rounded-lg text-sm font-medium transition-colors"
              >
                Logout
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};

export default Header;
