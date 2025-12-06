import type { FC, ReactNode } from 'react';
import { useAuth } from '../hooks/useAuth';
import Header from './Header';

interface LayoutProps {
  children: ReactNode;
}

const Layout: FC<LayoutProps> = ({ children }) => {
  const { loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 w-screen box-border overflow-x-hidden">
      <Header />
      <main className="w-full px-0 py-8 box-border">
        {children}
      </main>
    </div>
  );
};

export default Layout;
