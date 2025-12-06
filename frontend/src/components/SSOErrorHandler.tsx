import React from 'react'; 
import { useNavigate } from 'react-router-dom'; 

interface SSOErrorHandlerProps {
  error: string;
}

const SSOErrorHandler: React.FC<SSOErrorHandlerProps> = ({ error }) => { 
  const navigate = useNavigate(); 
  const [countdown, setCountdown] = React.useState(5); 

  React.useEffect(() => { 
    if (countdown > 0) { 
      const timer = setTimeout(() => setCountdown(countdown - 1), 1000); 
      return () => clearTimeout(timer); 
    } else { 
      navigate('/login'); 
    } 
  }, [countdown, navigate]); 

  return (
    <div className="text-center p-8"> 
      <div className="text-red-500 text-5xl mb-4">⚠️</div> 
      <h3 className="text-xl font-bold text-gray-900 mb-2">Single Sign-On Error</h3> 
      <p className="text-gray-600 mb-4">{error}</p> 
      <div className="text-sm text-gray-500"> 
        Redirecting to login in {countdown} seconds... 
      </div> 
      <button 
        onClick={() => navigate('/login')} 
        className="mt-4 text-primary-600 hover:text-primary-800 font-medium" 
      > 
        Go to Login Now 
      </button> 
      <div className="mt-6 flex items-center justify-center gap-4">
        <button
          onClick={() => { window.location.href = '/api/auth/google?force=1'; }}
          className="text-sm bg-gray-100 hover:bg-gray-200 text-gray-800 px-4 py-2 rounded-lg"
        >
          Try Again (Verify if needed)
        </button>
      </div>
    </div> 
  ); 
} 

export default SSOErrorHandler;
