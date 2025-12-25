import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Loader2, Mail } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import toast from 'react-hot-toast';

const BRANDFETCH_CLIENT_ID = "1idHfSqccAbp2Vb4wMw";

// Brand logos for the animated carousel - common phishing targets
const companies = [
  {
    name: "Google",
    logo: `https://cdn.brandfetch.io/google.com/w/400/h/400?c=${BRANDFETCH_CLIENT_ID}`,
    bgColor: "#4285F4",
  },
  {
    name: "Microsoft",
    logo: `https://cdn.brandfetch.io/microsoft.com/w/400/h/400?c=${BRANDFETCH_CLIENT_ID}`,
    bgColor: "#00A4EF",
  },
  {
    name: "PayPal",
    logo: `https://cdn.brandfetch.io/paypal.com/w/400/h/400?c=${BRANDFETCH_CLIENT_ID}`,
    bgColor: "#003087",
  },
  {
    name: "Amazon",
    logo: `https://cdn.brandfetch.io/amazon.com/w/400/h/400?c=${BRANDFETCH_CLIENT_ID}`,
    bgColor: "#FF9900",
  },
  {
    name: "Netflix",
    logo: `https://cdn.brandfetch.io/netflix.com/w/400/h/400?c=${BRANDFETCH_CLIENT_ID}`,
    bgColor: "#E50914",
  },
  {
    name: "Apple",
    logo: `https://cdn.brandfetch.io/apple.com/w/400/h/400?c=${BRANDFETCH_CLIENT_ID}`,
    bgColor: "#A2AAAD",
  },
  {
    name: "Facebook",
    logo: `https://cdn.brandfetch.io/facebook.com/w/400/h/400?c=${BRANDFETCH_CLIENT_ID}`,
    bgColor: "#1877F2",
  },
  {
    name: "LinkedIn",
    logo: `https://cdn.brandfetch.io/linkedin.com/w/400/h/400?c=${BRANDFETCH_CLIENT_ID}`,
    bgColor: "#0A66C2",
  },
  {
    name: "Dropbox",
    logo: `https://cdn.brandfetch.io/dropbox.com/w/400/h/400?c=${BRANDFETCH_CLIENT_ID}`,
    bgColor: "#0061FF",
  },
  {
    name: "Chase",
    logo: `https://cdn.brandfetch.io/chase.com/w/400/h/400?c=${BRANDFETCH_CLIENT_ID}`,
    bgColor: "#117ACA",
  },
];

const LogoCarousel: React.FC = () => {
  const [failedLogos, setFailedLogos] = useState<string[]>([]);

  const handleImageError = (companyName: string) => {
    setFailedLogos(prev => [...prev, companyName]);
  };

  return (
    <div className="w-full py-4">
      <p className="text-gray-500 text-xs uppercase tracking-wider mb-6 text-center">
        Protecting users from phishing attacks on
      </p>
      <div className="relative overflow-hidden py-4 logo-carousel-container">
        {/* Gradient fade overlays */}
        <div className="absolute left-0 top-0 bottom-0 w-24 bg-gradient-to-r from-gray-50 via-gray-50/80 to-transparent z-10 pointer-events-none" />
        <div className="absolute right-0 top-0 bottom-0 w-24 bg-gradient-to-l from-gray-50 via-gray-50/80 to-transparent z-10 pointer-events-none" />

        {/* Scrolling container */}
        <div className="flex animate-scroll-logos items-center">
          {/* First set */}
          {companies.map((company, index) => (
            <div
              key={`first-${index}`}
              className="flex-shrink-0 mx-4"
            >
              <div className="h-12 w-12 flex items-center justify-center p-1 hover:scale-110 transition-transform duration-300">
                {!failedLogos.includes(company.name) ? (
                  <img
                    src={company.logo}
                    alt={`${company.name} logo`}
                    className="w-full h-full object-contain opacity-80 hover:opacity-100 transition-all duration-300"
                    onError={() => handleImageError(company.name)}
                    loading="eager"
                    crossOrigin="anonymous"
                  />
                ) : (
                  <span
                    className="font-bold text-xs text-center"
                    style={{ color: company.bgColor }}
                  >
                    {company.name}
                  </span>
                )}
              </div>
            </div>
          ))}

          {/* Duplicate set for seamless loop */}
          {companies.map((company, index) => (
            <div
              key={`second-${index}`}
              className="flex-shrink-0 mx-4"
            >
              <div className="h-12 w-12 flex items-center justify-center p-1 hover:scale-110 transition-transform duration-300">
                {!failedLogos.includes(company.name) ? (
                  <img
                    src={company.logo}
                    alt={`${company.name} logo`}
                    className="w-full h-full object-contain opacity-80 hover:opacity-100 transition-all duration-300"
                    onError={() => handleImageError(company.name)}
                    loading="eager"
                    crossOrigin="anonymous"
                  />
                ) : (
                  <span
                    className="font-bold text-xs text-center"
                    style={{ color: company.bgColor }}
                  >
                    {company.name}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) {
      toast.error('Please enter username and password');
      return;
    }

    setIsLoading(true);
    try {
      await login(username, password);
      toast.success('Welcome back!');
      navigate('/');
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex">
      {/* Left Side - Branding */}
      <div className="hidden lg:flex lg:w-1/2 bg-gray-50 flex-col justify-between p-12">
        {/* Logo */}
        <div className="flex items-center gap-2">
          <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
            <ShieldCheck className="w-6 h-6 text-white" />
          </div>
          <span className="text-xl font-bold text-gray-900">
            PHISHING<span className="text-blue-600">MASTER</span>
          </span>
        </div>

        {/* Hero Text */}
        <div className="flex-1 flex flex-col justify-center">
          <h1 className="text-6xl xl:text-7xl font-bold text-gray-900 leading-tight">
            Detect, Protect
            <br />
            & Secure
          </h1>
          <p className="mt-6 text-xl text-gray-600">
            ML-powered phishing URL detection to keep your organization safe
          </p>
        </div>

        {/* Logo Carousel */}
        <LogoCarousel />
      </div>

      {/* Right Side - Login Form */}
      <div className="w-full lg:w-1/2 bg-white flex items-center justify-center p-8">
        <div className="w-full max-w-md">
          {/* Mobile Logo */}
          <div className="lg:hidden flex items-center justify-center gap-2 mb-8">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <ShieldCheck className="w-6 h-6 text-white" />
            </div>
            <span className="text-xl font-bold text-gray-900">
              PHISHING<span className="text-blue-600">MASTER</span>
            </span>
          </div>

          {/* Login Header */}
          <div className="text-center mb-8">
            <h2 className="text-2xl font-bold text-gray-900">Log in to your Account</h2>
            <p className="text-gray-500 mt-2">Hey Security Pro, Enter your credentials</p>
          </div>

          {/* Login Form */}
          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <div className="relative">
                <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-12 pr-4 py-3 bg-gray-50 border border-gray-200 rounded-lg text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                  placeholder="Enter your Username or Email"
                  disabled={isLoading}
                />
              </div>
            </div>

            <div>
              <div className="relative">
                <ShieldCheck className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-12 pr-4 py-3 bg-gray-50 border border-gray-200 rounded-lg text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                  placeholder="Enter your Password"
                  disabled={isLoading}
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-3 bg-blue-500 hover:bg-blue-600 text-white font-medium rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Signing in...
                </>
              ) : (
                'Log in'
              )}
            </button>
          </form>

          {/* Demo credentials */}
          <div className="mt-8 p-4 bg-gray-50 rounded-xl border border-gray-200 space-y-2">
            <p className="text-gray-500 text-sm text-center font-medium mb-2">Demo Credentials</p>
            <p className="text-gray-600 text-sm text-center">
              Admin: <span className="font-semibold text-gray-900">admin</span> / <span className="font-semibold text-gray-900">admin123</span>
            </p>
            <p className="text-gray-600 text-sm text-center">
              Test: <span className="font-semibold text-gray-900">test</span> / <span className="font-semibold text-gray-900">test123</span>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
