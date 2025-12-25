import React, { useState } from 'react';
import { Settings, Shield, Bell, Database, Key, Save, Loader2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { authAPI } from '../services/api';
import toast from 'react-hot-toast';

const SettingsPage: React.FC = () => {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('profile');
  const [isLoading, setIsLoading] = useState(false);
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });

  const tabs = [
    { id: 'profile', label: 'Profile', icon: Settings },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'detection', label: 'Detection', icon: Database },
  ];

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();

    if (passwordData.newPassword !== passwordData.confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }

    if (passwordData.newPassword.length < 8) {
      toast.error('Password must be at least 8 characters');
      return;
    }

    setIsLoading(true);
    try {
      await authAPI.changePassword(passwordData.currentPassword, passwordData.newPassword);
      toast.success('Password changed successfully');
      setPasswordData({ currentPassword: '', newPassword: '', confirmPassword: '' });
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to change password');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-dark-400 mt-1">Manage your account and application settings</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Sidebar */}
        <div className="lg:col-span-1">
          <div className="card p-2">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                  activeTab === tab.id
                    ? 'bg-blue-600/20 text-blue-400'
                    : 'text-dark-300 hover:bg-dark-700 hover:text-white'
                }`}
              >
                <tab.icon className="w-5 h-5" />
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="lg:col-span-3">
          {activeTab === 'profile' && (
            <div className="card">
              <h2 className="text-lg font-semibold text-white mb-6">Profile Settings</h2>
              <div className="space-y-4">
                <div>
                  <label className="label">Username</label>
                  <input
                    type="text"
                    value={user?.username || ''}
                    disabled
                    className="input opacity-60"
                  />
                </div>
                <div>
                  <label className="label">Email</label>
                  <input
                    type="email"
                    value={user?.email || ''}
                    disabled
                    className="input opacity-60"
                  />
                </div>
                <div>
                  <label className="label">Full Name</label>
                  <input
                    type="text"
                    defaultValue={user?.full_name || ''}
                    className="input"
                  />
                </div>
                <div>
                  <label className="label">Role</label>
                  <input
                    type="text"
                    value={user?.role || ''}
                    disabled
                    className="input opacity-60 capitalize"
                  />
                </div>
                <button className="btn btn-primary flex items-center gap-2">
                  <Save className="w-4 h-4" />
                  Save Changes
                </button>
              </div>
            </div>
          )}

          {activeTab === 'security' && (
            <div className="space-y-6">
              <div className="card">
                <div className="flex items-center gap-3 mb-6">
                  <Key className="w-5 h-5 text-dark-400" />
                  <h2 className="text-lg font-semibold text-white">Change Password</h2>
                </div>
                <form onSubmit={handlePasswordChange} className="space-y-4">
                  <div>
                    <label className="label">Current Password</label>
                    <input
                      type="password"
                      value={passwordData.currentPassword}
                      onChange={(e) =>
                        setPasswordData({ ...passwordData, currentPassword: e.target.value })
                      }
                      className="input"
                      required
                    />
                  </div>
                  <div>
                    <label className="label">New Password</label>
                    <input
                      type="password"
                      value={passwordData.newPassword}
                      onChange={(e) =>
                        setPasswordData({ ...passwordData, newPassword: e.target.value })
                      }
                      className="input"
                      required
                    />
                  </div>
                  <div>
                    <label className="label">Confirm New Password</label>
                    <input
                      type="password"
                      value={passwordData.confirmPassword}
                      onChange={(e) =>
                        setPasswordData({ ...passwordData, confirmPassword: e.target.value })
                      }
                      className="input"
                      required
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={isLoading}
                    className="btn btn-primary flex items-center gap-2"
                  >
                    {isLoading ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Changing...
                      </>
                    ) : (
                      <>
                        <Key className="w-4 h-4" />
                        Change Password
                      </>
                    )}
                  </button>
                </form>
              </div>

              <div className="card">
                <h2 className="text-lg font-semibold text-white mb-4">Session Information</h2>
                <div className="space-y-3">
                  <div className="flex justify-between py-2 border-b border-dark-700">
                    <span className="text-dark-400">Last Login</span>
                    <span className="text-white">Today at 10:30 AM</span>
                  </div>
                  <div className="flex justify-between py-2 border-b border-dark-700">
                    <span className="text-dark-400">IP Address</span>
                    <span className="text-white">192.168.1.100</span>
                  </div>
                  <div className="flex justify-between py-2">
                    <span className="text-dark-400">Browser</span>
                    <span className="text-white">Chrome on macOS</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'notifications' && (
            <div className="card">
              <h2 className="text-lg font-semibold text-white mb-6">Notification Preferences</h2>
              <div className="space-y-4">
                {[
                  { label: 'Critical Alerts', description: 'Get notified for critical severity threats' },
                  { label: 'High Alerts', description: 'Get notified for high severity threats' },
                  { label: 'Email Notifications', description: 'Receive alerts via email' },
                  { label: 'Daily Summary', description: 'Receive daily threat summary' },
                  { label: 'Weekly Report', description: 'Receive weekly security report' },
                ].map((item, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between py-3 border-b border-dark-700 last:border-0"
                  >
                    <div>
                      <p className="text-white font-medium">{item.label}</p>
                      <p className="text-dark-400 text-sm">{item.description}</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input type="checkbox" className="sr-only peer" defaultChecked={index < 2} />
                      <div className="w-11 h-6 bg-dark-600 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                    </label>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'detection' && (
            <div className="card">
              <h2 className="text-lg font-semibold text-white mb-6">Detection Settings</h2>
              <div className="space-y-6">
                <div>
                  <label className="label">ML Detection Threshold</label>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    defaultValue="50"
                    className="w-full"
                  />
                  <div className="flex justify-between text-sm text-dark-400 mt-1">
                    <span>Less Strict (0%)</span>
                    <span>More Strict (100%)</span>
                  </div>
                </div>

                <div>
                  <label className="label">Auto-Block High Severity</label>
                  <p className="text-dark-400 text-sm mb-2">
                    Automatically block URLs detected as high or critical severity
                  </p>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input type="checkbox" className="sr-only peer" defaultChecked />
                    <div className="w-11 h-6 bg-dark-600 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                  </label>
                </div>

                <div>
                  <label className="label">Update Threat Intelligence</label>
                  <p className="text-dark-400 text-sm mb-2">
                    Sync threat intelligence from external sources
                  </p>
                  <button className="btn btn-secondary">
                    <Database className="w-4 h-4 mr-2" />
                    Sync Now
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SettingsPage;
