import React, { useState, useEffect } from 'react';
import { Users, Plus, Edit, Trash2, Loader2, Shield, ShieldCheck, ShieldAlert } from 'lucide-react';
import { usersAPI } from '../services/api';
import { formatDate } from '../utils/helpers';
import toast from 'react-hot-toast';

interface User {
  id: number;
  email: string;
  username: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  created_at: string;
  last_login: string | null;
}

const UsersPage: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    setIsLoading(true);
    try {
      const response = await usersAPI.getUsers({});
      setUsers(response.data);
    } catch (error) {
      console.error('Failed to fetch users:', error);
      toast.error('Failed to load users');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this user?')) return;

    try {
      await usersAPI.deleteUser(id);
      toast.success('User deleted');
      fetchUsers();
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to delete user');
    }
  };

  const handleToggleActive = async (user: User) => {
    try {
      await usersAPI.updateUser(user.id, { is_active: !user.is_active });
      toast.success(`User ${user.is_active ? 'deactivated' : 'activated'}`);
      fetchUsers();
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to update user');
    }
  };

  const getRoleIcon = (role: string) => {
    switch (role) {
      case 'admin':
        return <ShieldAlert className="w-4 h-4 text-red-400" />;
      case 'analyst':
        return <ShieldCheck className="w-4 h-4 text-blue-400" />;
      default:
        return <Shield className="w-4 h-4 text-gray-400" />;
    }
  };

  const getRoleBadgeClass = (role: string) => {
    switch (role) {
      case 'admin':
        return 'bg-red-900/50 text-red-400 border-red-800';
      case 'analyst':
        return 'bg-blue-900/50 text-blue-400 border-blue-800';
      default:
        return 'bg-gray-900/50 text-gray-400 border-gray-700';
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">User Management</h1>
          <p className="text-dark-400 mt-1">Manage system users and their roles</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn btn-primary flex items-center gap-2"
        >
          <Plus className="w-4 h-4" />
          Add User
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-blue-500/20 rounded-xl">
              <Users className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <p className="text-dark-400 text-sm">Total Users</p>
              <p className="text-2xl font-bold text-white">{users.length}</p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-green-500/20 rounded-xl">
              <ShieldCheck className="w-6 h-6 text-green-400" />
            </div>
            <div>
              <p className="text-dark-400 text-sm">Active Users</p>
              <p className="text-2xl font-bold text-white">
                {users.filter((u) => u.is_active).length}
              </p>
            </div>
          </div>
        </div>
        <div className="card">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-red-500/20 rounded-xl">
              <ShieldAlert className="w-6 h-6 text-red-400" />
            </div>
            <div>
              <p className="text-dark-400 text-sm">Admins</p>
              <p className="text-2xl font-bold text-white">
                {users.filter((u) => u.role === 'admin').length}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Users Table */}
      <div className="card p-0">
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Status</th>
                <th>Last Login</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700">
              {users.map((user) => (
                <tr key={user.id}>
                  <td>
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center">
                        <span className="text-sm font-bold text-white">
                          {user.username.charAt(0).toUpperCase()}
                        </span>
                      </div>
                      <div>
                        <p className="font-medium text-white">{user.username}</p>
                        <p className="text-dark-400 text-sm">{user.email}</p>
                      </div>
                    </div>
                  </td>
                  <td>
                    <div className="flex items-center gap-2">
                      {getRoleIcon(user.role)}
                      <span
                        className={`px-2 py-1 rounded-full text-xs font-medium border ${getRoleBadgeClass(
                          user.role
                        )}`}
                      >
                        {user.role}
                      </span>
                    </div>
                  </td>
                  <td>
                    <button
                      onClick={() => handleToggleActive(user)}
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
                        user.is_active
                          ? 'bg-green-900/50 text-green-400'
                          : 'bg-red-900/50 text-red-400'
                      }`}
                    >
                      {user.is_active ? 'Active' : 'Inactive'}
                    </button>
                  </td>
                  <td className="text-dark-400">
                    {user.last_login ? formatDate(user.last_login) : 'Never'}
                  </td>
                  <td className="text-dark-400">{formatDate(user.created_at)}</td>
                  <td>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setEditingUser(user)}
                        className="p-1.5 text-dark-400 hover:text-white hover:bg-dark-700 rounded-lg transition-colors"
                        title="Edit"
                      >
                        <Edit className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDelete(user.id)}
                        className="p-1.5 text-dark-400 hover:text-red-400 hover:bg-dark-700 rounded-lg transition-colors"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default UsersPage;
