import { format, formatDistanceToNow } from 'date-fns';

export const formatDate = (date: string | Date) => {
  return format(new Date(date), 'MMM dd, yyyy HH:mm');
};

export const formatDateShort = (date: string | Date) => {
  return format(new Date(date), 'MMM dd, HH:mm');
};

export const formatRelativeTime = (date: string | Date) => {
  return formatDistanceToNow(new Date(date), { addSuffix: true });
};

export const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

export const formatNumber = (num: number) => {
  if (num >= 1000000) {
    return `${(num / 1000000).toFixed(1)}M`;
  }
  if (num >= 1000) {
    return `${(num / 1000).toFixed(1)}K`;
  }
  return num.toString();
};

export const getSeverityColor = (severity: string) => {
  const colors: Record<string, string> = {
    critical: 'text-red-500',
    high: 'text-orange-500',
    medium: 'text-yellow-500',
    low: 'text-green-500',
    info: 'text-blue-500',
  };
  return colors[severity] || 'text-gray-500';
};

export const getSeverityBgColor = (severity: string) => {
  const colors: Record<string, string> = {
    critical: 'bg-red-500/20',
    high: 'bg-orange-500/20',
    medium: 'bg-yellow-500/20',
    low: 'bg-green-500/20',
    info: 'bg-blue-500/20',
  };
  return colors[severity] || 'bg-gray-500/20';
};

export const getSeverityBadgeClass = (severity: string) => {
  const classes: Record<string, string> = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info',
  };
  return classes[severity] || 'badge-info';
};

export const truncateUrl = (url: string, maxLength: number = 50) => {
  if (url.length <= maxLength) return url;
  return `${url.substring(0, maxLength)}...`;
};

export const extractDomain = (url: string) => {
  try {
    const urlObj = new URL(url.startsWith('http') ? url : `http://${url}`);
    return urlObj.hostname;
  } catch {
    return url;
  }
};

export const getConfidenceLevel = (score: number) => {
  if (score >= 0.8) return { label: 'Very High', color: 'text-red-500' };
  if (score >= 0.6) return { label: 'High', color: 'text-orange-500' };
  if (score >= 0.4) return { label: 'Medium', color: 'text-yellow-500' };
  if (score >= 0.2) return { label: 'Low', color: 'text-green-500' };
  return { label: 'Very Low', color: 'text-blue-500' };
};

export const classNames = (...classes: (string | boolean | undefined)[]) => {
  return classes.filter(Boolean).join(' ');
};
