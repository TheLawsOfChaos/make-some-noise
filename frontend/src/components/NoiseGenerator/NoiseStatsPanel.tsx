import {
  ChartBarIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  PaperAirplaneIcon,
} from '@heroicons/react/24/outline';
import type { NoiseStats } from '../../types';

interface Props {
  stats: NoiseStats;
}

function formatDuration(seconds: number): string {
  if (seconds < 60) {
    return `${seconds}s`;
  } else if (seconds < 3600) {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs}s`;
  } else {
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${mins}m`;
  }
}

function formatNumber(num: number): string {
  if (num >= 1000000) {
    return `${(num / 1000000).toFixed(1)}M`;
  } else if (num >= 1000) {
    return `${(num / 1000).toFixed(1)}K`;
  }
  return num.toLocaleString();
}

interface StatCardProps {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  variant?: 'default' | 'error' | 'success';
}

function StatCard({ label, value, icon, variant = 'default' }: StatCardProps) {
  const variantClasses = {
    default: 'bg-white',
    error: 'bg-red-50',
    success: 'bg-green-50',
  };

  const iconClasses = {
    default: 'text-gray-400',
    error: 'text-red-500',
    success: 'text-green-500',
  };

  return (
    <div className={`rounded-lg p-3 ${variantClasses[variant]}`}>
      <div className="flex items-center gap-2">
        <div className={`h-5 w-5 ${iconClasses[variant]}`}>{icon}</div>
        <span className="text-xs text-gray-500">{label}</span>
      </div>
      <div className="mt-1 text-xl font-semibold">{value}</div>
    </div>
  );
}

export default function NoiseStatsPanel({ stats }: Props) {
  const sortedEventTypes = Object.entries(stats.by_event_type)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10);

  const maxCount = sortedEventTypes.length > 0 ? sortedEventTypes[0][1] : 1;

  return (
    <div className="card bg-gray-50">
      <h3 className="font-semibold mb-4">Generation Statistics</h3>

      {/* Primary Stats */}
      <div className="grid grid-cols-2 gap-3 mb-4">
        <StatCard
          label="Events/sec"
          value={stats.events_per_second.toFixed(1)}
          icon={<ChartBarIcon />}
        />
        <StatCard
          label="Total Sent"
          value={formatNumber(stats.total_sent)}
          icon={<PaperAirplaneIcon />}
          variant="success"
        />
        <StatCard
          label="Duration"
          value={formatDuration(stats.duration_seconds)}
          icon={<ClockIcon />}
        />
        <StatCard
          label="Errors"
          value={formatNumber(stats.total_errors)}
          icon={<ExclamationTriangleIcon />}
          variant={stats.total_errors > 0 ? 'error' : 'default'}
        />
      </div>

      {/* Breakdown by Event Type */}
      {sortedEventTypes.length > 0 && (
        <div className="mt-4">
          <h4 className="text-sm font-medium text-gray-600 mb-2">By Event Type</h4>
          <div className="space-y-2">
            {sortedEventTypes.map(([type, count]) => (
              <div key={type}>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-600 truncate">{type}</span>
                  <span className="font-medium">{formatNumber(count)}</span>
                </div>
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary-500 rounded-full transition-all duration-300"
                    style={{ width: `${(count / maxCount) * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Error Samples */}
      {stats.error_samples && stats.error_samples.length > 0 && (
        <div className="mt-4">
          <h4 className="text-sm font-medium text-red-600 mb-2">Recent Errors</h4>
          <div className="space-y-1">
            {stats.error_samples.map((error, idx) => (
              <p key={idx} className="text-xs text-red-500 truncate">
                {error}
              </p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
