import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  BoltIcon,
  ServerStackIcon,
  DocumentTextIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
} from '@heroicons/react/24/outline';
import { getHealth, getEventTypes, getDestinations } from '../api/client';
import type { HealthResponse, EventType, Destination } from '../types';

export default function Dashboard() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [eventTypes, setEventTypes] = useState<EventType[]>([]);
  const [destinations, setDestinations] = useState<Destination[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [healthData, eventTypesData, destinationsData] = await Promise.all([
          getHealth(),
          getEventTypes(),
          getDestinations(),
        ]);
        setHealth(healthData);
        setEventTypes(eventTypesData.event_types);
        setDestinations(destinationsData.destinations);
      } catch (err) {
        setError('Failed to connect to backend API');
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-8">Dashboard</h1>

      {/* Status Banner */}
      <div
        className={`card mb-8 ${
          error ? 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20' : 'border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900/20'
        }`}
      >
        <div className="flex items-center gap-3">
          {error ? (
            <>
              <ExclamationCircleIcon className="h-6 w-6 text-red-500" />
              <div>
                <h3 className="font-medium text-red-800 dark:text-red-300">API Disconnected</h3>
                <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
              </div>
            </>
          ) : (
            <>
              <CheckCircleIcon className="h-6 w-6 text-green-500" />
              <div>
                <h3 className="font-medium text-green-800 dark:text-green-300">API Connected</h3>
                <p className="text-sm text-green-600 dark:text-green-400">
                  Version {health?.version} | Uptime: {health?.uptime}
                </p>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="card">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-primary-100 dark:bg-primary-900/30 rounded-lg">
              <BoltIcon className="h-6 w-6 text-primary-600 dark:text-primary-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Event Types</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{eventTypes.length}</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-lg">
              <ServerStackIcon className="h-6 w-6 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Destinations</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{destinations.length}</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
              <DocumentTextIcon className="h-6 w-6 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Templates</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                {eventTypes.reduce((acc, t) => acc + (t.event_ids?.length || 1), 0)}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="card mb-8">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Quick Actions</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Link
            to="/generate"
            className="flex items-center gap-3 p-4 border border-gray-200 dark:border-slate-700 rounded-lg hover:border-primary-500 hover:bg-primary-50 dark:hover:bg-primary-900/20 transition-colors"
          >
            <BoltIcon className="h-8 w-8 text-primary-600 dark:text-primary-400" />
            <div>
              <h3 className="font-medium text-gray-900 dark:text-gray-100">Generate Events</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">Create synthetic security events</p>
            </div>
          </Link>

          <Link
            to="/destinations"
            className="flex items-center gap-3 p-4 border border-gray-200 dark:border-slate-700 rounded-lg hover:border-primary-500 hover:bg-primary-50 dark:hover:bg-primary-900/20 transition-colors"
          >
            <ServerStackIcon className="h-8 w-8 text-primary-600 dark:text-primary-400" />
            <div>
              <h3 className="font-medium text-gray-900 dark:text-gray-100">Manage Destinations</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400">Configure output targets</p>
            </div>
          </Link>
        </div>
      </div>

      {/* Available Event Types */}
      <div className="card">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Available Event Types</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {eventTypes.map((eventType) => (
            <div
              key={eventType.id}
              className="p-4 border border-gray-200 dark:border-slate-700 rounded-lg"
            >
              <div className="flex items-center justify-between mb-2">
                <h3 className="font-medium text-gray-900 dark:text-gray-100">{eventType.name}</h3>
                <span className="px-2 py-1 bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-gray-300 text-xs rounded-full">
                  {eventType.category}
                </span>
              </div>
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-2">{eventType.description}</p>
              {eventType.event_ids && (
                <p className="text-xs text-gray-400 dark:text-gray-500">
                  {eventType.event_ids.length} event ID{eventType.event_ids.length !== 1 ? 's' : ''}
                </p>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
