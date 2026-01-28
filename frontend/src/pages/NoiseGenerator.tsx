import { useEffect, useState, useCallback } from 'react';
import {
  PlayIcon,
  StopIcon,
  SignalIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';
import {
  getEventSources,
  getDestinations,
  getNoiseStatus,
  startNoise,
  stopNoise,
} from '../api/client';
import type {
  EventSourceTree,
  EnabledEventSource,
  Destination,
  NoiseStatus,
} from '../types';
import EventSourceSelector from '../components/NoiseGenerator/EventSourceSelector';
import NoiseStatsPanel from '../components/NoiseGenerator/NoiseStatsPanel';

const RATE_PRESETS = [
  { label: 'Low', value: 1, description: '1 event/sec' },
  { label: 'Medium', value: 10, description: '10 events/sec' },
  { label: 'High', value: 100, description: '100 events/sec' },
  { label: 'Burst', value: 1000, description: '1000 events/sec' },
];

export default function NoiseGenerator() {
  // Data state
  const [eventSources, setEventSources] = useState<EventSourceTree | null>(null);
  const [destinations, setDestinations] = useState<Destination[]>([]);
  const [noiseStatus, setNoiseStatus] = useState<NoiseStatus | null>(null);

  // Configuration state
  const [selectedDestination, setSelectedDestination] = useState<string>('');
  const [ratePerSecond, setRatePerSecond] = useState<number>(10);
  const [enabledSources, setEnabledSources] = useState<
    Record<string, EnabledEventSource>
  >({});

  // UI state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch initial data
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [sourcesData, destinationsData, statusData] = await Promise.all([
          getEventSources(),
          getDestinations(),
          getNoiseStatus(),
        ]);
        setEventSources(sourcesData);
        setDestinations(destinationsData.destinations);
        setNoiseStatus(statusData);

        // Set default destination
        if (destinationsData.destinations.length > 0 && !selectedDestination) {
          setSelectedDestination(destinationsData.destinations[0].id);
        }

        // Initialize enabled sources from current config if running
        if (statusData.running && statusData.current_config) {
          const sources: Record<string, EnabledEventSource> = {};
          statusData.current_config.enabled_sources.forEach((s) => {
            sources[s.event_type_id] = s;
          });
          setEnabledSources(sources);
          setRatePerSecond(statusData.current_config.rate_per_second);
          if (statusData.current_config.destination_id) {
            setSelectedDestination(statusData.current_config.destination_id);
          }
        }
      } catch (err) {
        console.error('Failed to fetch data:', err);
        setError('Failed to load data. Please try refreshing the page.');
      }
    };

    fetchData();
  }, []);

  // Poll for status updates when running
  useEffect(() => {
    if (noiseStatus?.running) {
      const interval = setInterval(async () => {
        try {
          const status = await getNoiseStatus();
          setNoiseStatus(status);
        } catch (err) {
          console.error('Failed to fetch status:', err);
        }
      }, 1000);
      return () => clearInterval(interval);
    }
  }, [noiseStatus?.running]);

  const handleToggleEventType = useCallback(
    (eventTypeId: string, enabled: boolean) => {
      setEnabledSources((prev) => {
        if (enabled) {
          return {
            ...prev,
            [eventTypeId]: {
              event_type_id: eventTypeId,
              enabled: true,
              weight: prev[eventTypeId]?.weight || 10,
              template_ids: prev[eventTypeId]?.template_ids,
              destination_id: prev[eventTypeId]?.destination_id,
            },
          };
        } else {
          const { [eventTypeId]: _, ...rest } = prev;
          return {
            ...rest,
            [eventTypeId]: {
              event_type_id: eventTypeId,
              enabled: false,
              weight: prev[eventTypeId]?.weight || 10,
              template_ids: prev[eventTypeId]?.template_ids,
              destination_id: prev[eventTypeId]?.destination_id,
            },
          };
        }
      });
    },
    []
  );

  const handleToggleTemplate = useCallback(
    (eventTypeId: string, templateId: string, enabled: boolean) => {
      setEnabledSources((prev) => {
        const source = prev[eventTypeId];
        if (!source) return prev;

        // Get all templates for this event type
        const eventTypeInfo = Object.values(eventSources?.categories || {})
          .flat()
          .find((s) => s.event_type.id === eventTypeId);

        if (!eventTypeInfo) return prev;

        const allTemplateIds = eventTypeInfo.templates.map((t) => t.id);
        let currentTemplateIds = source.template_ids || [];

        // If empty, it means all were selected - initialize with all
        if (currentTemplateIds.length === 0) {
          currentTemplateIds = [...allTemplateIds];
        }

        let newTemplateIds: string[];
        if (enabled) {
          newTemplateIds = [...new Set([...currentTemplateIds, templateId])];
        } else {
          newTemplateIds = currentTemplateIds.filter((id) => id !== templateId);
        }

        // If all templates are selected, clear the array (means "all")
        if (newTemplateIds.length === allTemplateIds.length) {
          newTemplateIds = [];
        }

        return {
          ...prev,
          [eventTypeId]: {
            ...source,
            template_ids: newTemplateIds,
          },
        };
      });
    },
    [eventSources]
  );

  const handleWeightChange = useCallback((eventTypeId: string, weight: number) => {
    setEnabledSources((prev) => ({
      ...prev,
      [eventTypeId]: {
        ...prev[eventTypeId],
        event_type_id: eventTypeId,
        weight,
        enabled: prev[eventTypeId]?.enabled || false,
      },
    }));
  }, []);

  const handleDestinationChange = useCallback(
    (eventTypeId: string, destinationId: string) => {
      setEnabledSources((prev) => ({
        ...prev,
        [eventTypeId]: {
          ...prev[eventTypeId],
          event_type_id: eventTypeId,
          destination_id: destinationId || undefined,
          enabled: prev[eventTypeId]?.enabled || false,
          weight: prev[eventTypeId]?.weight || 10,
        },
      }));
    },
    []
  );

  const handleStart = async () => {
    setError(null);
    setLoading(true);

    try {
      const enabledSourcesList = Object.values(enabledSources).filter(
        (s) => s.enabled
      );

      if (enabledSourcesList.length === 0) {
        setError('Please enable at least one event source.');
        setLoading(false);
        return;
      }

      // Check if we have valid destinations configured
      // Either global destination OR all enabled sources have per-source destinations
      const sourcesWithoutDestination = enabledSourcesList.filter(
        (s) => !s.destination_id && !selectedDestination
      );

      if (sourcesWithoutDestination.length > 0) {
        setError(
          'Please set a global destination or configure a destination for each event source.'
        );
        setLoading(false);
        return;
      }

      const response = await startNoise({
        destination_id: selectedDestination || undefined,
        rate_per_second: ratePerSecond,
        enabled_sources: enabledSourcesList,
      });

      setNoiseStatus(response.status);
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to start noise generation';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    setError(null);
    setLoading(true);

    try {
      const response = await stopNoise();
      setNoiseStatus(response.status);
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to stop noise generation';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const enabledCount = Object.values(enabledSources).filter((s) => s.enabled).length;
  const isRunning = noiseStatus?.running || false;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <SignalIcon className="h-7 w-7" />
          Noise Generator
        </h1>
        <p className="text-gray-600 mt-1">
          Continuously generate a mix of security events to feed your SIEM.
        </p>
      </div>

      {/* Status Banner */}
      {isRunning && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="h-3 w-3 bg-green-500 rounded-full animate-pulse"></div>
              <div className="absolute inset-0 h-3 w-3 bg-green-500 rounded-full animate-ping"></div>
            </div>
            <div>
              <p className="font-medium text-green-800">Noise generation is running</p>
              <p className="text-sm text-green-600">
                Generating ~{noiseStatus?.stats.events_per_second.toFixed(1)} events/second
              </p>
            </div>
          </div>
          <button
            onClick={handleStop}
            disabled={loading}
            className="btn bg-red-600 hover:bg-red-700 text-white flex items-center gap-2"
          >
            <StopIcon className="h-5 w-5" />
            Stop
          </button>
        </div>
      )}

      {/* Error Banner */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-center gap-3">
          <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />
          <p className="text-red-700">{error}</p>
        </div>
      )}

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Event Source Toggles */}
        <div className="lg:col-span-2">
          <EventSourceSelector
            eventSources={eventSources}
            enabledSources={enabledSources}
            destinations={destinations}
            globalDestinationId={selectedDestination}
            onToggleEventType={handleToggleEventType}
            onToggleTemplate={handleToggleTemplate}
            onWeightChange={handleWeightChange}
            onDestinationChange={handleDestinationChange}
            disabled={isRunning}
          />
        </div>

        {/* Right: Controls and Stats */}
        <div className="space-y-6">
          {/* Configuration Panel */}
          <div className="card">
            <h3 className="font-semibold mb-4">Configuration</h3>

            {/* Destination */}
            <div className="mb-4">
              <label className="label">Default Destination</label>
              <p className="text-xs text-gray-500 mb-2">
                Fallback for sources without a specific destination
              </p>
              <select
                value={selectedDestination}
                onChange={(e) => setSelectedDestination(e.target.value)}
                disabled={isRunning}
                className="select w-full"
              >
                <option value="">No default (use per-source)</option>
                {destinations.map((dest) => (
                  <option key={dest.id} value={dest.id}>
                    {dest.name} ({dest.type})
                  </option>
                ))}
              </select>
            </div>

            {/* Rate */}
            <div className="mb-4">
              <label className="label">Rate (events/second)</label>
              <div className="flex gap-2 mb-2">
                {RATE_PRESETS.map((preset) => (
                  <button
                    key={preset.value}
                    onClick={() => setRatePerSecond(preset.value)}
                    disabled={isRunning}
                    className={`px-3 py-1 text-sm rounded ${
                      ratePerSecond === preset.value
                        ? 'bg-primary-600 text-white'
                        : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                    } disabled:opacity-50`}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
              <input
                type="number"
                min="0.1"
                max="10000"
                step="0.1"
                value={ratePerSecond}
                onChange={(e) => setRatePerSecond(parseFloat(e.target.value) || 1)}
                disabled={isRunning}
                className="input w-full"
              />
            </div>

            {/* Summary */}
            <div className="bg-gray-50 rounded-lg p-3 mb-4">
              <p className="text-sm text-gray-600">
                <span className="font-medium">{enabledCount}</span> event type
                {enabledCount !== 1 ? 's' : ''} selected
              </p>
            </div>

            {/* Start Button */}
            {!isRunning && (
              <button
                onClick={handleStart}
                disabled={loading || enabledCount === 0}
                className="btn btn-primary w-full flex items-center justify-center gap-2"
              >
                {loading ? (
                  <div className="h-5 w-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                ) : (
                  <PlayIcon className="h-5 w-5" />
                )}
                Start Noise Generation
              </button>
            )}
          </div>

          {/* Stats Panel (only when running or has data) */}
          {noiseStatus && (noiseStatus.running || noiseStatus.stats.total_generated > 0) && (
            <NoiseStatsPanel stats={noiseStatus.stats} />
          )}
        </div>
      </div>
    </div>
  );
}
