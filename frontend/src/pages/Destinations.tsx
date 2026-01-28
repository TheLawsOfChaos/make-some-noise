import { useEffect, useState } from 'react';
import {
  PlusIcon,
  TrashIcon,
  PencilIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline';
import {
  getDestinations,
  createDestination,
  updateDestination,
  deleteDestination,
  testDestination,
} from '../api/client';
import type { Destination, DestinationType, DestinationConfig } from '../types';

const DESTINATION_TYPES: { value: DestinationType; label: string }[] = [
  { value: 'syslog_udp', label: 'Syslog (UDP)' },
  { value: 'syslog_tcp', label: 'Syslog (TCP)' },
  { value: 'hec', label: 'Splunk HEC' },
  { value: 'file', label: 'File Output' },
];

interface DestinationFormData {
  name: string;
  type: DestinationType;
  description: string;
  config: DestinationConfig;
}

const defaultFormData: DestinationFormData = {
  name: '',
  type: 'file',
  description: '',
  config: {
    file_path: '/tmp/output/siem-events.log',
  },
};

export default function Destinations() {
  const [destinations, setDestinations] = useState<Destination[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formData, setFormData] = useState<DestinationFormData>(defaultFormData);
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; message: string }>>({});
  const [testingId, setTestingId] = useState<string | null>(null);

  const fetchDestinations = async () => {
    try {
      const data = await getDestinations();
      setDestinations(data.destinations);
    } catch (err) {
      console.error('Failed to fetch destinations:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDestinations();
  }, []);

  const handleTest = async (id: string) => {
    setTestingId(id);
    try {
      const result = await testDestination(id);
      setTestResults((prev) => ({
        ...prev,
        [id]: { success: result.success, message: result.message },
      }));
    } catch {
      setTestResults((prev) => ({
        ...prev,
        [id]: { success: false, message: 'Test failed' },
      }));
    } finally {
      setTestingId(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (editingId) {
        await updateDestination(editingId, formData);
      } else {
        await createDestination(formData);
      }
      await fetchDestinations();
      setShowForm(false);
      setEditingId(null);
      setFormData(defaultFormData);
    } catch (err) {
      console.error('Failed to save destination:', err);
    }
  };

  const handleEdit = (dest: Destination) => {
    setFormData({
      name: dest.name,
      type: dest.type,
      description: dest.description || '',
      config: dest.config,
    });
    setEditingId(dest.id);
    setShowForm(true);
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this destination?')) return;
    try {
      await deleteDestination(id);
      await fetchDestinations();
    } catch (err) {
      console.error('Failed to delete destination:', err);
    }
  };

  const updateConfig = (key: keyof DestinationConfig, value: unknown) => {
    setFormData((prev) => ({
      ...prev,
      config: { ...prev.config, [key]: value },
    }));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Destinations</h1>
        <button
          className="btn btn-primary flex items-center gap-2"
          onClick={() => {
            setFormData(defaultFormData);
            setEditingId(null);
            setShowForm(true);
          }}
        >
          <PlusIcon className="h-4 w-4" />
          Add Destination
        </button>
      </div>

      {/* Form Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
            <form onSubmit={handleSubmit}>
              <div className="p-6">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                  {editingId ? 'Edit Destination' : 'New Destination'}
                </h2>

                <div className="space-y-4">
                  <div>
                    <label className="label">Name</label>
                    <input
                      type="text"
                      className="input"
                      value={formData.name}
                      onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
                      required
                    />
                  </div>

                  <div>
                    <label className="label">Type</label>
                    <select
                      className="select"
                      value={formData.type}
                      onChange={(e) =>
                        setFormData((prev) => ({
                          ...prev,
                          type: e.target.value as DestinationType,
                          config: {},
                        }))
                      }
                    >
                      {DESTINATION_TYPES.map((type) => (
                        <option key={type.value} value={type.value}>
                          {type.label}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="label">Description</label>
                    <input
                      type="text"
                      className="input"
                      value={formData.description}
                      onChange={(e) =>
                        setFormData((prev) => ({ ...prev, description: e.target.value }))
                      }
                    />
                  </div>

                  {/* Type-specific config */}
                  {(formData.type === 'syslog_udp' || formData.type === 'syslog_tcp') && (
                    <>
                      <div>
                        <label className="label">Host</label>
                        <input
                          type="text"
                          className="input"
                          value={formData.config.host || ''}
                          onChange={(e) => updateConfig('host', e.target.value)}
                          placeholder="e.g., 192.168.1.100"
                          required
                        />
                      </div>
                      <div>
                        <label className="label">Port</label>
                        <input
                          type="number"
                          className="input"
                          value={formData.config.port || 514}
                          onChange={(e) => updateConfig('port', parseInt(e.target.value))}
                          required
                        />
                      </div>
                      <div>
                        <label className="label">Format</label>
                        <select
                          className="select"
                          value={formData.config.format || 'rfc3164'}
                          onChange={(e) => updateConfig('format', e.target.value)}
                        >
                          <option value="rfc3164">RFC 3164 (BSD)</option>
                          <option value="rfc5424">RFC 5424</option>
                        </select>
                      </div>
                    </>
                  )}

                  {formData.type === 'hec' && (
                    <>
                      <div>
                        <label className="label">HEC URL</label>
                        <input
                          type="url"
                          className="input"
                          value={formData.config.url || ''}
                          onChange={(e) => updateConfig('url', e.target.value)}
                          placeholder="https://splunk:8088/services/collector/event"
                          required
                        />
                      </div>
                      <div>
                        <label className="label">HEC Token</label>
                        <input
                          type="password"
                          className="input"
                          value={formData.config.token || ''}
                          onChange={(e) => updateConfig('token', e.target.value)}
                          required
                        />
                      </div>
                      <div>
                        <label className="label">Index (Optional)</label>
                        <input
                          type="text"
                          className="input"
                          value={formData.config.index || ''}
                          onChange={(e) => updateConfig('index', e.target.value)}
                        />
                      </div>
                      <div className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          id="verify_ssl"
                          checked={formData.config.verify_ssl || false}
                          onChange={(e) => updateConfig('verify_ssl', e.target.checked)}
                        />
                        <label htmlFor="verify_ssl" className="text-sm text-gray-700 dark:text-gray-300">
                          Verify SSL Certificate
                        </label>
                      </div>
                    </>
                  )}

                  {formData.type === 'file' && (
                    <>
                      <div>
                        <label className="label">File Path</label>
                        <input
                          type="text"
                          className="input"
                          value={formData.config.file_path || ''}
                          onChange={(e) => updateConfig('file_path', e.target.value)}
                          placeholder="/var/log/siem-events.log"
                          required
                        />
                      </div>
                      <div>
                        <label className="label">Max Size (MB)</label>
                        <input
                          type="number"
                          className="input"
                          value={formData.config.max_size_mb || 100}
                          onChange={(e) => updateConfig('max_size_mb', parseInt(e.target.value))}
                        />
                      </div>
                    </>
                  )}
                </div>
              </div>

              <div className="px-6 py-4 bg-gray-50 dark:bg-slate-900 flex justify-end gap-3 rounded-b-lg">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => {
                    setShowForm(false);
                    setEditingId(null);
                  }}
                >
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  {editingId ? 'Update' : 'Create'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Destinations List */}
      <div className="grid gap-4">
        {destinations.map((dest) => (
          <div key={dest.id} className="card">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="font-medium text-gray-900 dark:text-gray-100">{dest.name}</h3>
                <p className="text-sm text-gray-500 dark:text-gray-400">{dest.description}</p>
                <div className="flex items-center gap-2 mt-2">
                  <span className="px-2 py-1 bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-gray-300 text-xs rounded-full">
                    {DESTINATION_TYPES.find((t) => t.value === dest.type)?.label}
                  </span>
                  {dest.type === 'file' && (
                    <span className="text-xs text-gray-400 dark:text-gray-500">{dest.config.file_path}</span>
                  )}
                  {(dest.type === 'syslog_udp' || dest.type === 'syslog_tcp') && (
                    <span className="text-xs text-gray-400 dark:text-gray-500">
                      {dest.config.host}:{dest.config.port}
                    </span>
                  )}
                  {dest.type === 'hec' && (
                    <span className="text-xs text-gray-400 dark:text-gray-500">{dest.config.url}</span>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-2">
                {testResults[dest.id] && (
                  <span
                    className={`flex items-center gap-1 text-xs ${
                      testResults[dest.id].success ? 'text-green-600' : 'text-red-600'
                    }`}
                  >
                    {testResults[dest.id].success ? (
                      <CheckCircleIcon className="h-4 w-4" />
                    ) : (
                      <ExclamationCircleIcon className="h-4 w-4" />
                    )}
                    {testResults[dest.id].message}
                  </span>
                )}
                <button
                  className="p-2 text-gray-400 dark:text-gray-500 hover:text-primary-600 dark:hover:text-primary-400"
                  onClick={() => handleTest(dest.id)}
                  disabled={testingId === dest.id}
                  title="Test connection"
                >
                  <ArrowPathIcon
                    className={`h-4 w-4 ${testingId === dest.id ? 'animate-spin' : ''}`}
                  />
                </button>
                <button
                  className="p-2 text-gray-400 dark:text-gray-500 hover:text-primary-600 dark:hover:text-primary-400"
                  onClick={() => handleEdit(dest)}
                  title="Edit"
                >
                  <PencilIcon className="h-4 w-4" />
                </button>
                <button
                  className="p-2 text-gray-400 dark:text-gray-500 hover:text-red-600 dark:hover:text-red-400"
                  onClick={() => handleDelete(dest.id)}
                  title="Delete"
                >
                  <TrashIcon className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>
        ))}

        {destinations.length === 0 && (
          <div className="card text-center text-gray-500 dark:text-gray-400 py-12">
            <p>No destinations configured yet.</p>
            <button
              className="btn btn-primary mt-4"
              onClick={() => {
                setFormData(defaultFormData);
                setShowForm(true);
              }}
            >
              Add Your First Destination
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
