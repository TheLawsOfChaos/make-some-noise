import { useEffect, useState } from 'react';
import {
  BoltIcon,
  EyeIcon,
  PaperAirplaneIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
} from '@heroicons/react/24/outline';
import {
  getEventTypes,
  getEventTypeSchema,
  getDestinations,
  generateEvents,
  previewEvent,
} from '../api/client';
import type { EventType, EventTemplate, Destination, GeneratedEvent, GenerateResponse } from '../types';

export default function Generate() {
  const [eventTypes, setEventTypes] = useState<EventType[]>([]);
  const [templates, setTemplates] = useState<EventTemplate[]>([]);
  const [destinations, setDestinations] = useState<Destination[]>([]);

  const [selectedType, setSelectedType] = useState<string>('');
  const [selectedTemplate, setSelectedTemplate] = useState<string>('');
  const [selectedDestination, setSelectedDestination] = useState<string>('');
  const [count, setCount] = useState<number>(10);

  const [preview, setPreview] = useState<GeneratedEvent | null>(null);
  const [result, setResult] = useState<GenerateResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [previewLoading, setPreviewLoading] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [eventTypesData, destinationsData] = await Promise.all([
          getEventTypes(),
          getDestinations(),
        ]);
        setEventTypes(eventTypesData.event_types);
        setDestinations(destinationsData.destinations);
      } catch (err) {
        console.error('Failed to fetch data:', err);
      }
    };

    fetchData();
  }, []);

  useEffect(() => {
    if (selectedType) {
      getEventTypeSchema(selectedType).then((data) => {
        setTemplates(data.templates);
        if (data.templates.length > 0) {
          setSelectedTemplate(data.templates[0].id);
        }
      });
    } else {
      setTemplates([]);
      setSelectedTemplate('');
    }
    setPreview(null);
    setResult(null);
  }, [selectedType]);

  const handlePreview = async () => {
    if (!selectedType) return;

    setPreviewLoading(true);
    try {
      const event = await previewEvent(selectedType, selectedTemplate);
      setPreview(event);
    } catch (err) {
      console.error('Preview failed:', err);
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleGenerate = async () => {
    if (!selectedType) return;

    setLoading(true);
    setResult(null);
    try {
      const response = await generateEvents({
        event_type: selectedType,
        event_id: selectedTemplate,
        count,
        destination_id: selectedDestination || undefined,
      });
      setResult(response);
    } catch (err) {
      console.error('Generation failed:', err);
      setResult({
        success: false,
        events_created: 0,
        events_sent: 0,
        errors: ['Failed to generate events'],
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900 mb-8">Generate Events</h1>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Configuration Panel */}
        <div className="space-y-6">
          <div className="card">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Event Configuration</h2>

            {/* Event Type */}
            <div className="mb-4">
              <label className="label">Event Type</label>
              <select
                className="select"
                value={selectedType}
                onChange={(e) => setSelectedType(e.target.value)}
              >
                <option value="">Select an event type...</option>
                {eventTypes.map((type) => (
                  <option key={type.id} value={type.id}>
                    {type.name} ({type.category})
                  </option>
                ))}
              </select>
            </div>

            {/* Template */}
            {templates.length > 0 && (
              <div className="mb-4">
                <label className="label">Event Template</label>
                <select
                  className="select"
                  value={selectedTemplate}
                  onChange={(e) => setSelectedTemplate(e.target.value)}
                >
                  {templates.map((template) => (
                    <option key={template.id} value={template.id}>
                      {template.name} (ID: {template.event_id || template.id})
                    </option>
                  ))}
                </select>
                {templates.find((t) => t.id === selectedTemplate)?.description && (
                  <p className="text-sm text-gray-500 mt-1">
                    {templates.find((t) => t.id === selectedTemplate)?.description}
                  </p>
                )}
              </div>
            )}

            {/* Count */}
            <div className="mb-4">
              <label className="label">Number of Events</label>
              <input
                type="number"
                className="input"
                min={1}
                max={10000}
                value={count}
                onChange={(e) => setCount(parseInt(e.target.value) || 1)}
              />
            </div>

            {/* Destination */}
            <div className="mb-6">
              <label className="label">Destination (Optional)</label>
              <select
                className="select"
                value={selectedDestination}
                onChange={(e) => setSelectedDestination(e.target.value)}
              >
                <option value="">Preview only (no delivery)</option>
                {destinations.map((dest) => (
                  <option key={dest.id} value={dest.id}>
                    {dest.name} ({dest.type})
                  </option>
                ))}
              </select>
            </div>

            {/* Action Buttons */}
            <div className="flex gap-3">
              <button
                className="btn btn-secondary flex items-center gap-2"
                onClick={handlePreview}
                disabled={!selectedType || previewLoading}
              >
                <EyeIcon className="h-4 w-4" />
                {previewLoading ? 'Loading...' : 'Preview'}
              </button>
              <button
                className="btn btn-primary flex items-center gap-2"
                onClick={handleGenerate}
                disabled={!selectedType || loading}
              >
                {selectedDestination ? (
                  <>
                    <PaperAirplaneIcon className="h-4 w-4" />
                    {loading ? 'Sending...' : `Generate & Send ${count}`}
                  </>
                ) : (
                  <>
                    <BoltIcon className="h-4 w-4" />
                    {loading ? 'Generating...' : `Generate ${count}`}
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Result */}
          {result && (
            <div
              className={`card ${
                result.success
                  ? 'border-green-200 bg-green-50'
                  : 'border-red-200 bg-red-50'
              }`}
            >
              <div className="flex items-start gap-3">
                {result.success ? (
                  <CheckCircleIcon className="h-6 w-6 text-green-500 flex-shrink-0" />
                ) : (
                  <ExclamationCircleIcon className="h-6 w-6 text-red-500 flex-shrink-0" />
                )}
                <div>
                  <h3
                    className={`font-medium ${
                      result.success ? 'text-green-800' : 'text-red-800'
                    }`}
                  >
                    {result.success ? 'Generation Complete' : 'Generation Failed'}
                  </h3>
                  <p
                    className={`text-sm ${
                      result.success ? 'text-green-600' : 'text-red-600'
                    }`}
                  >
                    Created: {result.events_created} events
                    {result.events_sent > 0 && ` | Sent: ${result.events_sent}`}
                    {result.destination && ` to ${result.destination}`}
                  </p>
                  {result.errors && result.errors.length > 0 && (
                    <ul className="mt-2 text-sm text-red-600">
                      {result.errors.map((err, i) => (
                        <li key={i}>{err}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Preview Panel */}
        <div className="card">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Event Preview</h2>
          {preview ? (
            <div>
              <div className="flex items-center gap-2 mb-4">
                <span className="px-2 py-1 bg-primary-100 text-primary-700 text-xs rounded-full">
                  {preview.type}
                </span>
                {preview.event_id && (
                  <span className="px-2 py-1 bg-gray-100 text-gray-600 text-xs rounded-full">
                    ID: {preview.event_id}
                  </span>
                )}
                <span className="px-2 py-1 bg-gray-100 text-gray-600 text-xs rounded-full">
                  {preview.sourcetype}
                </span>
              </div>
              <pre className="code-preview whitespace-pre-wrap break-all">
                {preview.raw_event}
              </pre>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-64 text-gray-400">
              <EyeIcon className="h-12 w-12 mb-4" />
              <p>Select an event type and click Preview</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
