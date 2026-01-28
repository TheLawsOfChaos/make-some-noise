import axios from 'axios';
import type {
  EventType,
  EventTemplate,
  GeneratedEvent,
  GenerateRequest,
  GenerateResponse,
  Destination,
  TestConnectionResponse,
  HealthResponse,
  DestinationType,
  DestinationConfig,
  NoiseStartRequest,
  NoiseUpdateRequest,
  NoiseStatus,
  NoiseStats,
  EventSourceTree,
} from '../types';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Health
export const getHealth = async (): Promise<HealthResponse> => {
  const response = await api.get('/health');
  return response.data;
};

// Event Types
export const getEventTypes = async (): Promise<{ event_types: EventType[]; count: number }> => {
  const response = await api.get('/event-types');
  return response.data;
};

export const getEventTypeSchema = async (
  type: string
): Promise<{ event_type: EventType; templates: EventTemplate[] }> => {
  const response = await api.get(`/event-types/${type}/schema`);
  return response.data;
};

// Event Generation
export const generateEvents = async (request: GenerateRequest): Promise<GenerateResponse> => {
  const response = await api.post('/generate', request);
  return response.data;
};

export const previewEvent = async (
  eventType: string,
  eventId?: string,
  overrides?: Record<string, unknown>
): Promise<GeneratedEvent> => {
  const response = await api.post('/generate/preview', {
    event_type: eventType,
    event_id: eventId,
    overrides,
  });
  return response.data;
};

// Destinations
export const getDestinations = async (): Promise<{ destinations: Destination[]; count: number }> => {
  const response = await api.get('/destinations');
  return response.data;
};

export const getDestination = async (id: string): Promise<Destination> => {
  const response = await api.get(`/destinations/${id}`);
  return response.data;
};

export const createDestination = async (
  destination: Omit<Destination, 'id' | 'created_at' | 'updated_at' | 'events_sent'>
): Promise<Destination> => {
  const response = await api.post('/destinations', destination);
  return response.data;
};

export const updateDestination = async (
  id: string,
  destination: Partial<Destination>
): Promise<Destination> => {
  const response = await api.put(`/destinations/${id}`, destination);
  return response.data;
};

export const deleteDestination = async (id: string): Promise<void> => {
  await api.delete(`/destinations/${id}`);
};

export const testDestination = async (id: string): Promise<TestConnectionResponse> => {
  const response = await api.post(`/destinations/${id}/test`);
  return response.data;
};

export const testDestinationConfig = async (
  type: DestinationType,
  config: DestinationConfig
): Promise<TestConnectionResponse> => {
  const response = await api.post('/destinations/test', { type, config });
  return response.data;
};

// Templates
export const getTemplates = async (
  category?: string
): Promise<{ templates: EventTemplate[]; count: number }> => {
  const params = category ? { category } : {};
  const response = await api.get('/templates', { params });
  return response.data;
};

export const getTemplate = async (id: string): Promise<EventTemplate> => {
  const response = await api.get(`/templates/${id}`);
  return response.data;
};

export const createTemplate = async (
  template: Omit<EventTemplate, 'id' | 'source'>
): Promise<EventTemplate> => {
  const response = await api.post('/templates', template);
  return response.data;
};

export const updateTemplate = async (
  id: string,
  template: Partial<EventTemplate>
): Promise<EventTemplate> => {
  const response = await api.put(`/templates/${id}`, template);
  return response.data;
};

export const deleteTemplate = async (id: string): Promise<void> => {
  await api.delete(`/templates/${id}`);
};

// Event Sources (for Noise Generator)
export const getEventSources = async (): Promise<EventSourceTree> => {
  const response = await api.get('/event-sources');
  return response.data;
};

// Noise Generation
export const startNoise = async (
  request: NoiseStartRequest
): Promise<{ success: boolean; message: string; status: NoiseStatus }> => {
  const response = await api.post('/noise/start', request);
  return response.data;
};

export const stopNoise = async (): Promise<{ success: boolean; message: string; status: NoiseStatus }> => {
  const response = await api.post('/noise/stop');
  return response.data;
};

export const getNoiseStatus = async (): Promise<NoiseStatus> => {
  const response = await api.get('/noise/status');
  return response.data;
};

export const updateNoiseConfig = async (
  request: NoiseUpdateRequest
): Promise<{ success: boolean; status: NoiseStatus }> => {
  const response = await api.put('/noise/config', request);
  return response.data;
};

export const getNoiseStats = async (): Promise<NoiseStats> => {
  const response = await api.get('/noise/stats');
  return response.data;
};

export default api;
