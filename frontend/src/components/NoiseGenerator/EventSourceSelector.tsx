import { useState } from 'react';
import { ChevronDownIcon, ChevronRightIcon } from '@heroicons/react/24/outline';
import type { EventSourceTree, EnabledEventSource, EventTemplate, Destination } from '../../types';

interface Props {
  eventSources: EventSourceTree | null;
  enabledSources: Record<string, EnabledEventSource>;
  destinations: Destination[];
  globalDestinationId?: string;
  onToggleEventType: (eventTypeId: string, enabled: boolean) => void;
  onToggleTemplate: (eventTypeId: string, templateId: string, enabled: boolean) => void;
  onWeightChange: (eventTypeId: string, weight: number) => void;
  onDestinationChange: (eventTypeId: string, destinationId: string) => void;
  disabled?: boolean;
}

export default function EventSourceSelector({
  eventSources,
  enabledSources,
  destinations,
  globalDestinationId,
  onToggleEventType,
  onToggleTemplate,
  onWeightChange,
  onDestinationChange,
  disabled = false,
}: Props) {
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set());
  const [expandedEventTypes, setExpandedEventTypes] = useState<Set<string>>(new Set());

  const toggleCategory = (category: string) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(category)) {
        next.delete(category);
      } else {
        next.add(category);
      }
      return next;
    });
  };

  const toggleEventTypeExpand = (eventTypeId: string) => {
    setExpandedEventTypes((prev) => {
      const next = new Set(prev);
      if (next.has(eventTypeId)) {
        next.delete(eventTypeId);
      } else {
        next.add(eventTypeId);
      }
      return next;
    });
  };

  const toggleAllInCategory = (category: string) => {
    const sources = eventSources?.categories[category] || [];
    const allEnabled = sources.every(
      (s) => enabledSources[s.event_type.id]?.enabled
    );

    sources.forEach((source) => {
      onToggleEventType(source.event_type.id, !allEnabled);
    });
  };

  const getCategoryState = (category: string): 'all' | 'none' | 'some' => {
    const sources = eventSources?.categories[category] || [];
    if (sources.length === 0) return 'none';

    const enabledCount = sources.filter(
      (s) => enabledSources[s.event_type.id]?.enabled
    ).length;

    if (enabledCount === 0) return 'none';
    if (enabledCount === sources.length) return 'all';
    return 'some';
  };

  const getEventTypeState = (
    eventTypeId: string,
    templates: EventTemplate[]
  ): 'all' | 'none' | 'some' => {
    const source = enabledSources[eventTypeId];
    if (!source?.enabled) return 'none';

    // If no specific templates selected, all are enabled
    if (!source.template_ids || source.template_ids.length === 0) return 'all';

    if (source.template_ids.length === templates.length) return 'all';
    return 'some';
  };

  const isTemplateEnabled = (eventTypeId: string, templateId: string): boolean => {
    const source = enabledSources[eventTypeId];
    if (!source?.enabled) return false;

    // If no specific templates, all are enabled
    if (!source.template_ids || source.template_ids.length === 0) return true;

    return source.template_ids.includes(templateId);
  };

  const formatCategoryName = (category: string): string => {
    return category
      .split('_')
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  if (!eventSources) {
    return (
      <div className="card">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-200 dark:bg-slate-700 rounded w-1/3 mb-4"></div>
          <div className="space-y-3">
            <div className="h-4 bg-gray-200 dark:bg-slate-700 rounded"></div>
            <div className="h-4 bg-gray-200 dark:bg-slate-700 rounded"></div>
            <div className="h-4 bg-gray-200 dark:bg-slate-700 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  const categories = Object.entries(eventSources.categories).sort(([a], [b]) =>
    a.localeCompare(b)
  );

  return (
    <div className="card">
      <h2 className="text-lg font-semibold mb-4 text-gray-900 dark:text-gray-100">Event Sources</h2>
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
        Select which event types to include in noise generation. Each event type can have its own destination, or use the global default. Expand to select specific templates.
      </p>

      <div className="space-y-4">
        {categories.map(([category, sources]) => {
          const isExpanded = expandedCategories.has(category);
          const categoryState = getCategoryState(category);

          return (
            <div key={category} className="border dark:border-slate-700 rounded-lg overflow-hidden">
              {/* Category Header */}
              <div
                className={`flex items-center justify-between px-4 py-3 bg-gray-50 dark:bg-slate-800 cursor-pointer hover:bg-gray-100 dark:hover:bg-slate-700 ${
                  disabled ? 'opacity-50' : ''
                }`}
                onClick={() => toggleCategory(category)}
              >
                <div className="flex items-center gap-2">
                  {isExpanded ? (
                    <ChevronDownIcon className="h-5 w-5 text-gray-500 dark:text-gray-400" />
                  ) : (
                    <ChevronRightIcon className="h-5 w-5 text-gray-500 dark:text-gray-400" />
                  )}
                  <span className="font-medium text-gray-900 dark:text-gray-100">{formatCategoryName(category)}</span>
                  <span className="text-sm text-gray-500 dark:text-gray-400">({sources.length})</span>
                </div>
                <div className="flex items-center gap-3">
                  <span
                    className={`text-xs px-2 py-1 rounded ${
                      categoryState === 'all'
                        ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400'
                        : categoryState === 'some'
                        ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400'
                        : 'bg-gray-100 dark:bg-slate-700 text-gray-500 dark:text-gray-400'
                    }`}
                  >
                    {categoryState === 'all'
                      ? 'All enabled'
                      : categoryState === 'some'
                      ? 'Partial'
                      : 'None enabled'}
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleAllInCategory(category);
                    }}
                    className="text-sm text-primary-600 dark:text-primary-400 hover:text-primary-800 dark:hover:text-primary-300 font-medium"
                    disabled={disabled}
                  >
                    Toggle All
                  </button>
                </div>
              </div>

              {/* Event Types in Category */}
              {isExpanded && (
                <div className="divide-y">
                  {sources.map((source) => {
                    const eventTypeId = source.event_type.id;
                    const isEventExpanded = expandedEventTypes.has(eventTypeId);
                    const sourceConfig = enabledSources[eventTypeId];
                    const isEnabled = sourceConfig?.enabled || false;
                    const eventState = getEventTypeState(eventTypeId, source.templates);

                    return (
                      <div key={eventTypeId} className="bg-white dark:bg-slate-800">
                        {/* Event Type Row */}
                        <div className="flex items-center gap-3 px-4 py-3">
                          {/* Expand button */}
                          <button
                            onClick={() => toggleEventTypeExpand(eventTypeId)}
                            className="p-1 hover:bg-gray-100 dark:hover:bg-slate-700 rounded"
                            disabled={disabled}
                          >
                            {isEventExpanded ? (
                              <ChevronDownIcon className="h-4 w-4 text-gray-400 dark:text-gray-500" />
                            ) : (
                              <ChevronRightIcon className="h-4 w-4 text-gray-400 dark:text-gray-500" />
                            )}
                          </button>

                          {/* Checkbox */}
                          <input
                            type="checkbox"
                            checked={isEnabled}
                            onChange={(e) =>
                              onToggleEventType(eventTypeId, e.target.checked)
                            }
                            disabled={disabled}
                            className="h-4 w-4 text-primary-600 rounded border-gray-300 focus:ring-primary-500"
                          />

                          {/* Event Type Info */}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-sm text-gray-900 dark:text-gray-100">
                                {source.event_type.name}
                              </span>
                              {eventState === 'some' && (
                                <span className="text-xs text-yellow-600 dark:text-yellow-400">
                                  (partial)
                                </span>
                              )}
                            </div>
                            <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                              {source.templates.length} template
                              {source.templates.length !== 1 ? 's' : ''}
                            </p>
                          </div>

                          {/* Destination & Weight (only when enabled) */}
                          {isEnabled && (
                            <div className="flex items-center gap-4">
                              {/* Destination Dropdown */}
                              <div className="flex items-center gap-2">
                                <select
                                  value={sourceConfig?.destination_id || ''}
                                  onChange={(e) =>
                                    onDestinationChange(eventTypeId, e.target.value)
                                  }
                                  disabled={disabled}
                                  className="text-xs border dark:border-slate-600 rounded px-2 py-1 bg-white dark:bg-slate-700 dark:text-gray-200 focus:ring-primary-500 focus:border-primary-500"
                                >
                                  <option value="">
                                    {globalDestinationId
                                      ? `Global (${destinations.find((d) => d.id === globalDestinationId)?.name || 'Default'})`
                                      : 'Select destination'}
                                  </option>
                                  {destinations.map((dest) => (
                                    <option key={dest.id} value={dest.id}>
                                      {dest.name}
                                    </option>
                                  ))}
                                </select>
                              </div>

                              {/* Weight Slider */}
                              <div className="flex items-center gap-2 w-32">
                                <input
                                  type="range"
                                  min="1"
                                  max="100"
                                  value={sourceConfig?.weight || 10}
                                  onChange={(e) =>
                                    onWeightChange(eventTypeId, parseInt(e.target.value))
                                  }
                                  disabled={disabled}
                                  className="w-full h-2 bg-gray-200 dark:bg-slate-600 rounded-lg appearance-none cursor-pointer"
                                />
                                <span className="text-xs text-gray-500 dark:text-gray-400 w-8 text-right">
                                  {sourceConfig?.weight || 10}
                                </span>
                              </div>
                            </div>
                          )}
                        </div>

                        {/* Templates (expanded) */}
                        {isEventExpanded && (
                          <div className="bg-gray-50 dark:bg-slate-900 px-4 py-2 space-y-1">
                            {source.templates.map((template) => {
                              const templateEnabled = isTemplateEnabled(
                                eventTypeId,
                                template.id
                              );

                              return (
                                <label
                                  key={template.id}
                                  className="flex items-center gap-3 py-1 px-8 hover:bg-gray-100 dark:hover:bg-slate-800 rounded cursor-pointer"
                                >
                                  <input
                                    type="checkbox"
                                    checked={templateEnabled}
                                    onChange={(e) =>
                                      onToggleTemplate(
                                        eventTypeId,
                                        template.id,
                                        e.target.checked
                                      )
                                    }
                                    disabled={disabled || !isEnabled}
                                    className="h-3 w-3 text-primary-600 rounded border-gray-300 dark:border-slate-600 focus:ring-primary-500"
                                  />
                                  <span
                                    className={`text-sm ${
                                      !isEnabled ? 'text-gray-400 dark:text-gray-500' : 'text-gray-900 dark:text-gray-100'
                                    }`}
                                  >
                                    {template.name}
                                  </span>
                                  {template.event_id && (
                                    <span className="text-xs text-gray-400 dark:text-gray-500">
                                      ({template.event_id})
                                    </span>
                                  )}
                                </label>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
