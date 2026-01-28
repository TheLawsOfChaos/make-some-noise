import { useEffect, useState } from 'react';
import { DocumentTextIcon } from '@heroicons/react/24/outline';
import { getTemplates } from '../api/client';
import type { EventTemplate } from '../types';

// Extended template type with metadata
interface TemplateWithMetadata extends EventTemplate {
  source?: 'builtin' | 'custom';
}

const CATEGORIES = [
  { id: '', label: 'All Categories' },
  { id: 'windows_security', label: 'Windows Security' },
  { id: 'windows_sysmon', label: 'Windows Sysmon' },
  { id: 'cisco_asa', label: 'Cisco ASA' },
  { id: 'cisco_firepower', label: 'Cisco Firepower' },
  { id: 'suricata', label: 'Suricata IDS' },
  { id: 'linux_auditbeat', label: 'Linux Auditbeat' },
  { id: 'microsoft_ad', label: 'Microsoft AD' },
];

export default function Templates() {
  const [templates, setTemplates] = useState<TemplateWithMetadata[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCategory, setSelectedCategory] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    const fetchTemplates = async () => {
      try {
        const data = await getTemplates(selectedCategory || undefined);
        setTemplates(data.templates);
      } catch (err) {
        console.error('Failed to fetch templates:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchTemplates();
  }, [selectedCategory]);

  const filteredTemplates = templates.filter((template) => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      template.name.toLowerCase().includes(query) ||
      template.description?.toLowerCase().includes(query) ||
      template.id.toLowerCase().includes(query)
    );
  });

  // Group templates by category
  const groupedTemplates = filteredTemplates.reduce((acc, template) => {
    const category = template.category;
    if (!acc[category]) {
      acc[category] = [];
    }
    acc[category].push(template);
    return acc;
  }, {} as Record<string, TemplateWithMetadata[]>);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-8">Event Templates</h1>

      {/* Filters */}
      <div className="card mb-8">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="label">Category</label>
            <select
              className="select"
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
            >
              {CATEGORIES.map((cat) => (
                <option key={cat.id} value={cat.id}>
                  {cat.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label">Search</label>
            <input
              type="text"
              className="input"
              placeholder="Search templates..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Templates List */}
      <div className="space-y-8">
        {Object.entries(groupedTemplates).map(([category, categoryTemplates]) => (
          <div key={category}>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center gap-2">
              <DocumentTextIcon className="h-5 w-5 text-gray-400 dark:text-gray-500" />
              {CATEGORIES.find((c) => c.id === category)?.label || category}
              <span className="text-sm font-normal text-gray-400 dark:text-gray-500">
                ({categoryTemplates.length})
              </span>
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {categoryTemplates.map((template) => (
                <div key={template.id} className="card hover:border-primary-300 dark:hover:border-primary-600 transition-colors">
                  <div className="flex items-start justify-between mb-2">
                    <h3 className="font-medium text-gray-900 dark:text-gray-100">{template.name}</h3>
                    <div className="flex gap-1">
                      <span
                        className={`px-2 py-0.5 text-xs rounded-full ${
                          template.source === 'custom'
                            ? 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300'
                            : 'bg-gray-100 dark:bg-slate-700 text-gray-600 dark:text-gray-300'
                        }`}
                      >
                        {template.source || 'builtin'}
                      </span>
                    </div>
                  </div>

                  {template.description && (
                    <p className="text-sm text-gray-500 dark:text-gray-400 mb-3">{template.description}</p>
                  )}

                  <div className="flex items-center gap-2 text-xs text-gray-400 dark:text-gray-500">
                    {template.event_id && (
                      <span className="px-2 py-0.5 bg-gray-100 dark:bg-slate-700 rounded">
                        ID: {template.event_id}
                      </span>
                    )}
                    <span className="px-2 py-0.5 bg-gray-100 dark:bg-slate-700 rounded">{template.format}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}

        {filteredTemplates.length === 0 && (
          <div className="card text-center text-gray-500 dark:text-gray-400 py-12">
            <DocumentTextIcon className="h-12 w-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
            <p>No templates found matching your criteria.</p>
          </div>
        )}
      </div>

      {/* Summary */}
      <div className="mt-8 text-center text-sm text-gray-500 dark:text-gray-400">
        Showing {filteredTemplates.length} of {templates.length} templates
      </div>
    </div>
  );
}
