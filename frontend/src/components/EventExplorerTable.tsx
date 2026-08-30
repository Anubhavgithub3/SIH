import React, { useState, useMemo } from 'react';
import {
  Search,
  Filter,
  Download,
  Eye,
  X,
  Copy,
  Check,
  Globe,
  Shield,
  Layers,
  Terminal,
} from 'lucide-react';
import type { NormalizedEvent } from '../types';

interface EventExplorerTableProps {
  events: NormalizedEvent[];
}

export const EventExplorerTable: React.FC<EventExplorerTableProps> = ({ events }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [selectedEvent, setSelectedEvent] = useState<NormalizedEvent | null>(null);
  const [copied, setCopied] = useState(false);

  // Filtered & Searched Events
  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      const matchSearch =
        searchTerm === '' ||
        JSON.stringify(e).toLowerCase().includes(searchTerm.toLowerCase());

      const sev = (e.event?.severity || 'low').toLowerCase();
      const matchSeverity =
        severityFilter === 'all' ||
        sev.includes(severityFilter.toLowerCase());

      const src = (e.source || 'unknown').toLowerCase();
      const matchSource =
        sourceFilter === 'all' ||
        src === sourceFilter.toLowerCase();

      return matchSearch && matchSeverity && matchSource;
    });
  }, [events, searchTerm, severityFilter, sourceFilter]);

  // Unique sources for filter dropdown
  const uniqueSources = useMemo(() => {
    const set = new Set<string>();
    events.forEach((e) => {
      if (e.source) set.add(e.source);
    });
    return Array.from(set);
  }, [events]);

  const copyEventJSON = () => {
    if (!selectedEvent) return;
    navigator.clipboard.writeText(JSON.stringify(selectedEvent, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const exportJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(events, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `security_events_${new Date().toISOString()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const exportCSV = () => {
    const headers = ['Timestamp', 'Source', 'Action', 'Severity', 'Source IP', 'Destination IP', 'Country', 'Threat'];
    const rows = filteredEvents.map((e) => [
      e.timestamp || '',
      e.source || '',
      e.event?.action || '',
      e.event?.severity || '',
      e.network?.source_ip || e.network?.src_ip || '',
      e.network?.destination_ip || e.network?.dst_ip || '',
      e.enrichment?.country || '',
      e.threat?.reputation || '',
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.map((c) => `"${c}"`).join(','))].join('\n');
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', encodeURI(csvContent));
    downloadAnchor.setAttribute('download', `security_events_${new Date().toISOString()}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="event-explorer-container glass-panel">
      {/* Table Toolbar */}
      <div className="explorer-toolbar">
        <div className="search-box-wrap">
          <Search size={16} className="search-icon" />
          <input
            type="text"
            className="search-input"
            placeholder="Search by IP, message, action, threat..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          {searchTerm && (
            <button onClick={() => setSearchTerm('')} className="search-clear-btn">
              <X size={14} />
            </button>
          )}
        </div>

        <div className="filter-group">
          {/* Severity Filter */}
          <div className="filter-select-wrap">
            <Filter size={14} className="filter-icon" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="filter-select"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Source Filter */}
          <div className="filter-select-wrap">
            <Layers size={14} className="filter-icon" />
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="filter-select"
            >
              <option value="all">All Sources</option>
              {uniqueSources.map((src) => (
                <option key={src} value={src}>
                  {src.toUpperCase()}
                </option>
              ))}
            </select>
          </div>

          {/* Export Buttons */}
          <button onClick={exportJSON} className="btn btn-secondary btn-sm" title="Export as JSON">
            <Download size={13} />
            <span>JSON</span>
          </button>
          <button onClick={exportCSV} className="btn btn-secondary btn-sm" title="Export as CSV">
            <Download size={13} />
            <span>CSV</span>
          </button>
        </div>
      </div>

      {/* Events Count summary */}
      <div className="table-meta-bar">
        <span>Showing <strong>{filteredEvents.length}</strong> of {events.length} normalized events</span>
        {filteredEvents.length < events.length && (
          <span className="filter-active-note">Filtered active</span>
        )}
      </div>

      {/* Main Table */}
      <div className="table-container">
        <table className="siem-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source</th>
              <th>Action / Event</th>
              <th>Severity</th>
              <th>Source IP</th>
              <th>Destination IP</th>
              <th>Geo / Intel</th>
              <th>Inspect</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvents.map((event, idx) => {
              const severity = (event.event?.severity || 'low').toLowerCase();
              const action = event.event?.action || event.event?.type || 'event';
              const sourceIp = event.network?.source_ip || event.network?.src_ip || '—';
              const destIp = event.network?.destination_ip || event.network?.dst_ip || '—';
              const country = event.enrichment?.country;
              const reputation = event.threat?.reputation;

              const isSuspicious = reputation === 'suspicious' || reputation === 'malicious';

              return (
                <tr
                  key={idx}
                  onClick={() => setSelectedEvent(event)}
                  className="table-row-clickable"
                >
                  <td className="mono text-muted td-time">
                    {event.timestamp ? event.timestamp.replace('T', ' ').replace('Z', '') : '—'}
                  </td>
                  <td>
                    <span className="source-pill mono">
                      {event.source || 'api'}
                    </span>
                  </td>
                  <td>
                    <div className="action-cell">
                      <span className="action-title">{action}</span>
                      {event.event?.type && event.event.type !== action && (
                        <span className="action-type-sub mono">{event.event.type}</span>
                      )}
                    </div>
                  </td>
                  <td>
                    <span className={`badge badge-${severity}`}>
                      {severity}
                    </span>
                  </td>
                  <td className="mono">
                    <span className={isSuspicious ? 'text-red font-bold' : ''}>
                      {sourceIp}
                    </span>
                  </td>
                  <td className="mono text-muted">
                    {destIp}
                  </td>
                  <td>
                    <div className="geo-intel-cell">
                      {country && (
                        <span className="geo-flag-chip">
                          <Globe size={11} />
                          <span>{country}</span>
                        </span>
                      )}
                      {reputation && (
                        <span className={`badge badge-${isSuspicious ? 'critical' : 'low'}`}>
                          {reputation}
                        </span>
                      )}
                    </div>
                  </td>
                  <td>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedEvent(event);
                      }}
                      className="btn-inspect"
                      title="Inspect Canonical JSON"
                    >
                      <Eye size={14} />
                    </button>
                  </td>
                </tr>
              );
            })}

            {filteredEvents.length === 0 && (
              <tr>
                <td colSpan={8} className="empty-table-cell">
                  <Terminal size={24} className="text-muted" />
                  <p>No matching normalized security events found.</p>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Deep JSON Inspector Modal / Drawer */}
      {selectedEvent && (
        <div className="modal-backdrop" onClick={() => setSelectedEvent(null)}>
          <div className="modal-content glass-panel" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title-wrap">
                <Shield size={20} className="text-accent" />
                <div>
                  <h3 className="modal-title">Canonical Event Schema Details</h3>
                  <p className="modal-subtitle">Normalized standard event representation</p>
                </div>
              </div>
              <div className="modal-header-actions">
                <button onClick={copyEventJSON} className="btn btn-secondary btn-sm">
                  {copied ? <Check size={14} /> : <Copy size={14} />}
                  <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                </button>
                <button onClick={() => setSelectedEvent(null)} className="btn-close">
                  <X size={18} />
                </button>
              </div>
            </div>

            <div className="modal-body">
              {/* Field Groups Summary */}
              <div className="modal-summary-grid">
                <div className="modal-field-card">
                  <span className="field-card-label">Source & Host</span>
                  <span className="field-card-val mono">{selectedEvent.source || 'api'} / {selectedEvent.host || 'local'}</span>
                </div>
                <div className="modal-field-card">
                  <span className="field-card-label">Event Action</span>
                  <span className="field-card-val mono">{selectedEvent.event?.action || 'unknown'}</span>
                </div>
                <div className="modal-field-card">
                  <span className="field-card-label">Severity</span>
                  <span className={`badge badge-${selectedEvent.event?.severity || 'low'}`}>
                    {selectedEvent.event?.severity || 'low'}
                  </span>
                </div>
                <div className="modal-field-card">
                  <span className="field-card-label">GeoIP Country</span>
                  <span className="field-card-val mono">{selectedEvent.enrichment?.country || 'N/A'}</span>
                </div>
              </div>

              {/* Raw JSON viewer */}
              <div className="json-viewer-header">
                <span className="mono text-muted">JSON Schema Output:</span>
              </div>
              <pre className="modal-json-pre mono">
                {JSON.stringify(selectedEvent, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
