import React, { useState, useMemo } from 'react';
import {
  Search,
  Filter,
  Eye,
  X,
  Copy,
  Check,
  Globe,
  Shield,
  Layers,
  Terminal,
  FileSpreadsheet,
  FileCode,
  Sparkles,
} from 'lucide-react';
import type { NormalizedEvent } from '../types';

interface EventExplorerTableProps {
  events: NormalizedEvent[];
}

export const EventExplorerTable: React.FC<EventExplorerTableProps> = ({ events }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [quickFilter, setQuickFilter] = useState<'all' | 'blocked' | 'critical' | 'threats' | 'geo'>('all');
  const [selectedEvent, setSelectedEvent] = useState<NormalizedEvent | null>(null);
  const [copied, setCopied] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);

  // Filtered & Searched Events
  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      // Quick preset filter
      if (quickFilter === 'blocked') {
        const act = String(e.event?.action || '').toLowerCase();
        if (!act.includes('deny') && !act.includes('block') && !act.includes('drop')) return false;
      } else if (quickFilter === 'critical') {
        const sev = String(e.event?.severity || e.severity || '').toLowerCase();
        if (sev !== 'critical' && sev !== 'high') return false;
      } else if (quickFilter === 'threats') {
        const rep = String(e.threat?.reputation || '').toLowerCase();
        if (rep !== 'suspicious' && rep !== 'malicious') return false;
      } else if (quickFilter === 'geo') {
        const country = e.enrichment?.country;
        if (!country || country === 'US' || country === 'IN') return false;
      }

      const matchSearch =
        searchTerm === '' ||
        JSON.stringify(e).toLowerCase().includes(searchTerm.toLowerCase());

      const sev = String(e.event?.severity || e.severity || 'low').toLowerCase();
      const matchSeverity =
        severityFilter === 'all' ||
        sev.includes(severityFilter.toLowerCase());

      const src = (e.source || 'unknown').toLowerCase();
      const matchSource =
        sourceFilter === 'all' ||
        src === sourceFilter.toLowerCase();

      return matchSearch && matchSeverity && matchSource;
    });
  }, [events, searchTerm, severityFilter, sourceFilter, quickFilter]);

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
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(filteredEvents, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `siem_normalized_events_${new Date().toISOString()}.json`);
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
      e.event?.severity || e.severity || '',
      e.network?.source_ip || e.network?.src_ip || '',
      e.network?.destination_ip || e.network?.dst_ip || '',
      e.enrichment?.country || '',
      e.threat?.reputation || '',
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.map((c) => `"${c}"`).join(','))].join('\n');
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', encodeURI(csvContent));
    downloadAnchor.setAttribute('download', `siem_normalized_events_${new Date().toISOString()}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="event-explorer-container glass-panel">
      {/* Explorer Top Banner */}
      <div className="explorer-header-section">
        <div>
          <div className="badge-row" style={{ display: 'flex', gap: '8px', marginBottom: '6px' }}>
            <span className="badge badge-cyan">OCSF Standard Compliant</span>
            <span className="badge badge-purple">Real-Time Search &amp; Filter</span>
          </div>
          <h2 className="card-title" style={{ fontSize: '1.3rem' }}>SIEM Event Explorer &amp; Query Surface</h2>
          <p className="card-subtitle" style={{ fontSize: '0.86rem' }}>
            Deep forensic search, multi-field faceted filtering, and canonical JSON object inspection
          </p>
        </div>

        <div className="export-btn-group">
          <button onClick={exportJSON} className="btn btn-secondary btn-sm" title="Export as JSON">
            <FileCode size={14} className="text-cyan" />
            <span>Export JSON</span>
          </button>
          <button onClick={exportCSV} className="btn btn-secondary btn-sm" title="Export as CSV">
            <FileSpreadsheet size={14} className="text-emerald" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Quick Facet Filter Chips */}
      <div className="quick-filter-chips-row">
        <span className="quick-filter-label">
          <Sparkles size={14} className="text-accent" />
          <span>Quick Views:</span>
        </span>
        <button
          onClick={() => setQuickFilter('all')}
          className={`quick-chip ${quickFilter === 'all' ? 'active' : ''}`}
        >
          All Telemetry ({events.length})
        </button>
        <button
          onClick={() => setQuickFilter('blocked')}
          className={`quick-chip ${quickFilter === 'blocked' ? 'active' : ''}`}
        >
          Blocked / Dropped Only
        </button>
        <button
          onClick={() => setQuickFilter('critical')}
          className={`quick-chip ${quickFilter === 'critical' ? 'active' : ''}`}
        >
          High &amp; Critical Severity
        </button>
        <button
          onClick={() => setQuickFilter('threats')}
          className={`quick-chip ${quickFilter === 'threats' ? 'active' : ''}`}
        >
          Suspicious CTI IOCs
        </button>
        <button
          onClick={() => setQuickFilter('geo')}
          className={`quick-chip ${quickFilter === 'geo' ? 'active' : ''}`}
        >
          Cross-Border / Geo-Risk
        </button>
      </div>

      {/* Table Search & Dropdown Toolbar */}
      <div className="explorer-toolbar">
        <div className="search-box-wrap">
          <Search size={16} className="search-icon" />
          <input
            type="text"
            className="search-input"
            placeholder="Search by IP, message token, action, reputation, vendor..."
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
        </div>
      </div>

      {/* Events Count summary */}
      <div className="table-meta-bar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>Showing <strong>{Math.min(filteredEvents.length, (currentPage - 1) * 25 + 1)}</strong> - <strong>{Math.min(currentPage * 25, filteredEvents.length)}</strong> of {filteredEvents.length.toLocaleString()} normalized canonical records</span>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className="btn btn-secondary btn-sm"
          >
            Previous
          </button>
          <span className="mono" style={{ fontSize: '0.85rem' }}>
            Page {currentPage} of {Math.max(1, Math.ceil(filteredEvents.length / 25))}
          </span>
          <button
            onClick={() => setCurrentPage((p) => Math.min(Math.max(1, Math.ceil(filteredEvents.length / 25)), p + 1))}
            disabled={currentPage >= Math.ceil(filteredEvents.length / 25)}
            className="btn btn-secondary btn-sm"
          >
            Next
          </button>
        </div>
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
            {filteredEvents.slice((currentPage - 1) * 25, currentPage * 25).map((event, idx) => {
              const severity = String(event.event?.severity || event.severity || 'low').toLowerCase();
              const action = String(event.event?.action || event.event?.type || 'event');
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
                    <span className={`badge badge-${severity === 'critical' ? 'critical' : severity === 'high' ? 'high' : severity === 'medium' ? 'medium' : 'low'}`}>
                      {severity.toUpperCase()}
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
                          {reputation.toUpperCase()}
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
                  {copied ? <Check size={14} className="text-emerald" /> : <Copy size={14} />}
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
                  <span className="field-card-label">Source &amp; Host</span>
                  <span className="field-card-val mono">{selectedEvent.source || 'api'} / {selectedEvent.host || 'local'}</span>
                </div>
                <div className="modal-field-card">
                  <span className="field-card-label">Event Action</span>
                  <span className="field-card-val mono">{selectedEvent.event?.action || 'unknown'}</span>
                </div>
                <div className="modal-field-card">
                  <span className="field-card-label">Severity</span>
                  <span className={`badge badge-${selectedEvent.event?.severity || 'low'}`}>
                    {String(selectedEvent.event?.severity || 'low').toUpperCase()}
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
