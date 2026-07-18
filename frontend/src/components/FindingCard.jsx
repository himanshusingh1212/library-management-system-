import { useState } from "react";

const SEVERITY_BADGE = {
  critical: "bg-severity-critical text-white",
  high: "bg-severity-high text-white",
  medium: "bg-severity-medium text-white",
  low: "bg-severity-low text-white",
  info: "bg-severity-info text-white",
};

export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center justify-between gap-3 px-4 py-3 text-left"
      >
        <div className="flex items-center gap-3 min-w-0">
          <span
            className={`shrink-0 text-[11px] font-bold uppercase px-2 py-0.5 rounded ${SEVERITY_BADGE[finding.severity]}`}
          >
            {finding.severity}
          </span>
          <span className="text-soc-text text-sm truncate">{finding.title}</span>
        </div>
        <span className="text-soc-muted text-xs shrink-0">CVSS {finding.cvss_score}</span>
      </button>

      {expanded && (
        <div className="px-4 pb-4 pt-1 border-t border-soc-border text-sm space-y-2">
          <p className="text-soc-text">{finding.description}</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-soc-muted">
            <div>
              <span className="text-soc-muted">Resource: </span>
              <span className="text-soc-text">{finding.resource_name}</span>
            </div>
            <div>
              <span className="text-soc-muted">Type: </span>
              <span className="text-soc-text">{finding.resource_type}</span>
            </div>
            <div className="sm:col-span-2">
              <span className="text-soc-muted">MITRE ATT&CK: </span>
              <span className="text-soc-accent">
                {finding.mitre.tactic_name} ({finding.mitre.tactic_id}) &rarr;{" "}
                {finding.mitre.technique_name} ({finding.mitre.technique_id})
              </span>
            </div>
          </div>
          <div>
            <span className="text-soc-muted">Recommendation: </span>
            <span className="text-soc-text">{finding.recommendation}</span>
          </div>
        </div>
      )}
    </div>
  );
}
