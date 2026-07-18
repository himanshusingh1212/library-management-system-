const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLOR = {
  critical: "bg-severity-critical",
  high: "bg-severity-high",
  medium: "bg-severity-medium",
  low: "bg-severity-low",
  info: "bg-severity-info",
};

export default function SeveritySummary({ severityCounts }) {
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + (severityCounts[s] || 0), 0);

  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg p-5">
      <div className="flex items-baseline justify-between mb-3">
        <h2 className="text-soc-text font-semibold">Severity Summary</h2>
        <span className="text-soc-muted text-sm">{total} total findings</span>
      </div>

      <div className="w-full h-3 rounded-full overflow-hidden flex bg-soc-bg mb-4">
        {total === 0 ? (
          <div className="w-full bg-soc-border" />
        ) : (
          SEVERITY_ORDER.map((s) =>
            severityCounts[s] ? (
              <div
                key={s}
                className={SEVERITY_COLOR[s]}
                style={{ width: `${(severityCounts[s] / total) * 100}%` }}
                title={`${s}: ${severityCounts[s]}`}
              />
            ) : null
          )
        )}
      </div>

      <div className="grid grid-cols-5 gap-2">
        {SEVERITY_ORDER.map((s) => (
          <div key={s} className="flex flex-col items-center gap-1">
            <span className={`w-2.5 h-2.5 rounded-full ${SEVERITY_COLOR[s]}`} />
            <span className="text-lg font-bold text-soc-text">{severityCounts[s] || 0}</span>
            <span className="text-xs text-soc-muted uppercase tracking-wide">{s}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
