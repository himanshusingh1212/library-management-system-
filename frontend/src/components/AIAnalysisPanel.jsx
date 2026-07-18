export default function AIAnalysisPanel({ analysis }) {
  if (!analysis) {
    return (
      <div className="bg-soc-panel border border-soc-border rounded-lg p-5 text-soc-muted text-sm">
        AI analysis was not generated for this scan.
      </div>
    );
  }

  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg p-5 flex flex-col gap-5">
      <div className="flex items-center gap-2">
        <span className="text-soc-accent text-xs font-semibold uppercase tracking-wide border border-soc-accent rounded px-2 py-0.5">
          AI Generated
        </span>
        <h2 className="text-soc-text font-semibold">Executive Analysis</h2>
      </div>

      <div>
        <h3 className="text-sm font-semibold text-soc-muted mb-1">Executive Summary</h3>
        <p className="text-soc-text text-sm leading-relaxed">{analysis.executive_summary}</p>
      </div>

      {analysis.top_risks?.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-soc-muted mb-1">Top Risks</h3>
          <ul className="list-disc list-inside space-y-1">
            {analysis.top_risks.map((risk, i) => (
              <li key={i} className="text-soc-text text-sm">
                {risk}
              </li>
            ))}
          </ul>
        </div>
      )}

      {analysis.remediation_plan?.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-soc-muted mb-1">Prioritized Remediation Plan</h3>
          <ol className="list-decimal list-inside space-y-1">
            {analysis.remediation_plan.map((step, i) => (
              <li key={i} className="text-soc-text text-sm">
                {step}
              </li>
            ))}
          </ol>
        </div>
      )}

      <div>
        <h3 className="text-sm font-semibold text-soc-muted mb-1">Business Impact</h3>
        <p className="text-soc-text text-sm leading-relaxed">{analysis.business_impact}</p>
      </div>
    </div>
  );
}
