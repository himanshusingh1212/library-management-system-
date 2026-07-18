import { useState } from "react";
import ScanTrigger from "./components/ScanTrigger";
import SeveritySummary from "./components/SeveritySummary";
import MitreCoverage from "./components/MitreCoverage";
import AIAnalysisPanel from "./components/AIAnalysisPanel";
import FindingsList from "./components/FindingsList";
import { triggerScan, reportUrl } from "./api";

export default function App() {
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleScan(payload) {
    setLoading(true);
    setError(null);
    try {
      const result = await triggerScan(payload);
      setScan(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const coverageErrors =
    scan?.scanner_summaries?.flatMap((s) => s.errors.map((e) => ({ ...e, scanner: s.scanner }))) || [];

  return (
    <div className="min-h-screen bg-soc-bg text-soc-text">
      <header className="border-b border-soc-border px-6 py-4 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight">
            SecureOps <span className="text-soc-accent">AI</span>
          </h1>
          <p className="text-soc-muted text-xs">Azure security posture scanning &amp; AI-generated reporting</p>
        </div>
        {scan && (
          <a
            href={reportUrl(scan.id)}
            className="bg-soc-panel border border-soc-border hover:border-soc-accent text-soc-text text-sm px-4 py-2 rounded transition"
          >
            Download PDF Report
          </a>
        )}
      </header>

      <main className="max-w-6xl mx-auto px-6 py-6 flex flex-col gap-6">
        <ScanTrigger onScan={handleScan} loading={loading} />

        {error && (
          <div className="bg-severity-critical/10 border border-severity-critical text-red-300 rounded-lg px-4 py-3 text-sm">
            {error}
          </div>
        )}

        {scan && (
          <>
            {coverageErrors.length > 0 && (
              <div className="bg-soc-panel border border-soc-border rounded-lg p-4 text-sm">
                <h3 className="text-soc-muted font-semibold mb-2">Scan Coverage Notes</h3>
                <ul className="space-y-1">
                  {coverageErrors.map((e, i) => (
                    <li key={i} className="text-severity-medium">
                      [{e.scanner}] {e.message}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <SeveritySummary severityCounts={scan.severity_counts} />
            <MitreCoverage findings={scan.findings} />
            <AIAnalysisPanel analysis={scan.ai_analysis} />

            <div>
              <h2 className="text-soc-text font-semibold mb-3">Findings ({scan.findings.length})</h2>
              <FindingsList findings={scan.findings} />
            </div>
          </>
        )}

        {!scan && !loading && (
          <div className="text-soc-muted text-sm text-center py-16 border border-dashed border-soc-border rounded-lg">
            Enter a subscription ID above and run a scan to see results.
          </div>
        )}
      </main>
    </div>
  );
}
