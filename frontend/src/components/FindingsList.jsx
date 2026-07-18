import { useState } from "react";
import FindingCard from "./FindingCard";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export default function FindingsList({ findings }) {
  const [filter, setFilter] = useState("all");

  const filtered =
    filter === "all" ? findings : findings.filter((f) => f.severity === filter);
  const sorted = [...filtered].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-soc-muted text-sm mr-1">Filter:</span>
        {["all", ...SEVERITY_ORDER].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`text-xs px-3 py-1 rounded-full border transition ${
              filter === s
                ? "bg-soc-accent text-soc-bg border-soc-accent"
                : "border-soc-border text-soc-muted hover:text-soc-text"
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      {sorted.length === 0 ? (
        <div className="text-soc-muted text-sm py-6 text-center">No findings match this filter.</div>
      ) : (
        <div className="flex flex-col gap-2">
          {sorted.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}
