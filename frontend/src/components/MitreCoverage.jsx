const ALL_TACTICS = [
  ["TA0043", "Reconnaissance"],
  ["TA0042", "Resource Development"],
  ["TA0001", "Initial Access"],
  ["TA0002", "Execution"],
  ["TA0003", "Persistence"],
  ["TA0004", "Privilege Escalation"],
  ["TA0005", "Defense Evasion"],
  ["TA0006", "Credential Access"],
  ["TA0007", "Discovery"],
  ["TA0008", "Lateral Movement"],
  ["TA0009", "Collection"],
  ["TA0011", "Command and Control"],
  ["TA0010", "Exfiltration"],
  ["TA0040", "Impact"],
];

export default function MitreCoverage({ findings }) {
  const tacticCounts = {};
  for (const f of findings) {
    const id = f.mitre.tactic_id;
    tacticCounts[id] = (tacticCounts[id] || 0) + 1;
  }
  const maxCount = Math.max(1, ...Object.values(tacticCounts));

  return (
    <div className="bg-soc-panel border border-soc-border rounded-lg p-5">
      <h2 className="text-soc-text font-semibold mb-1">MITRE ATT&CK Coverage</h2>
      <p className="text-soc-muted text-sm mb-4">
        Attacker tactics actually exposed by findings in this scan.
      </p>
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
        {ALL_TACTICS.map(([id, name]) => {
          const count = tacticCounts[id] || 0;
          const intensity = count === 0 ? 0 : count / maxCount;
          return (
            <div
              key={id}
              className="rounded p-2 border text-center"
              style={{
                borderColor: count > 0 ? "#22d3ee" : "#1f2937",
                backgroundColor:
                  count > 0 ? `rgba(34, 211, 238, ${0.12 + intensity * 0.35})` : "#0b0f14",
              }}
              title={`${name} (${id}): ${count} finding(s)`}
            >
              <div className="text-[11px] text-soc-muted">{id}</div>
              <div className="text-xs text-soc-text leading-tight mt-1">{name}</div>
              {count > 0 && (
                <div className="text-sm font-bold text-soc-accent mt-1">{count}</div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
