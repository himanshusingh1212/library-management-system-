import { useState } from "react";

const SCANNERS = [
  { key: "include_network", label: "Network (NSG)" },
  { key: "include_key_vault", label: "Key Vault" },
  { key: "include_storage", label: "Storage" },
  { key: "include_identity", label: "Conditional Access" },
];

export default function ScanTrigger({ onScan, loading }) {
  const [subscriptionId, setSubscriptionId] = useState("");
  const [options, setOptions] = useState({
    include_network: true,
    include_key_vault: true,
    include_storage: true,
    include_identity: true,
  });

  function toggle(key) {
    setOptions((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  function handleSubmit(e) {
    e.preventDefault();
    if (!subscriptionId.trim()) return;
    onScan({ subscription_id: subscriptionId.trim(), ...options });
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="bg-soc-panel border border-soc-border rounded-lg p-5 flex flex-col gap-4"
    >
      <div>
        <label className="block text-sm text-soc-muted mb-1">Azure Subscription ID</label>
        <input
          type="text"
          value={subscriptionId}
          onChange={(e) => setSubscriptionId(e.target.value)}
          placeholder="00000000-0000-0000-0000-000000000000"
          className="w-full bg-soc-bg border border-soc-border rounded px-3 py-2 text-soc-text font-mono text-sm focus:outline-none focus:border-soc-accent"
        />
      </div>

      <div className="flex flex-wrap gap-4">
        {SCANNERS.map((s) => (
          <label key={s.key} className="flex items-center gap-2 text-sm text-soc-text cursor-pointer">
            <input
              type="checkbox"
              checked={options[s.key]}
              onChange={() => toggle(s.key)}
              className="accent-soc-accent"
            />
            {s.label}
          </label>
        ))}
      </div>

      <button
        type="submit"
        disabled={loading || !subscriptionId.trim()}
        className="self-start bg-soc-accent text-soc-bg font-semibold px-5 py-2 rounded disabled:opacity-40 disabled:cursor-not-allowed hover:brightness-110 transition"
      >
        {loading ? "Scanning..." : "Run Scan"}
      </button>
    </form>
  );
}
