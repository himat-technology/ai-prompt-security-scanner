"use client";

import type { AttackPreset } from "@/lib/security-scanner";

interface PresetAttacksProps {
  presets: AttackPreset[];
  activeId: string | null;
  onSelect: (preset: AttackPreset) => void;
}

const PRESET_COLORS = [
  "from-rose-500 to-orange-400",
  "from-amber-500 to-yellow-400",
  "from-lime-500 to-emerald-400",
  "from-teal-500 to-cyan-400",
  "from-sky-500 to-blue-400",
  "from-indigo-500 to-violet-400",
  "from-fuchsia-500 to-pink-400",
  "from-orange-500 to-rose-400",
  "from-cyan-500 to-teal-400",
  "from-emerald-500 to-lime-400",
] as const;

export function PresetAttacks({
  presets,
  activeId,
  onSelect,
}: PresetAttacksProps) {
  return (
    <section
      aria-labelledby="preset-heading"
      className="space-y-3 rounded-2xl border border-white/15 bg-white/10 p-4 backdrop-blur-md sm:p-5"
    >
      <div>
        <h2 id="preset-heading" className="text-sm font-semibold text-white">
          Load Preset Attack Vectors & Security Test Samples
        </h2>
        <p className="mt-1 text-xs text-slate-300">
          Click a sample to load a safe test payload into the editor. Samples
          never contain real credentials.
        </p>
      </div>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-2">
        {presets.map((preset, index) => {
          const selected = activeId === preset.id;
          const gradient = PRESET_COLORS[index % PRESET_COLORS.length];
          return (
            <button
              key={preset.id}
              type="button"
              onClick={() => onSelect(preset)}
              aria-pressed={selected}
              className={`group rounded-xl border px-3 py-2.5 text-left transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-300 ${
                selected
                  ? "border-cyan-300 bg-white shadow-lg shadow-cyan-500/20"
                  : "border-white/15 bg-white/90 hover:border-cyan-300 hover:shadow-md"
              }`}
            >
              <span className="flex items-start gap-2">
                <span
                  className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-gradient-to-br text-[10px] font-bold text-white shadow-sm ${gradient}`}
                  aria-hidden="true"
                >
                  {index + 1}
                </span>
                <span>
                  <span className="block text-sm font-semibold text-slate-900">
                    {preset.label}
                  </span>
                  <span className="mt-0.5 block text-xs text-slate-500">
                    {preset.description}
                  </span>
                </span>
              </span>
            </button>
          );
        })}
      </div>
    </section>
  );
}
