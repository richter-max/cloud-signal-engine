"use client";

import { useState } from "react";

interface EvidenceViewerProps {
    evidence: Record<string, any>;
}

export function EvidenceViewer({ evidence }: EvidenceViewerProps) {
    const [expanded, setExpanded] = useState(true);

    return (
        <div className="card">
            <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-white">Evidence</h3>
                <button
                    onClick={() => setExpanded(!expanded)}
                    className="text-sm text-blue-400 hover:text-blue-300"
                >
                    {expanded ? "Collapse" : "Expand"}
                </button>
            </div>

            {expanded && (
                <div className="space-y-3">
                    {Object.entries(evidence).map(([key, value]) => (
                        <div key={key} className="flex flex-col gap-1">
                            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">
                                {key.replace(/_/g, " ")}
                            </span>
                            <div className="bg-slate-800/50 p-3 rounded border border-slate-700">
                                {Array.isArray(value) ? (
                                    <ul className="list-disc list-inside text-sm text-slate-200 space-y-1">
                                        {value.map((item, idx) => (
                                            <li key={idx} className="font-mono text-xs">
                                                {typeof item === "object" ? JSON.stringify(item) : String(item)}
                                            </li>
                                        ))}
                                    </ul>
                                ) : typeof value === "object" && value !== null ? (
                                    <pre className="text-xs text-slate-200 font-mono overflow-x-auto">
                                        {JSON.stringify(value, null, 2)}
                                    </pre>
                                ) : (
                                    <span className="text-sm text-slate-200 font-mono">
                                        {String(value)}
                                    </span>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
