"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Alert } from "@/types";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { EvidenceViewer } from "@/components/evidence-viewer";
import { TriagePanel } from "@/components/triage-panel";
import { format } from "date-fns";
import { ArrowLeft, Clock, Calendar } from "lucide-react";
import Link from "next/link";

export default function AlertDetailPage({ params }: { params: { id: string } }) {
    const router = useRouter();
    const [alert, setAlert] = useState<Alert | null>(null);
    const [loading, setLoading] = useState(true);

    const fetchAlert = useCallback(async () => {
        try {
            const res = await fetch(`/api/v1/alerts/${params.id}`);
            if (res.ok) {
                const data = await res.json();
                setAlert(data);
            } else {
                router.push("/");
            }
        } catch (error) {
            console.error("Error fetching alert:", error);
            router.push("/");
        } finally {
            setLoading(false);
        }
    }, [params.id, router]);

    useEffect(() => {
        fetchAlert();
    }, [fetchAlert]);

    if (loading) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
                <p className="text-slate-400">Loading alert...</p>
            </div>
        );
    }

    if (!alert) {
        return null;
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
            {/* Header */}
            <header className="border-b border-slate-700 bg-slate-900/50 backdrop-blur-sm">
                <div className="max-w-7xl mx-auto px-6 py-4">
                    <Link
                        href="/"
                        className="inline-flex items-center gap-2 text-slate-400 hover:text-white transition-colors"
                    >
                        <ArrowLeft size={20} />
                        <span>Back to Dashboard</span>
                    </Link>
                </div>
            </header>

            <main className="max-w-7xl mx-auto px-6 py-8">
                {/* Alert Header */}
                <div className="card mb-6">
                    <div className="flex items-start justify-between mb-4">
                        <div className="flex items-center gap-3">
                            <SeverityBadge severity={alert.severity} />
                            <StatusBadge status={alert.status} />
                        </div>
                        <span className="text-sm text-slate-400">Alert #{alert.id}</span>
                    </div>

                    <h1 className="text-2xl font-bold text-white mb-4">{alert.summary}</h1>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                        <div className="flex items-center gap-2 text-slate-400">
                            <Clock size={16} />
                            <span>
                                Detected: {format(new Date(alert.alert_time), "MMM d, yyyy HH:mm:ss")}
                            </span>
                        </div>
                        {alert.window_start && alert.window_end && (
                            <div className="flex items-center gap-2 text-slate-400">
                                <Calendar size={16} />
                                <span>
                                    Window: {format(new Date(alert.window_start), "HH:mm")} -{" "}
                                    {format(new Date(alert.window_end), "HH:mm")}
                                </span>
                            </div>
                        )}
                        <div className="text-slate-400">
                            <span className="font-mono text-xs bg-slate-800 px-2 py-1 rounded">
                                {alert.rule_id}
                            </span>
                        </div>
                    </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {/* Evidence */}
                    <div className="lg:col-span-2">
                        <EvidenceViewer evidence={alert.evidence} />
                    </div>

                    {/* Triage Actions */}
                    <div>
                        <TriagePanel alert={alert} onUpdate={fetchAlert} />
                    </div>
                </div>
            </main>
        </div>
    );
}
