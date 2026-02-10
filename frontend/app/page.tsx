"use client";

import { useEffect, useState } from "react";
import { Alert } from "@/types";
import { AlertCard } from "@/components/alert-card";
import { Shield, AlertTriangle, Activity, TrendingUp } from "lucide-react";

export default function HomePage() {
    const [alerts, setAlerts] = useState<Alert[]>([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState("all");
    const [severityFilter, setSeverityFilter] = useState("all");

    useEffect(() => {
        fetchAlerts();
        // Auto-refresh every 30 seconds
        const interval = setInterval(fetchAlerts, 30000);
        return () => clearInterval(interval);
    }, []);

    const fetchAlerts = async () => {
        try {
            const res = await fetch("/api/v1/alerts?limit=100");
            if (res.ok) {
                const data = await res.json();
                setAlerts(data);
            }
        } catch (error) {
            console.error("Error fetching alerts:", error);
        } finally {
            setLoading(false);
        }
    };

    const filteredAlerts = alerts.filter((alert) => {
        if (filter !== "all" && alert.status !== filter) return false;
        if (severityFilter !== "all" && alert.severity !== severityFilter) return false;
        return true;
    });

    const stats = {
        total: alerts.length,
        open: alerts.filter((a) => a.status === "open").length,
        critical: alerts.filter((a) => a.severity === "critical").length,
        high: alerts.filter((a) => a.severity === "high").length,
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
            {/* Header */}
            <header className="border-b border-slate-700 bg-slate-900/50 backdrop-blur-sm">
                <div className="max-w-7xl mx-auto px-6 py-6">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-blue-600 rounded-lg">
                            <Shield className="text-white" size={28} />
                        </div>
                        <div>
                            <h1 className="text-2xl font-bold text-white">SignalForge</h1>
                            <p className="text-sm text-slate-400">Security Detection Platform</p>
                        </div>
                    </div>
                </div>
            </header>

            <main className="max-w-7xl mx-auto px-6 py-8">
                {/* Stats Cards */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                    <div className="card bg-gradient-to-br from-blue-900/30 to-blue-800/20 border-blue-500/30">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-sm text-blue-300 mb-1">Total Alerts</p>
                                <p className="text-3xl font-bold text-white">{stats.total}</p>
                            </div>
                            <Activity className="text-blue-400" size={32} />
                        </div>
                    </div>

                    <div className="card bg-gradient-to-br from-red-900/30 to-red-800/20 border-red-500/30">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-sm text-red-300 mb-1">Open Alerts</p>
                                <p className="text-3xl font-bold text-white">{stats.open}</p>
                            </div>
                            <AlertTriangle className="text-red-400" size={32} />
                        </div>
                    </div>

                    <div className="card bg-gradient-to-br from-orange-900/30 to-orange-800/20 border-orange-500/30">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-sm text-orange-300 mb-1">Critical</p>
                                <p className="text-3xl font-bold text-white">{stats.critical}</p>
                            </div>
                            <TrendingUp className="text-orange-400" size={32} />
                        </div>
                    </div>

                    <div className="card bg-gradient-to-br from-yellow-900/30 to-yellow-800/20 border-yellow-500/30">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-sm text-yellow-300 mb-1">High Severity</p>
                                <p className="text-3xl font-bold text-white">{stats.high}</p>
                            </div>
                            <AlertTriangle className="text-yellow-400" size={32} />
                        </div>
                    </div>
                </div>

                {/* Filters */}
                <div className="card mb-6">
                    <div className="flex flex-wrap gap-4 items-center">
                        <div>
                            <label className="text-sm text-slate-400 mb-2 block">Status</label>
                            <select
                                value={filter}
                                onChange={(e) => setFilter(e.target.value)}
                                className="px-4 py-2 bg-slate-800 border border-slate-600 rounded-md text-slate-200 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                            >
                                <option value="all">All Statuses</option>
                                <option value="open">Open</option>
                                <option value="triaged">Triaged</option>
                                <option value="closed">Closed</option>
                                <option value="false_positive">False Positive</option>
                            </select>
                        </div>

                        <div>
                            <label className="text-sm text-slate-400 mb-2 block">Severity</label>
                            <select
                                value={severityFilter}
                                onChange={(e) => setSeverityFilter(e.target.value)}
                                className="px-4 py-2 bg-slate-800 border border-slate-600 rounded-md text-slate-200 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                            >
                                <option value="all">All Severities</option>
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                            </select>
                        </div>

                        <div className="ml-auto flex items-center gap-2">
                            <button
                                onClick={fetchAlerts}
                                className="btn btn-primary text-sm"
                            >
                                Refresh
                            </button>
                        </div>
                    </div>
                </div>

                {/* Alerts List */}
                {loading ? (
                    <div className="card text-center py-12">
                        <p className="text-slate-400">Loading alerts...</p>
                    </div>
                ) : filteredAlerts.length === 0 ? (
                    <div className="card text-center py-12">
                        <Shield className="mx-auto text-slate-600 mb-4" size={48} />
                        <p className="text-slate-400">No alerts found</p>
                        <p className="text-sm text-slate-500 mt-2">
                            {filter !== "all" || severityFilter !== "all"
                                ? "Try adjusting your filters"
                                : "System is secure"}
                        </p>
                    </div>
                ) : (
                    <div className="space-y-4">
                        {filteredAlerts.map((alert) => (
                            <AlertCard key={alert.id} alert={alert} />
                        ))}
                    </div>
                )}
            </main>
        </div>
    );
}
