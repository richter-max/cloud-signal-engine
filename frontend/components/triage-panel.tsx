"use client";

import { useState } from "react";
import { Alert } from "@/types";
import { CheckCircle, XCircle, AlertTriangle, Ban } from "lucide-react";

interface TriagePanelProps {
    alert: Alert;
    onUpdate: () => void;
}

export function TriagePanel({ alert, onUpdate }: TriagePanelProps) {
    const [loading, setLoading] = useState(false);
    const [showFPForm, setShowFPForm] = useState(false);
    const [fpReason, setFpReason] = useState("");

    const updateStatus = async (status: string) => {
        setLoading(true);
        try {
            const res = await fetch(`/api/v1/alerts/${alert.id}/status`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ status }),
            });

            if (res.ok) {
                onUpdate();
            } else {
                alert("Failed to update status");
            }
        } catch (error) {
            console.error("Error updating status:", error);
            alert("Error updating status");
        } finally {
            setLoading(false);
        }
    };

    const markFalsePositive = async () => {
        if (!fpReason.trim()) {
            alert("Please provide a reason");
            return;
        }

        setLoading(true);
        try {
            const res = await fetch(`/api/v1/alerts/${alert.id}/false-positive`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ reason: fpReason }),
            });

            if (res.ok) {
                setShowFPForm(false);
                setFpReason("");
                onUpdate();
            } else {
                alert("Failed to mark as false positive");
            }
        } catch (error) {
            console.error("Error marking false positive:", error);
            alert("Error marking false positive");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="card">
            <h3 className="text-lg font-semibold text-white mb-4">Triage Actions</h3>

            <div className="space-y-3">
                {alert.status === "open" && (
                    <>
                        <button
                            onClick={() => updateStatus("triaged")}
                            disabled={loading}
                            className="btn btn-primary w-full flex items-center justify-center gap-2"
                        >
                            <AlertTriangle size={16} />
                            Mark as Triaged
                        </button>

                        <button
                            onClick={() => updateStatus("closed")}
                            disabled={loading}
                            className="btn btn-secondary w-full flex items-center justify-center gap-2"
                        >
                            <CheckCircle size={16} />
                            Close Alert
                        </button>
                    </>
                )}

                {alert.status === "triaged" && (
                    <button
                        onClick={() => updateStatus("closed")}
                        disabled={loading}
                        className="btn btn-primary w-full flex items-center justify-center gap-2"
                    >
                        <CheckCircle size={16} />
                        Close Alert
                    </button>
                )}

                {alert.status !== "false_positive" && (
                    <>
                        {!showFPForm ? (
                            <button
                                onClick={() => setShowFPForm(true)}
                                disabled={loading}
                                className="btn btn-danger w-full flex items-center justify-center gap-2"
                            >
                                <Ban size={16} />
                                Mark as False Positive
                            </button>
                        ) : (
                            <div className="space-y-2 p-4 bg-slate-800 rounded-md border border-slate-700">
                                <label className="text-sm text-slate-300 font-medium">
                                    Reason for False Positive
                                </label>
                                <textarea
                                    value={fpReason}
                                    onChange={(e) => setFpReason(e.target.value)}
                                    placeholder="Explain why this is a false positive..."
                                    className="w-full px-3 py-2 bg-slate-900 border border-slate-600 rounded-md text-slate-200 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    rows={3}
                                />
                                <div className="flex gap-2">
                                    <button
                                        onClick={markFalsePositive}
                                        disabled={loading}
                                        className="btn btn-danger flex-1"
                                    >
                                        Confirm
                                    </button>
                                    <button
                                        onClick={() => setShowFPForm(false)}
                                        className="btn btn-secondary flex-1"
                                    >
                                        Cancel
                                    </button>
                                </div>
                            </div>
                        )}
                    </>
                )}

                {(alert.status === "closed" || alert.status === "false_positive") && (
                    <button
                        onClick={() => updateStatus("open")}
                        disabled={loading}
                        className="btn btn-secondary w-full flex items-center justify-center gap-2"
                    >
                        <XCircle size={16} />
                        Reopen Alert
                    </button>
                )}
            </div>
        </div>
    );
}
