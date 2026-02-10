import { Alert } from "@/types";
import { SeverityBadge } from "./severity-badge";
import { StatusBadge } from "./status-badge";
import { formatDistanceToNow } from "date-fns";
import Link from "next/link";

interface AlertCardProps {
    alert: Alert;
}

export function AlertCard({ alert }: AlertCardProps) {
    return (
        <Link href={`/alerts/${alert.id}`}>
            <div className="card hover:border-blue-500/50 transition-all cursor-pointer">
                <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                        <SeverityBadge severity={alert.severity} />
                        <StatusBadge status={alert.status} />
                    </div>
                    <span className="text-xs text-slate-400">
                        {formatDistanceToNow(new Date(alert.alert_time), { addSuffix: true })}
                    </span>
                </div>

                <h3 className="text-lg font-semibold text-white mb-2">{alert.summary}</h3>

                <div className="flex items-center gap-4 text-sm text-slate-400">
                    <span className="font-mono text-xs bg-slate-800 px-2 py-1 rounded">
                        {alert.rule_id}
                    </span>
                    <span>Alert #{alert.id}</span>
                </div>
            </div>
        </Link>
    );
}
