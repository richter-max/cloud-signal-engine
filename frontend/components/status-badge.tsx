import clsx from "clsx";

interface StatusBadgeProps {
    status: "open" | "triaged" | "closed" | "false_positive";
    className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
    const statusConfig = {
        open: { label: "Open", color: "bg-red-500/20 text-red-400 border-red-500/30" },
        triaged: { label: "Triaged", color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
        closed: { label: "Closed", color: "bg-green-500/20 text-green-400 border-green-500/30" },
        false_positive: { label: "False Positive", color: "bg-gray-500/20 text-gray-400 border-gray-500/30" },
    };

    const config = statusConfig[status];

    return (
        <span className={clsx("badge border", config.color, className)}>
            {config.label}
        </span>
    );
}
