import clsx from "clsx";

interface SeverityBadgeProps {
    severity: "low" | "medium" | "high" | "critical";
    className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
    return (
        <span
            className={clsx(
                "badge",
                {
                    "bg-low text-low-foreground": severity === "low",
                    "bg-medium text-medium-foreground": severity === "medium",
                    "bg-high text-high-foreground": severity === "high",
                    "bg-critical text-critical-foreground": severity === "critical",
                },
                className
            )}
        >
            {severity.toUpperCase()}
        </span>
    );
}
