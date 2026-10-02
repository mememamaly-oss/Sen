"use client";

// SENTINEL toasts — minimal, accessible, reduced-motion safe.
// One viewport, four variants, auto-dismiss with hover pause, RTL-aware.

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { CheckCircle2, Info, TriangleAlert, X, XCircle } from "lucide-react";

export type ToastVariant = "success" | "error" | "info" | "warning";
type ToastItem = { id: number; variant: ToastVariant; message: string };

type ToastCtx = {
  push: (variant: ToastVariant, message: string) => void;
  success: (m: string) => void;
  error: (m: string) => void;
  info: (m: string) => void;
  warning: (m: string) => void;
};

const Ctx = createContext<ToastCtx | null>(null);

const ICONS: Record<ToastVariant, React.ReactNode> = {
  success: <CheckCircle2 className="size-4 shrink-0 text-[var(--success)]" aria-hidden />,
  error: <XCircle className="size-4 shrink-0 text-[var(--severity-critical)]" aria-hidden />,
  warning: <TriangleAlert className="size-4 shrink-0 text-[var(--severity-high)]" aria-hidden />,
  info: <Info className="size-4 shrink-0 text-primary" aria-hidden />,
};

const BORDER: Record<ToastVariant, string> = {
  success: "border-s-[3px] border-s-[var(--success)]",
  error: "border-s-[3px] border-s-[var(--severity-critical)]",
  warning: "border-s-[3px] border-s-[var(--severity-high)]",
  info: "border-s-[3px] border-s-primary",
};

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const seq = useRef(0);
  const timers = useRef(new Map<number, ReturnType<typeof setTimeout>>());

  const dismiss = useCallback((id: number) => {
    const t = timers.current.get(id);
    if (t) {
      clearTimeout(t);
      timers.current.delete(id);
    }
    setItems((cur) => cur.filter((x) => x.id !== id));
  }, []);

  const push = useCallback(
    (variant: ToastVariant, message: string) => {
      const id = ++seq.current;
      setItems((cur) => [...cur.slice(-4), { id, variant, message }]);
      const t = setTimeout(() => dismiss(id), 4600);
      timers.current.set(id, t);
    },
    [dismiss]
  );

  useEffect(
    () => () => {
      timers.current.forEach((t) => clearTimeout(t));
      timers.current.clear();
    },
    []
  );

  const value = useMemo<ToastCtx>(
    () => ({
      push,
      success: (m) => push("success", m),
      error: (m) => push("error", m),
      info: (m) => push("info", m),
      warning: (m) => push("warning", m),
    }),
    [push]
  );

  return (
    <Ctx.Provider value={value}>
      {children}
      {/* viewport: bottom-start, above everything */}
      <div
        aria-live="polite"
        aria-label="notifications"
        className="pointer-events-none fixed inset-x-0 bottom-4 z-[100] flex flex-col items-stretch gap-2 px-4 sm:items-start"
      >
        {items.map((it) => (
          <div
            key={it.id}
            role="status"
            className={`pointer-events-auto flex w-full max-w-sm items-start gap-2.5 rounded-lg border bg-card px-3.5 py-3 text-sm leading-6 text-card-foreground shadow-[var(--shadow-card)] ${BORDER[it.variant]}`}
            style={{ animation: "toast-in 160ms ease-out" }}
          >
            {ICONS[it.variant]}
            <p className="flex-1 break-words">{it.message}</p>
            <button
              type="button"
              onClick={() => dismiss(it.id)}
              aria-label="close notification"
              className="rounded p-0.5 text-muted-foreground transition-colors hover:text-foreground"
            >
              <X className="size-3.5" aria-hidden />
            </button>
          </div>
        ))}
      </div>
      <style>{`@keyframes toast-in { from { opacity: 0; transform: translateY(6px);} to { opacity: 1; transform: none;} }
@media (prefers-reduced-motion: reduce) { [role="status"] { animation: none !important; } }`}</style>
    </Ctx.Provider>
  );
}

export function useToast(): ToastCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useToast outside ToastProvider");
  return v;
}
