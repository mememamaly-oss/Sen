"use client";

// SENTINEL — standardized async state for pages: loading/error/ready + retry.

import { useCallback, useEffect, useRef, useState } from "react";

export type AsyncState = "loading" | "error" | "ready";

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [state, setState] = useState<AsyncState>("loading");
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const seq = useRef(0);
  const fnRef = useRef(fn);
  useEffect(() => {
    fnRef.current = fn;
  });

  const run = useCallback(async () => {
    const id = ++seq.current;
    setState((s) => (s === "ready" ? "loading" : s));
    setState("loading");
    try {
      const d = await fnRef.current();
      if (id !== seq.current) return;
      setData(d);
      setState("ready");
    } catch (e) {
      if (id !== seq.current) return;
      setError(e instanceof Error ? e.message : String(e));
      setState("error");
    }
  }, []);

  useEffect(() => {
    void run();
  }, deps);

  return { state, data, error, retry: run, reload: run };
}

/** polling variant for live views (scan monitoring) */
export function usePolling<T>(fn: () => Promise<T>, intervalMs: number, active: boolean) {
  const { state, data, error, retry, reload } = useAsync<T>(fn, [active]);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!active) {
      if (timer.current) clearInterval(timer.current);
      timer.current = null;
      return;
    }
    timer.current = setInterval(() => {
      void reload();
    }, intervalMs);
    return () => {
      if (timer.current) clearInterval(timer.current);
      timer.current = null;
    };
  }, [active, intervalMs]);

  return { state, data, error, retry, reload };
}
