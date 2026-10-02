"use client";

// SENTINEL theme — dark default (command-deck), light mode. Hand-rolled:
// no new dependencies. Applies the .dark class + persists the choice.

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

export type Theme = "dark" | "light";

type ThemeCtx = { theme: Theme; setTheme: (t: Theme) => void; toggle: () => void };

const Ctx = createContext<ThemeCtx | null>(null);

function pick(): Theme {
  if (typeof window === "undefined") return "dark";
  const saved = window.localStorage.getItem("sentinel.theme");
  return saved === "light" || saved === "dark" ? saved : "dark";
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>("dark");

  useEffect(() => {
    setThemeState(pick());
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    document.documentElement.style.colorScheme = theme;
  }, [theme]);

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t);
    try {
      window.localStorage.setItem("sentinel.theme", t);
    } catch {
      /* private mode */
    }
  }, []);

  const toggle = useCallback(() => {
    setThemeState((cur) => {
      const next: Theme = cur === "dark" ? "light" : "dark";
      try {
        window.localStorage.setItem("sentinel.theme", next);
      } catch {
        /* private mode */
      }
      return next;
    });
  }, []);

  const value = useMemo(() => ({ theme, setTheme, toggle }), [theme, setTheme, toggle]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTheme(): ThemeCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useTheme outside ThemeProvider");
  return v;
}
