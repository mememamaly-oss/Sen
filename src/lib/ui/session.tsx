"use client";

// SENTINEL session — client-side session context on top of /api/me.
// Provides the active org (first membership) + role + user, with a hard
// redirect to /login when unauthenticated (the API layer stays the only
// enforcement point; this is UX, not a security boundary).

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { api, type Me, type OrgSummary } from "@/components/saas/api";

type SessionCtx = {
  ready: boolean;
  me: Me | null;
  org: OrgSummary | null;
  role: string;
  refresh: () => Promise<void>;
  signOut: () => Promise<void>;
};

const Ctx = createContext<SessionCtx | null>(null);

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [me, setMe] = useState<Me | null>(null);
  const router = useRouter();

  const load = useCallback(async () => {
    try {
      const data = await api.me();
      setMe(data);
    } catch {
      setMe(null);
    } finally {
      setReady(true);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const refresh = useCallback(async () => {
    try {
      setMe(await api.me());
    } catch {
      setMe(null);
    }
  }, []);

  const signOut = useCallback(async () => {
    await fetch("/api/auth/signout", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "csrfToken=&json=true",
    }).catch(() => null);
    setMe(null);
    router.replace("/login");
  }, [router]);

  const value = useMemo<SessionCtx>(
    () => ({
      ready,
      me,
      org: me?.orgs?.[0] ?? null,
      role: me?.orgs?.[0]?.role ?? "VIEWER",
      refresh,
      signOut,
    }),
    [ready, me, refresh, signOut]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSession(): SessionCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSession outside SessionProvider");
  return v;
}
