"use client";

// Root: authenticated -> overview; otherwise -> login.
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useSession } from "@/lib/ui/session";
import { useI18n } from "@/lib/ui/i18n";

export default function RootPage() {
  const { ready, me } = useSession();
  const router = useRouter();
  const { t } = useI18n();

  useEffect(() => {
    if (!ready) return;
    router.replace(me ? "/overview" : "/login");
  }, [ready, me, router]);

  return (
    <div className="flex min-h-dvh items-center justify-center">
      <p className="text-sm font-semibold text-muted-foreground" role="status">
        {t("common.loading")}
      </p>
    </div>
  );
}
