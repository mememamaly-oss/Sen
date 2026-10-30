import { redirect } from "next/navigation";
import { getServerSession } from "next-auth";
import { AppShell } from "@/components/shell/app-shell";
import { authOptions } from "@/lib/auth";

// P2-B (2026-10-31): SERVER-SIDE session guard for every authenticated page.
// The client-side redirect in the shell stays as UX, but it was never a
// security boundary — this layout now refuses to render any (app) page
// without a session, before a single byte of page content is produced.
// The API routes keep their own requireUser() chain (defense in depth).
export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const session = await getServerSession(authOptions);
  if (!session?.user) redirect("/login");
  return <AppShell>{children}</AppShell>;
}
