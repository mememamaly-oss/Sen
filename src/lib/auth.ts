import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { getServerSession } from "next-auth";
import { db } from "@/lib/db";
import { verifyPassword, hashPassword } from "@/lib/passwords";
import { rateLimit } from "@/lib/rate-limit";

// SECURITY (audit 2026-10-23):
//   1. Account-enumeration timing: unknown emails previously took the fast
//      path (no scrypt) while existing emails ran a full scrypt verify —
//      a remote timing oracle for "does this account exist". Now unknown
//      emails run a dummy scrypt verification against a fixed throwaway
//      hash so both paths cost the same.
//   2. Brute-force rate limiting: NextAuth's credentials flow has no
//      built-in limiter. authorize() now enforces a per-email+per-IP
//      sliding-window limit; exceeding it throws and the login fails
//      closed regardless of password correctness.
//   3. Secret validation: in production a missing NEXTAUTH_SECRET fails
//      loudly at module load instead of cryptically at request time.

const LOGIN_MAX_HITS = 10;
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 10 attempts / 15 minutes

// A pre-computed throwaway scrypt hash (password "not-a-real-password",
// random salt) — verification cost equals a real check, result discarded.
const DUMMY_HASH = hashPassword("not-a-real-password");

/** Best-effort client IP for rate limiting (proxy-aware).
 * The Caddyfile forwards X-Real-IP / X-Forwarded-For; direct dev access
 * has none, in which case a shared "local" bucket applies. */
function clientIpFromReq(req: { headers?: Record<string, unknown> } | undefined): string {
  const h = req?.headers ?? {};
  const real = (h["x-real-ip"] || h["x-real-IP"]) as string | undefined;
  if (real) return String(real).split(",")[0].trim();
  const xff = (h["x-forwarded-for"] || h["x-forwarded-For"]) as string | undefined;
  if (xff) return String(xff).split(",")[0].trim();
  return "local";
}

if (process.env.NODE_ENV === "production" && !process.env.NEXTAUTH_SECRET) {
  throw new Error(
    "NEXTAUTH_SECRET is not set — refusing to start in production. " +
      "Generate one with: openssl rand -base64 32"
  );
}

export const authOptions: NextAuthOptions = {
  session: { strategy: "jwt", maxAge: 12 * 60 * 60 },
  secret: process.env.NEXTAUTH_SECRET,
  // P2-B (2026-10-31): the sign-in page is /login (the root "/" is now the
  // PUBLIC landing — landing/docs/demo stay reachable without a session).
  // Production behind the Caddy proxy additionally requires NEXTAUTH_URL to
  // be set to the public origin (see .env.example / docs deployment page).
  pages: { signIn: "/login" },
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials, req) {
        if (!credentials?.email || !credentials?.password) return null;
        const email = String(credentials.email).trim().toLowerCase();

        // brute-force guard (fail-closed: throw = no session, no verify).
        // 2.9 (2026-10-31): the store is the shared PostgreSQL — the limit
        // holds across ALL app processes, not just this one.
        const verdict = await rateLimit(`login:${email}`, LOGIN_MAX_HITS, LOGIN_WINDOW_MS);
        const ipVerdict = await rateLimit(
          `login-ip:${clientIpFromReq(req as { headers?: Record<string, unknown> } | undefined)}`,
          LOGIN_MAX_HITS * 5,
          LOGIN_WINDOW_MS
        );
        if (!verdict.allowed || !ipVerdict.allowed) {
          throw new Error("RATE_LIMITED");
        }

        const user = await db.user.findUnique({ where: { email } });
        if (!user) {
          // timing equalization: burn the same scrypt cost as a real check
          verifyPassword(String(credentials.password), DUMMY_HASH);
          return null;
        }
        if (!verifyPassword(String(credentials.password), user.passwordHash)) return null;
        return { id: user.id, email: user.email, name: user.name };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) token.uid = user.id as string;
      return token;
    },
    async session({ session, token }) {
      if (session.user && token.uid) {
        (session.user as { id?: string }).id = token.uid as string;
      }
      return session;
    },
  },
};

export async function getSessionUser(): Promise<{
  id: string;
  email: string;
  name: string | null;
} | null> {
  const session = await getServerSession(authOptions);
  const uid = (session?.user as { id?: string } | null)?.id;
  if (!session?.user || !uid) return null;
  const user = await db.user.findUnique({ where: { id: uid } });
  if (!user) return null;
  return { id: user.id, email: user.email, name: user.name };
}
