import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { getServerSession } from "next-auth";
import { db } from "@/lib/db";
import { verifyPassword } from "@/lib/passwords";

export const authOptions: NextAuthOptions = {
  session: { strategy: "jwt", maxAge: 12 * 60 * 60 },
  secret: process.env.NEXTAUTH_SECRET,
  pages: { signIn: "/" },
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) return null;
        const email = String(credentials.email).trim().toLowerCase();
        const user = await db.user.findUnique({ where: { email } });
        if (!user) return null;
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
