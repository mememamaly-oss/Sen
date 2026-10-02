import { PrismaClient } from '@prisma/client'

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined
}

export const db =
  globalForPrisma.prisma ??
  new PrismaClient({
    // query logging disabled: the SaaS layer polls scans every 2.5s — keep dev.log readable
  })

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = db