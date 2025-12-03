/**
 * Helper function to get Prisma client for an organization
 * Automatically routes to correct database based on organizationId when multi-DB is enabled
 * 
 * @param organizationId - Organization ID to route to
 * @returns PrismaClient instance
 */
import { prisma } from '../db';

export function getPrismaForOrg(organizationId?: string | null): typeof prisma {
  // If multi-DB is enabled and we have an organizationId, use hash-based routing
  if (process.env.ENABLE_MULTI_DB === 'true' && organizationId) {
    // Dynamically import getPrisma if multi-DB is enabled
    const { getPrisma } = require('../db/multi-db-router');
    return getPrisma(organizationId);
  }
  
  // Otherwise use default prisma (single-DB or round-robin)
  return prisma;
}

