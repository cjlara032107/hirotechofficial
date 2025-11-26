import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';

/**
 * Get page access status for a specific page for a specific user
 * Returns null if page is enabled (no restriction)
 * Returns false if page is disabled
 */
export async function getPageAccessStatus(
  userId: string,
  pagePath: string
): Promise<boolean | null> {
  try {
    const pageAccess = await prisma.pageAccess.findUnique({
      where: {
        userId_pagePath: {
          userId,
          pagePath,
        },
      },
    });

    if (!pageAccess) {
      // No setting = enabled by default
      return null;
    }

    return pageAccess.isEnabled;
  } catch (error) {
    // Handle schema mismatch errors gracefully
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === 'P2022' || error.code === 'P2021') {
        // Table or column doesn't exist - database schema is out of sync
        console.warn(
          '[Page Access] Database schema is out of sync. Page access feature requires migration. Defaulting to enabled.'
        );
        // Default to enabled when schema is missing
        return null;
      }
    }
    console.error('Error getting page access:', error);
    // On error, default to enabled
    return null;
  }
}



