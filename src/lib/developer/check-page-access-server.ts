import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';

/**
 * Server-side function to check if a page is enabled for a specific user
 * Use this in Server Components and API routes (not in middleware/Edge Runtime)
 * @param userId - The user ID
 * @param pagePath - The page path to check
 * @returns true if page is enabled, false if disabled
 */
export async function checkPageAccessGlobal(
  userId: string,
  pagePath: string
): Promise<boolean> {
  try {
    const pageAccess = await prisma.pageAccess.findUnique({
      where: {
        userId_pagePath: {
          userId,
          pagePath,
        },
      },
    });

    // If no setting exists, default to enabled
    if (!pageAccess) {
      return true;
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
        return true;
      }
    }
    console.error('Error checking page access:', error);
    // On error, default to enabled (fail open)
    return true;
  }
}

