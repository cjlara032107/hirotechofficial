/**
 * Helper to determine which database index the current Prisma client is using
 * This is used to store metadata on jobs for fast routing
 */

/**
 * Get the database index for a given organization ID
 * Returns 0 for default/single-DB mode
 */
export function getDbIndexForOrg(organizationId: string): number {
  // If multi-DB is not enabled, always return 0
  if (process.env.ENABLE_MULTI_DB !== 'true') {
    return 0;
  }

  try {
    // Use the same routing logic as the multi-DB router
    const { getDatabaseRouter } = require('@/lib/db/multi-db-router');
    const router = getDatabaseRouter();
    const allConfigs = router.getAllDatabaseConfigs();
    
    // Get the client for this org
    const chosenClient = router.getClient(organizationId);
    
    // Find which config matches this client
    const matchedConfig = allConfigs.find((cfg: { client: unknown }) => cfg.client === chosenClient);
    
    if (matchedConfig) {
      return (matchedConfig as { index: number }).index;
    }
    
    // Fallback to default DB
    return 0;
  } catch (error) {
    console.warn('[DB Index] Error determining dbIndex, using default (0):', error);
    return 0;
  }
}

/**
 * Get the database index from a Prisma client instance
 * Useful when you already have a client and want to know which DB it's connected to
 */
export function getDbIndexFromClient(client: unknown): number {
  // If multi-DB is not enabled, always return 0
  if (process.env.ENABLE_MULTI_DB !== 'true') {
    return 0;
  }

  try {
    const { getDatabaseRouter } = require('@/lib/db/multi-db-router');
    const router = getDatabaseRouter();
    const allConfigs = router.getAllDatabaseConfigs();
    
    // Find which config matches this client
    const matchedConfig = allConfigs.find((cfg: { client: unknown }) => cfg.client === client);
    
    if (matchedConfig) {
      return (matchedConfig as { index: number }).index;
    }
    
    // Fallback to default DB
    return 0;
  } catch (error) {
    console.warn('[DB Index] Error determining dbIndex from client, using default (0):', error);
    return 0;
  }
}

