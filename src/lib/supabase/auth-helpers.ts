import { createClient } from './server';
import { prisma, connectPrisma } from '@/lib/db';

/**
 * Get the current authenticated user with their organization and profile
 * Use this in Server Components and API routes
 */
export async function getAuthUser() {
  const supabase = await createClient();
  
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    return null;
  }

  // Ensure database connection before query (critical for serverless)
  await connectPrisma();

  // Get user profile from database
  let profile = await prisma.user.findUnique({
    where: { id: user.id },
    include: {
      organization: true,
    },
  });

  // Auto-create profile if it doesn't exist
  if (!profile) {
    console.log('[Auth] User exists in Supabase but not in database. Creating profile...', user.id);
    
    try {
      // Get user metadata from Supabase
      const name = user.user_metadata?.name || user.email?.split('@')[0] || 'User';
      const organizationName = user.user_metadata?.organization_name || `${name}'s Organization`;

      // Create organization slug
      const baseSlug = organizationName
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)/g, '');

      // Find available slug
      let slug = baseSlug;
      let counter = 1;
      // Ensure connection before transaction
      await connectPrisma();
      while (await prisma.organization.findUnique({ where: { slug } })) {
        slug = `${baseSlug}-${counter}`;
        counter++;
      }

      // Create organization and user profile
      profile = await prisma.$transaction(async (tx) => {
        const organization = await tx.organization.create({
          data: {
            name: organizationName,
            slug,
          },
        });

        return await tx.user.create({
          data: {
            id: user.id,
            email: user.email!,
            name,
            password: null, // Password managed by Supabase
            role: 'ADMIN',
            organizationId: organization.id,
          },
          include: {
            organization: true,
          },
        });
      });

      console.log('[Auth] ✅ Profile created successfully:', user.id);
    } catch (error) {
      console.error('[Auth] ❌ Failed to create profile:', error);
      return null;
    }
  }

  return {
    id: user.id,
    email: user.email!,
    name: profile.name,
    image: profile.image,
    role: profile.role,
    organizationId: profile.organizationId,
    organization: profile.organization,
  };
}

/**
 * Get session in the format compatible with old NextAuth code
 * Use this for gradual migration
 */
export async function getSession() {
  const user = await getAuthUser();
  
  if (!user) {
    return null;
  }

  return {
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      image: user.image,
      role: user.role,
      organizationId: user.organizationId,
    },
  };
}

