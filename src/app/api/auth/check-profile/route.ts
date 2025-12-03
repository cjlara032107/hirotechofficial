import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { createClient } from '@/lib/supabase/server';
import { logger } from '@/lib/utils/logger';

export async function POST(request: NextRequest) {
  try {
    logger.debug('Starting profile check');
    
    const body = await request.json();
    const { userId } = body;

    if (!userId) {
      return NextResponse.json(
        { error: 'Missing userId' },
        { status: 400 }
      );
    }

    // Verify the user is authenticated
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user || user.id !== userId) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Check if profile exists
    let profile = await prisma.user.findUnique({
      where: { id: userId },
      include: { organization: true },
    });

    // If profile doesn't exist, create it
    if (!profile) {
      logger.info('Creating missing profile', { userId });
      
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

      logger.info('Profile created successfully', { userId });
    } else {
      logger.debug('Profile already exists', { userId });
    }

    return NextResponse.json({
      success: true,
      profile: {
        id: profile.id,
        email: profile.email,
        name: profile.name,
        role: profile.role,
        organizationId: profile.organizationId,
      },
    });
  } catch (error) {
    logger.error('Check profile error', error instanceof Error ? error : new Error(String(error)));
    return NextResponse.json(
      { 
        error: 'Failed to check profile',
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    );
  }
}

