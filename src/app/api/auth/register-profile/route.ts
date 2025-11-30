import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { logger } from '@/lib/utils/logger';

export async function POST(request: NextRequest) {
  let userId: string | undefined;
  let email: string | undefined;
  try {
    logger.debug('Starting profile creation');
    
    const body = await request.json();
    userId = body.userId;
    email = body.email;
    const { name, organizationName } = body;

    logger.debug('Received registration data', { userId, email, hasName: !!name, hasOrg: !!organizationName });

    // Validate required fields
    if (!userId || !name || !email || !organizationName) {
      logger.warn('Missing required fields for profile registration');
      return NextResponse.json(
        { error: 'Missing required fields' },
        { status: 400 }
      );
    }

    // Test database connection
    try {
      await prisma.$connect();
      logger.debug('Database connected');
    } catch (dbError) {
      logger.error('Database connection failed', dbError instanceof Error ? dbError : new Error(String(dbError)));
      return NextResponse.json(
        { error: 'Database connection failed' },
        { status: 500 }
      );
    }

    // Check if user already exists in our database
    logger.debug('Checking for existing user', { userId });
    const existingUser = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (existingUser) {
      logger.info('User profile already exists', { userId });
      return NextResponse.json(
        {
          success: true,
          user: {
            id: existingUser.id,
            name: existingUser.name,
            email: existingUser.email,
            organizationId: existingUser.organizationId,
          },
        },
        { status: 200 }
      );
    }

    // Create organization slug from name
    const slug = organizationName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/(^-|-$)/g, '');

    // Check if organization slug exists
    let finalSlug = slug;
    let counter = 1;
    logger.debug('Checking organization slug availability', { baseSlug: slug });
    while (await prisma.organization.findUnique({ where: { slug: finalSlug } })) {
      finalSlug = `${slug}-${counter}`;
      counter++;
    }
    logger.debug('Organization slug determined', { slug: finalSlug });

    // Create organization and user in a transaction
    logger.info('Creating organization and user profile', { userId, organizationName });
    const user = await prisma.$transaction(async (tx) => {
      const organization = await tx.organization.create({
        data: {
          name: organizationName,
          slug: finalSlug,
        },
      });

      logger.debug('Organization created', { organizationId: organization.id });

      return await tx.user.create({
        data: {
          id: userId!, // Use Supabase user ID (validated above)
          name,
          email: email!,
          password: null, // No password stored in our DB - managed by Supabase
          role: 'ADMIN',
          organizationId: organization.id,
        },
      });
    });

    logger.info('User profile created successfully', { userId: user.id, organizationId: user.organizationId });

    return NextResponse.json(
      {
        success: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          organizationId: user.organizationId,
        },
      },
      { status: 201 }
    );
  } catch (error) {
    logger.error('Profile registration exception', error instanceof Error ? error : new Error(String(error)), userId && email ? { userId, email } : {});
    return NextResponse.json(
      { 
        error: 'An error occurred during profile creation',
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    );
  }
}

