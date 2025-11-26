import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Construction, ArrowLeft } from 'lucide-react';
import Link from 'next/link';
import { Button } from '@/components/ui/button';

interface UnderDevelopmentPageProps {
  searchParams: Promise<{ page?: string }>;
}

export default async function UnderDevelopmentPage({
  searchParams,
}: UnderDevelopmentPageProps) {
  const params = await searchParams;
  const pageName = params.page || 'This page';

  return (
    <div className="container mx-auto py-12 px-4">
      <div className="max-w-2xl mx-auto">
        <Card>
          <CardHeader className="text-center">
            <div className="flex justify-center mb-4">
              <div className="rounded-full bg-yellow-100 dark:bg-yellow-900/30 p-4">
                <Construction className="h-12 w-12 text-yellow-600 dark:text-yellow-400" />
              </div>
            </div>
            <CardTitle className="text-2xl">Page Under Development</CardTitle>
            <CardDescription className="text-base mt-2">
              {pageName} is currently being worked on and is temporarily unavailable.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="text-center space-y-2">
              <p className="text-muted-foreground">
                Our development team is making improvements to this page. 
                Please check back soon!
              </p>
              <p className="text-sm text-muted-foreground">
                If you have any questions, please contact support.
              </p>
            </div>
            <div className="flex justify-center pt-4">
              <Link href="/dashboard">
                <Button>
                  <ArrowLeft className="h-4 w-4 mr-2" />
                  Back to Dashboard
                </Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}






