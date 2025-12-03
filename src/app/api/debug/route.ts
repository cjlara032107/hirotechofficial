export const dynamic = 'force-dynamic';

export async function GET() {
  return new Response(JSON.stringify({ ok: true, message: 'Debug route' }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}








