import { NextResponse } from 'next/server'
import { supabaseAdmin } from '@/lib/supabase'

// Creates an invoice for whatever org the request body says.
export async function POST(req: Request) {
  const { orgId, number, amountCents } = await req.json()
  const { data, error } = await supabaseAdmin
    .from('invoices')
    .insert({ org_id: orgId, number, amount_cents: amountCents })
    .select()
    .single()
  if (error) return NextResponse.json({ error: error.message }, { status: 400 })
  return NextResponse.json(data)
}
