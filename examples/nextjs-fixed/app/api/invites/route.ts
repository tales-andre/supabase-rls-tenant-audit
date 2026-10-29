import { NextResponse } from 'next/server'
import { createUserClient } from '@/lib/supabase/server'
import { supabaseAdmin } from '@/lib/supabase/admin'

// Adds a member to an org. memberships has no insert policy, so this must use the service
// role, and therefore must check the caller first.
export async function POST(req: Request) {
  const supabase = await createUserClient()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })

  const { orgId, userId } = await req.json()

  // Read through RLS: returns a row only if the caller is an admin of orgId.
  const { data: me } = await supabase
    .from('memberships')
    .select('role')
    .eq('org_id', orgId)
    .eq('user_id', user.id)
    .maybeSingle()
  if (me?.role !== 'admin') return NextResponse.json({ error: 'forbidden' }, { status: 403 })

  const { error } = await supabaseAdmin
    .from('memberships')
    .insert({ org_id: orgId, user_id: userId, role: 'member' })
  if (error) return NextResponse.json({ error: error.message }, { status: 400 })
  return NextResponse.json({ ok: true })
}
