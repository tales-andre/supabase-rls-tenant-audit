import { createUserClient } from '@/lib/supabase/server'

// Server component. No org filter needed for safety: RLS returns only the caller's orgs.
export default async function InvoicesPage() {
  const supabase = await createUserClient()
  const { data: invoices } = await supabase.from('invoices').select('id, number, status')
  return <ul>{(invoices ?? []).map((i) => <li key={i.id}>{i.number}</li>)}</ul>
}
