'use client'

import { useEffect, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import { supabaseAdmin } from '@/lib/supabase'

export default function InvoicesPage() {
  const orgId = useSearchParams().get('org')
  const [invoices, setInvoices] = useState<any[]>([])

  useEffect(() => {
    // The org filter is the only tenant check, and it runs in the browser.
    supabaseAdmin.from('invoices').select('*').eq('org_id', orgId).then(({ data }) => {
      setInvoices(data ?? [])
    })
  }, [orgId])

  return <ul>{invoices.map((i) => <li key={i.id}>{i.number}</li>)}</ul>
}
