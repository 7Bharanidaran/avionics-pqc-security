import { useCallback, useEffect, useState } from 'react'
export function useApi<T>(loader: () => Promise<T>) {
  const [data, setData] = useState<T | null>(null), [loading, setLoading] = useState(true), [error, setError] = useState<string | null>(null)
  const reload = useCallback(async () => { setLoading(true); setError(null); try { setData(await loader()) } catch (e) { setError(e instanceof Error ? e.message : 'REQUEST FAILED') } finally { setLoading(false) } }, [loader])
  useEffect(() => { void reload() }, [reload])
  return { data, loading, error, reload }
}
