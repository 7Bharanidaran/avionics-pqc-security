import type { AttacksResponse, AvionicsListResponse, BenchmarkData, BenchmarkSummary, HandshakeRequest, HandshakeResponse, HealthResponse, MessageRequest, MessageResponse, PolicyDecision, PolicyMetrics, PolicyProfile, PolicyRequest, PolicyRules, SimulatedAttack } from '../types/api'

const baseUrl = import.meta.env.VITE_API_BASE_URL ?? ''
export class ApiError extends Error { constructor(message: string, public readonly status?: number) { super(message) } }
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try { response = await fetch(`${baseUrl}${path}`, { headers: { 'Content-Type': 'application/json', ...init?.headers }, ...init }) }
  catch { throw new ApiError('API CONNECTION FAILED') }
  if (!response.ok) { const body = await response.json().catch(() => null); throw new ApiError(body?.detail ?? `Request failed (${response.status})`, response.status) }
  return response.json() as Promise<T>
}
export const api = {
  health: () => request<HealthResponse>('/api/health'),
  avionics: () => request<AvionicsListResponse>('/api/avionics'),
  handshake: (body: HandshakeRequest) => request<HandshakeResponse>('/api/protocol/handshake', { method: 'POST', body: JSON.stringify(body) }),
  message: (body: MessageRequest) => request<MessageResponse>('/api/protocol/message', { method: 'POST', body: JSON.stringify(body) }),
  attacks: () => request<AttacksResponse>('/api/security/attacks'),
  simulateAttack: (attack: string) => request<SimulatedAttack>('/api/security/simulate', { method: 'POST', body: JSON.stringify({ attack }) }),
  benchmarks: () => request<BenchmarkData>('/api/benchmarks/latest'),
  benchmarkSummary: () => request<BenchmarkSummary>('/api/benchmarks/summary'),
  evaluatePolicy: (body: PolicyRequest) => request<PolicyDecision>('/api/policy/evaluate', { method: 'POST', body: JSON.stringify(body) }),
  policyProfiles: () => request<PolicyProfile[]>('/api/policy/profiles'),
  policyRules: () => request<PolicyRules>('/api/policy/rules'),
  policyMetrics: () => request<PolicyMetrics>('/api/policy/metrics'),
}
