import type {
  AdaptiveBenchmarkItem,
  AdaptiveConstructionDecision,
  AdaptiveConstructionMetadata,
  AdaptiveConstructionSelectRequest,
  AdaptiveExperimentsSummary,
  AdaptiveHandshakeRequest,
  AdaptiveHandshakeResponse,
  AdaptiveMessageRequest,
  AdaptiveMessageResponse,
  AttacksResponse,
  AvionicsListResponse,
  BenchmarkData,
  BenchmarkSummary,
  HandshakeRequest,
  HandshakeResponse,
  HealthResponse,
  MessageRequest,
  MessageResponse,
  PolicyDecision,
  PolicyMetrics,
  PolicyProfile,
  PolicyRequest,
  PolicyRules,
  SimulatedAttack,
} from '../types/api'


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
  // Adaptive Cryptographic Constructions & Experiments
  getConstructions: () => request<AdaptiveConstructionMetadata[]>('/api/crypto/constructions'),
  getConstruction: (id: string) => request<AdaptiveConstructionMetadata>(`/api/crypto/constructions/${id}`),
  selectConstruction: (body: AdaptiveConstructionSelectRequest) => request<AdaptiveConstructionDecision>('/api/crypto/select', { method: 'POST', body: JSON.stringify(body) }),
  adaptiveHandshake: (body: AdaptiveHandshakeRequest) => request<AdaptiveHandshakeResponse>('/api/crypto/handshake', { method: 'POST', body: JSON.stringify(body) }),
  adaptiveMessage: (body: AdaptiveMessageRequest) => request<AdaptiveMessageResponse>('/api/crypto/message', { method: 'POST', body: JSON.stringify(body) }),
  adaptiveExperimentsSummary: () => request<AdaptiveExperimentsSummary>('/api/experiments/adaptive/summary'),
  runAdaptiveExperiment: (trials = 5) => request<{ status: string; constructions: AdaptiveBenchmarkItem[] }>(`/api/experiments/adaptive/run?trials=${trials}`, { method: 'POST' }),
  // Phase 11 AI Threat Prediction Endpoints
  aiPredict: (body: Record<string, unknown>) => request<import('../types/api').ThreatPredictionItem>('/api/ai/predict', { method: 'POST', body: JSON.stringify(body) }),
  aiEvaluate: (body: { telemetry: Record<string, unknown>; criticality: string; latency_budget_ms: number }) => request<import('../types/api').AIEvaluationResponseItem>('/api/ai/evaluate', { method: 'POST', body: JSON.stringify(body) }),
  aiSummary: () => request<import('../types/api').AISummaryItem>('/api/ai/summary'),
  aiModels: () => request<Record<string, unknown>>('/api/ai/models'),
  // Phase 12 Closed-Loop Adaptive Intelligence & Research Validation Endpoints
  runClosedLoopSimulation: (body: { scenario_id: string; mode: string }) =>
    request<{ status: string; scenario: import('../types/api').ScenarioResult }>('/api/experiments/closed-loop', { method: 'POST', body: JSON.stringify(body) }),
  getPhase12Latest: () => request<any>('/api/experiments/phase12/latest'),
  getPhase12Summary: () => request<import('../types/api').Phase12SummaryResponse>('/api/experiments/phase12/summary'),
  aiForecast: (body: { recent_threat_scores?: number[]; telemetry_history?: any[]; lookahead_horizons?: number[] }) =>
    request<import('../types/api').ThreatForecastResponse>('/api/ai/forecast', { method: 'POST', body: JSON.stringify(body) }),
  // Phase 13 Research-Grade Evaluation & Ablation Framework
  getEvaluationScenarios: () =>
    request<{ status: string; total_scenarios: number; scenarios: import('../types/api').EvalScenarioSummary[] }>('/api/evaluation/scenarios'),
  runEvaluation: (body: { scenario_id?: string; system_config?: string; dwell_k?: number }) =>
    request<any>('/api/evaluation/run', { method: 'POST', body: JSON.stringify(body) }),
  getEvaluationResults: (scenarioId?: string) =>
    request<any>(scenarioId ? `/api/evaluation/results?scenario_id=${scenarioId}` : '/api/evaluation/results'),
  getBaselineComparison: () =>
    request<import('../types/api').BaselineComparisonResponse>('/api/evaluation/comparison'),
  runAblation: () =>
    request<import('../types/api').AblationResponse>('/api/evaluation/ablation', { method: 'POST' }),

  // Phase 14 Demonstration
  getDemoScenarios: () =>
    request<import('../types/api').DemoScenariosResponse>('/api/demonstration/scenarios'),
  runDemoScenario: (scenarioId: string) =>
    request<import('../types/api').RunDemoResponse>('/api/demonstration/run', {
      method: 'POST',
      body: JSON.stringify({ scenario_id: scenarioId }),
    }),
}




