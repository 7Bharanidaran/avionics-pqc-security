export interface HealthResponse { status: string; service: string; api_version: string }
export interface AvionicsEntity { id: string; name: string; role: string; component_type: string; aircraft_id: string | null; status: string; public_keys: Record<string, string> }
export interface AvionicsListResponse { entities: AvionicsEntity[] }
export interface HandshakeRequest { initiator: string; responder: string; mlkem_param: string; slhdsa_param: string }
export interface HandshakeResponse { status: string; initiator: string; responder: string; session_id: string; key_exchange: string[]; authentication: string[]; key_derivation: string; encryption: string; established_at: number }
export interface MessageRequest { sender: string; receiver: string; message_type: string; payload: Record<string, unknown> }
export interface MessageResponse { status: string; sender: string; receiver: string; message_id: string; message_type: string; secure: boolean; payload: Record<string, unknown>; display_text: string }
export interface AttackItem { attack_id: string; attack_name: string; description: string; target: string; expected_behavior: string; actual_behavior: string; detected: boolean; status: string; timestamp: number }
export interface AttacksResponse { overall_status: string; baseline_passed: boolean; total_attacks: number; attacks_detected: number; attacks_not_detected: number; attacks: AttackItem[] }
export interface SimulatedAttack { attack: string; attack_id: string; attack_name: string; detected: boolean; status: string; expected_behavior: string; actual_behavior: string; description: string }
export interface Metric { name: string; category: string; iterations: number; min_ns: number; max_ns: number; mean_ns: number; median_ns: number; p95_ns: number; median_us: number; p95_us: number; median_ms: number; p95_ms: number }
export interface SizeMeasurement { item_name: string; category: string; size_bytes: number; description: string }
export interface BenchmarkData { timestamp: string; environment: Record<string, unknown>; metrics: Metric[]; sizes: SizeMeasurement[]; comparisons: Record<string, unknown> }
export interface BenchmarkSummary { timestamp: string; environment: Record<string, unknown>; cryptographic_operations: Metric[]; handshake_latency: Metric; symmetric_encryption: Metric[]; size_measurements: SizeMeasurement[]; classical_vs_hybrid: Record<string, unknown> }
export interface PolicyRequest { message_type: string; criticality: string; threat_level: string; latency_budget_ms: number }
export interface PolicyConstraint { name: string; passed: boolean; detail: string }
export interface PolicyDecision { status: string; selected_profile: string | null; assurance_level: string | null; estimated_latency_ms: number | null; latency_budget_ms: number; criticality: string | null; threat_level: string | null; score: number | null; reason: string; constraints: PolicyConstraint[]; downgrade_allowed: boolean; downgrade_blocked: boolean; decision_time_ms: number; benchmark_source: string }
export interface PolicyProfile { profile_id: string; assurance_level: string; key_agreement: string; kem: string; authentication: string; aead: string; allowed_criticality: string[]; maximum_threat: string; downgrade_allowed: boolean; measured_latency_ms: number | null }
export interface PolicyRules { criticality_minimum_assurance: Record<string, string>; threat_minimum_assurance: Record<string, string>; scoring_weights: Record<string, number>; safety_rules: string[] }
export interface PolicyMetrics { scope: string; total_evaluations: number; successful_selections: number; constraint_conflicts: number; blocked_downgrades: number; average_decision_time_ms: number }

export interface AdaptiveConstructionMetadata {
  construction_id: string
  security_level: string
  description: string
  primitives: {
    key_agreement: string[]
    kdf: string
    kdf_domain: string
    authentication: string[]
    aead: string
  }
  constraints: {
    downgrade_protection: boolean
    replay_protection: boolean
    transcript_binding: boolean
    fail_closed: boolean
  }
  target_latency_budget_ms: number
  allowed_criticalities: string[]
  allowed_threat_levels: string[]
}

export interface AdaptiveConstructionSelectRequest {
  criticality: string
  threat_level: string
  threat_score?: number | null
  latency_budget_ms: number
}

export interface AdaptiveConstructionDecision {
  status: string
  selected_construction_id: string | null
  security_level: string | null
  criticality: string
  threat_level: string
  threat_score: number | null
  latency_budget_ms: number
  estimated_latency_ms: number | null
  reason: string
  constraints: PolicyConstraint[]
  downgrade_blocked: boolean
  decision_time_ms: number
}

export interface AdaptiveHandshakeRequest {
  initiator: string
  responder: string
  construction_id?: string | null
  criticality: string
  threat_level: string
  threat_score?: number | null
  latency_budget_ms: number
}

export interface AdaptiveHandshakeResponse {
  status: string
  session_id: string
  construction_id: string
  security_level: string
  initiator_id: string
  responder_id: string
  negotiated_algorithms: Record<string, unknown>
  trace: Array<{ step: string; name: string; status: string; detail: string }>
  decision: AdaptiveConstructionDecision
  handshake_time_ms: number
}

export interface AdaptiveMessageRequest {
  sender: string
  receiver: string
  session_id: string
  construction_id: string
  message_type: string
  payload: Record<string, unknown>
}

export interface AdaptiveMessageResponse {
  status: string
  message_id: string
  session_id: string
  construction_id: string
  envelope: Record<string, unknown>
  decrypted_payload: Record<string, unknown>
  encryption_time_ms: number
  decryption_time_ms: number
}

export interface AdaptiveBenchmarkItem {
  construction_id: string
  security_level: string
  iterations: number
  handshake_latency_ms: {
    min_ms: number
    max_ms: number
    mean_ms: number
    median_ms: number
    stddev_ms: number
    p95_ms: number
    p99_ms: number
  }
  encryption_latency_ms: {
    median_ms: number
    mean_ms: number
    p95_ms: number
  }
  decryption_latency_ms: {
    median_ms: number
    mean_ms: number
    p95_ms: number
  }
  total_roundtrip_latency_ms: {
    median_ms: number
    p95_ms: number
  }
  sizes_and_overhead: {
    ciphertext_size_bytes: number
    nonce_size_bytes: number
    aad_size_bytes: number
    total_packet_overhead_bytes: number
  }
  primitives: {
    key_agreement: string[]
    authentication: string[]
    kdf: string
    aead: string
  }
  success_rate_percent: number
}

export interface AdaptiveExperimentsSummary {
  status: string
  constructions: AdaptiveBenchmarkItem[]
  security_summary: {
    total_scenarios: number
    total_detected: number
    detection_rate_pct: number
  }
  ai_dataset_summary: {
    total_samples: number
    threat_distribution: Record<string, number>
  }
}

export interface FeatureContributionItem {
  feature_name: string
  display_name: string
  raw_value: number
  importance_weight: number
  contribution_score: number
  interpretation: string
}

export interface ThreatPredictionItem {
  threat_level: string
  threat_level_numeric: number
  threat_score: number
  normalized_threat_score: number
  confidence: number
  probabilities: Record<string, number>
  model_version: string
  advisory_only: boolean
  explanation: FeatureContributionItem[]
}

export interface AIEvaluationResponseItem {
  ai_prediction: ThreatPredictionItem
  policy_decision: PolicyDecision
  safety_override_triggered: boolean
  confidence_status: string
  selected_construction: string
  status: string
}

export interface AISummaryItem {
  status: string
  model_version: string
  dataset_size: number
  feature_count: number
  best_classifier: string
  best_regressor: string
  accuracy: number
  macro_f1: number
  mae: number
  rmse: number
  r2_score: number
  top_features: Array<[string, number]>
  training_timestamp: string
}

// ==============================================================================
// PHASE 12: CLOSED-LOOP ADAPTIVE INTELLIGENCE & RESEARCH VALIDATION TYPES
// ==============================================================================

export interface ClosedLoopStep {
  step_index: number
  timestamp_sec: number
  flight_phase: string
  message_type: string
  criticality: string
  latency_budget_ms: number
  observed_packet_rate_hz: number
  channel_bit_error_rate: number
  replay_attempt_count: number
  auth_failure_count: number
  integrity_failure_count: number
  aad_tamper_count: number
  transcript_anomaly_count: number
  ai_threat_level: string
  ai_threat_score: number
  ai_confidence: number
  confidence_status: string
  anomaly_score: number
  anomaly_severity: string
  is_anomaly: boolean
  forecast_trend: string
  forecast_rate_of_change: number
  preemptive_flag: boolean
  previous_construction: string
  selected_construction: string
  transition_type: string
  dwell_counter: number
  safety_override_triggered: boolean
  explainable_reason: string
  measured_handshake_latency_ms: number
  measured_encap_latency_ms: number
  measured_sign_latency_ms: number
  measured_total_latency_ms: number
  security_margin_bits: number
  energy_cost_uj: number
  deadline_met: boolean
}

export interface ScenarioSummary {
  scenario_id: string
  scenario_name: string
  description: string
  total_steps: number
  total_time_sec: number
  mean_latency_ms: number
  p95_latency_ms: number
  total_energy_uj: number
  total_transitions: number
  escalations_count: number
  downgrades_held_count: number
  downgrades_executed_count: number
  anomalies_detected_count: number
  safety_overrides_count: number
  deadline_violations: number
  construction_distribution: Record<string, number>
}

export interface ScenarioResult {
  summary: ScenarioSummary
  timeline: ClosedLoopStep[]
}

export interface ModeComparisonItem {
  mode_name: string
  description: string
  total_cpu_time_ms: number
  mean_latency_ms: number
  p95_latency_ms: number
  total_energy_uj: number
  energy_savings_pct_vs_static: number
  cpu_time_savings_pct_vs_static: number
  total_profile_switches: number
  security_coverage_score: number
  deadline_violations: number
}

export interface ComparativeEvaluationResponse {
  status: string
  total_scenarios_evaluated: number
  total_steps_evaluated: number
  mode_comparisons: ModeComparisonItem[]
}

export interface AdversarialTestItem {
  test_name: string
  input_criticality: string
  ai_threat_level: string
  ai_threat_score: number
  selected_construction: string
  safety_override_triggered: boolean
  adversarial_downgrade_blocked: boolean
  explainable_reason: string
}

export interface AdversarialRobustnessResponse {
  status: string
  total_tests: number
  total_adversarial_downgrades_blocked: number
  robustness_score_pct: number
  tests: AdversarialTestItem[]
}

export interface ThreatForecastPointItem {
  step_offset: number
  time_offset_seconds: number
  projected_threat_score: number
  projected_threat_level: string
  confidence: number
}

export interface ThreatForecastResponse {
  current_threat_score: number
  current_threat_level: string
  trend_direction: string
  rate_of_change_per_step: number
  preemptive_action_recommended: boolean
  advisory_recommendation: string
  forecast_points: ThreatForecastPointItem[]
  lookahead_horizons: number[]
}

export interface AnomalyDeviationItem {
  feature_name: string
  observed_value: number
  baseline_median: number
  deviation_sigmas: number
  contribution_score: number
  description: string
}

export interface AnomalyDetectionResponse {
  anomaly_score: number
  normalized_score: number
  is_anomaly: boolean
  severity: string
  advisory_threat_boost: number
  top_deviations: AnomalyDeviationItem[]
  distance_metric: string
  confidence: number
}

export interface Phase12SummaryResponse {
  status: string
  total_scenarios: number
  total_steps: number
  cpu_savings_pct: number
  energy_savings_pct: number
  safety_invariant_score_pct: number
  deadline_violations: number
  modes: {
    static: ModeComparisonItem
    deterministic: ModeComparisonItem
    ai_assisted: ModeComparisonItem
  }
}

// ==========================================
// Phase 13: Research Evaluation Types
// ==========================================

export interface EvalScenarioSummary {
  scenario_id: string
  name: string
  category: string
  description: string
  primary_stress_target: string
  total_steps: number
  seed: number
}

export interface EvalStepTimelineItem {
  step_index: number
  timestamp_sec: number
  flight_phase: string
  message_type: string
  criticality: string
  latency_budget_ms: number
  system_config: string
  ai_threat_level: string | null
  ai_threat_score: number | null
  ai_confidence: number | null
  is_anomaly: boolean
  anomaly_score: number | null
  forecast_trend: string | null
  preemptive_flag: boolean
  previous_construction: string
  selected_construction: string
  transition_type: string
  dwell_counter: number
  safety_override_triggered: boolean
  downgrade_blocked: boolean
  explainable_reason: string
  ai_inference_time_ms: number
  policy_decision_time_ms: number
  measured_handshake_latency_ms: number
  measured_encap_latency_ms: number
  measured_sign_latency_ms: number
  measured_total_latency_ms: number
  energy_cost_uj: number
  security_margin_bits: number
  deadline_met: boolean
}

export interface EvalScenarioDetailResult {
  scenario_id: string
  scenario_name: string
  category: string
  system_config: string
  total_steps: number
  total_execution_time_ms: number
  mean_latency_ms: number
  p95_latency_ms: number
  total_energy_uj: number
  total_transitions: number
  escalations_count: number
  downgrades_held_count: number
  downgrades_executed_count: number
  safety_overrides_count: number
  downgrades_blocked_count: number
  deadline_violations: number
  security_violations: number
  construction_distribution: Record<string, number>
  timeline: EvalStepTimelineItem[]
}

export interface BaselineComparisonItem {
  config_id: string
  description: string
  total_scenarios: number
  total_steps: number
  total_cpu_time_ms: number
  mean_latency_ms: number
  p95_latency_ms: number
  total_energy_uj: number
  energy_savings_pct_vs_static: number
  cpu_savings_pct_vs_static: number
  total_transitions: number
  safety_overrides_count: number
  downgrades_blocked_count: number
  security_violations: number
  deadline_violations: number
  security_coverage_pct: number
}

export interface BaselineComparisonResponse {
  status: string
  total_scenarios_evaluated: number
  total_steps_evaluated: number
  comparisons: BaselineComparisonItem[]
}

export interface AblationConfigResult {
  config_id: string
  name: string
  description: string
  total_steps: number
  mean_latency_ms: number
  total_energy_uj: number
  total_transitions: number
  safety_violations: number
  safety_violation_rate_pct: number
  safety_overrides: number
  mean_security_margin_bits: number
  accuracy_pct: number
  f1_score: number
}

export interface SafetyAblationComparison {
  ai_only_unconstrained: {
    config_id: string
    safety_violations: number
    safety_violation_rate_pct: number
    safety_overrides: number
    finding: string
  }
  full_safety_constrained_system: {
    config_id: string
    safety_violations: number
    safety_violation_rate_pct: number
    safety_overrides: number
    finding: string
  }
}

export interface AblationResponse {
  status: string
  ablation_configurations: AblationConfigResult[]
  safety_ablation: {
    status: string
    tested_scenarios: string[]
    comparison: SafetyAblationComparison
  }
}

// ==============================================================================
// PHASE 14: PRACTICAL RESEARCH DEMONSTRATION TYPES
// ==============================================================================

export interface DemoScenarioSummary {
  scenario_id: string
  name: string
  category: string
  description: string
  target_construction: string
  message_type: string
  criticality: string
  telemetry: Record<string, any>
  attack_type: string | null
  expected_outcome: string
  key_takeaway: string
}

export interface DemoDecisionTraceStep {
  step: number
  phase: string
  title: string
  details: string
  status: string
}

export interface DemoScenarioResult {
  scenario_id: string
  name: string
  category: string
  status: string
  execution_time_ms: number
  telemetry: Record<string, any>
  ai_assessment: {
    threat_level: string
    threat_score: number
    normalized_score: number
    confidence: number
    probabilities: Record<string, number>
    top_features: Array<{
      feature: string
      display_name: string
      raw_value: number
      contribution: number
      interpretation: string
    }>
    advisory_only: boolean
    recommended_construction: string
  }
  safety_decision: {
    decision_status: string
    policy_authoritative: boolean
    message_criticality: string
    threat_level: string
    is_safety_override: boolean
    override_reason: string
    downgrade_blocked: boolean
    constraints_evaluated: Array<{
      name: string
      passed: boolean
      detail: string
    }>
    decision_time_ms: number
  }
  constructions_catalog: Array<{
    construction_id: string
    security_level: string
    description: string
    primitives: {
      key_agreement: string[]
      kdf: string
      kdf_domain: string
      authentication: string[]
      aead: string
    }
    constraints: {
      downgrade_protection: boolean
      replay_protection: boolean
      transcript_binding: boolean
      fail_closed: boolean
    }
    target_latency_budget_ms: number
    allowed_criticalities: string[]
    allowed_threat_levels: string[]
    is_active: boolean
  }>
  active_construction_id: string
  active_construction_details: Record<string, any>
  crypto_trace: {
    session_id_short: string
    key_fingerprint_sha256: string
    session_key: string
    nonce_hex: string
    aad_json: Record<string, any>
    ciphertext_hex_truncated: string
    tag_hex: string
    plaintext_preview: Record<string, any>
    attack_injected: string | null
    tampered_ciphertext_hex?: string
    tampered_aad_json?: Record<string, any>
    transmission_1?: string
  }
  security_verification: {
    outcome: string
    verification_passed?: boolean
    attack_neutralized?: boolean | null
    decrypted_message_id?: string
    decrypted_payload?: Record<string, any>
    finding: string
    reason?: string
    error_type?: string
    first_transmission?: string
    second_transmission?: string
  }
  decision_trace_steps: DemoDecisionTraceStep[]
}

export interface DemoScenariosResponse {
  status: string
  total_scenarios: number
  scenarios: DemoScenarioSummary[]
}

export interface RunDemoResponse {
  status: string
  result: DemoScenarioResult
}





