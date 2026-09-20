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
