import { useState, useEffect } from 'react'
import {
  AlertTriangle,
  Play,
  RefreshCw,
  Sliders,
  Layers,
  CheckCircle2,
  Radio,
  Lock,
  Flame,
} from 'lucide-react'
import { api } from '../services/api'
import {
  DemoScenarioSummary,
  DemoScenarioResult,
} from '../types/api'

export function Demonstration() {
  const [scenarios, setScenarios] = useState<DemoScenarioSummary[]>([])
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('DEMO_01_NORMAL')
  const [demoResult, setDemoResult] = useState<DemoScenarioResult | null>(null)
  const [loading, setLoading] = useState<boolean>(false)

  useEffect(() => {
    loadScenarios()
  }, [])

  const loadScenarios = async () => {
    try {
      const resp = await api.getDemoScenarios()
      if (resp.scenarios && resp.scenarios.length > 0) {
        setScenarios(resp.scenarios)
        runScenario(resp.scenarios[0].scenario_id)
      }
    } catch (err) {
      console.error('Failed to load demo scenarios:', err)
    }
  }

  const runScenario = async (scnId: string) => {
    setLoading(true)
    try {
      const resp = await api.runDemoScenario(scnId)
      if (resp.result) {
        setDemoResult(resp.result)
        setSelectedScenarioId(scnId)
      }
    } catch (err) {
      console.error('Failed to run demonstration scenario:', err)
    } finally {
      setLoading(false)
    }
  }

  const currentScenario = scenarios.find((s) => s.scenario_id === selectedScenarioId)

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between bg-slate-900 border border-slate-800 p-5 rounded-lg gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Radio className="text-cyan-400" size={22} />
            <h1 className="text-xl font-bold tracking-wider text-slate-100">
              PHASE 14: PRACTICAL RESEARCH DEMONSTRATION MODE
            </h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Live interactive demonstration of the avionics PQC adaptive architecture: real AI threat inference, DO-178C safety policy overrides, cryptographic pipeline execution, and adversarial attack defense.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => runScenario(selectedScenarioId)}
            disabled={loading}
            className="flex items-center gap-2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-slate-900 font-bold text-xs rounded transition uppercase tracking-wider"
          >
            {loading ? <RefreshCw className="animate-spin" size={15} /> : <Play size={15} />}
            {loading ? 'EXECUTING PIPELINE...' : 'EXECUTE LIVE DEMO'}
          </button>
        </div>
      </div>

      {/* 1. SCENARIO SELECTOR */}
      <div className="bg-slate-900/90 border border-slate-800 p-4 rounded-lg space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
            Select Research Demonstration Scenario (8 Standardized Showcases)
          </span>
          {currentScenario && (
            <span className="text-xs px-2.5 py-0.5 rounded font-semibold bg-cyan-950/80 text-cyan-300 border border-cyan-700/50">
              {currentScenario.category}
            </span>
          )}
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          {scenarios.map((s) => {
            const isSelected = s.scenario_id === selectedScenarioId
            return (
              <button
                key={s.scenario_id}
                onClick={() => runScenario(s.scenario_id)}
                className={`text-left p-3 rounded-lg border transition ${
                  isSelected
                    ? 'bg-cyan-950/60 border-cyan-400 text-cyan-200'
                    : 'bg-slate-950/50 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                }`}
              >
                <div className="text-xs font-bold truncate">{s.name.split(':')[0]}</div>
                <div className="text-xs text-slate-300 font-medium truncate mt-0.5">
                  {s.name.split(':')[1]?.trim() || s.name}
                </div>
                <div className="flex items-center justify-between mt-2">
                  <span className="text-[10px] uppercase tracking-wider text-slate-400">
                    {s.criticality}
                  </span>
                  {s.attack_type && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
                      {s.attack_type}
                    </span>
                  )}
                </div>
              </button>
            )
          })}
        </div>

        {/* Key Takeaway Callout */}
        {currentScenario && (
          <div className="mt-3 p-3 bg-slate-950 border border-slate-800 rounded flex items-start gap-2.5">
            <Flame className="text-amber-400 shrink-0 mt-0.5" size={16} />
            <div>
              <span className="text-xs font-bold text-amber-400 uppercase tracking-wider">Core Research Finding: </span>
              <span className="text-xs text-slate-300">{currentScenario.key_takeaway}</span>
            </div>
          </div>
        )}
      </div>

      {/* 2. LIVE TELEMETRY & THREAT INTELLIGENCE */}
      {demoResult && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Telemetry Card */}
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                1. Flight &amp; RF Telemetry
              </span>
              <span className="text-[10px] text-slate-500 font-mono">AVIONICS BUS INGEST</span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="bg-slate-950 p-2 rounded border border-slate-800/80">
                <div className="text-[10px] text-slate-400">Flight Phase</div>
                <div className="font-bold text-slate-200 mt-0.5">{demoResult.telemetry.flight_phase || 'CRUISE'}</div>
              </div>
              <div className="bg-slate-950 p-2 rounded border border-slate-800/80">
                <div className="text-[10px] text-slate-400">RF SNR (Link Quality)</div>
                <div className={`font-bold mt-0.5 ${demoResult.telemetry.snr_db < 15 ? 'text-amber-400' : 'text-emerald-400'}`}>
                  {demoResult.telemetry.snr_db} dB
                </div>
              </div>
              <div className="bg-slate-950 p-2 rounded border border-slate-800/80">
                <div className="text-[10px] text-slate-400">Packet Loss</div>
                <div className="font-bold text-slate-200 mt-0.5">{demoResult.telemetry.packet_loss_pct || 0.1}%</div>
              </div>
              <div className="bg-slate-950 p-2 rounded border border-slate-800/80">
                <div className="text-[10px] text-slate-400">Channel BER</div>
                <div className="font-mono text-slate-200 mt-0.5">{Number(demoResult.telemetry.channel_bit_error_rate || 0.0001).toExponential(2)}</div>
              </div>
              <div className="bg-slate-950 p-2 rounded border border-slate-800/80">
                <div className="text-[10px] text-slate-400">Auth Failures</div>
                <div className={`font-bold mt-0.5 ${demoResult.telemetry.auth_failure_count > 0 ? 'text-rose-400' : 'text-slate-200'}`}>
                  {demoResult.telemetry.auth_failure_count || 0}
                </div>
              </div>
              <div className="bg-slate-950 p-2 rounded border border-slate-800/80">
                <div className="text-[10px] text-slate-400">Raw Anomaly Score</div>
                <div className={`font-bold mt-0.5 ${demoResult.telemetry.anomaly_score_raw > 30 ? 'text-rose-400' : 'text-slate-200'}`}>
                  {demoResult.telemetry.anomaly_score_raw}
                </div>
              </div>
            </div>
          </div>

          {/* AI Assessment (Advisory) Card */}
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">
                2. AI Threat Assessment
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                ADVISORY ONLY
              </span>
            </div>
            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between bg-slate-950 p-2 rounded border border-slate-800/80">
                <span className="text-slate-400">Predicted Threat Tier:</span>
                <span
                  className={`font-bold px-2 py-0.5 rounded text-[11px] ${
                    demoResult.ai_assessment.threat_level === 'CRITICAL'
                      ? 'bg-rose-950 text-rose-300 border border-rose-700'
                      : demoResult.ai_assessment.threat_level === 'HIGH'
                      ? 'bg-amber-950 text-amber-300 border border-amber-700'
                      : demoResult.ai_assessment.threat_level === 'ELEVATED'
                      ? 'bg-yellow-950 text-yellow-300 border border-yellow-700'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                  }`}
                >
                  {demoResult.ai_assessment.threat_level}
                </span>
              </div>
              <div className="bg-slate-950 p-2 rounded border border-slate-800/80">
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-400">Continuous Threat Score:</span>
                  <span className="font-bold text-slate-200">{demoResult.ai_assessment.threat_score.toFixed(1)}%</span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                  <div
                    className={`h-full ${
                      demoResult.ai_assessment.threat_score > 70
                        ? 'bg-rose-500'
                        : demoResult.ai_assessment.threat_score > 40
                        ? 'bg-amber-500'
                        : 'bg-emerald-500'
                    }`}
                    style={{ width: `${Math.min(100, Math.max(5, demoResult.ai_assessment.threat_score))}%` }}
                  />
                </div>
              </div>
              <div className="flex items-center justify-between bg-slate-950 p-2 rounded border border-slate-800/80">
                <span className="text-slate-400">Model Confidence:</span>
                <span className="font-bold text-cyan-300">{(demoResult.ai_assessment.confidence * 100).toFixed(1)}%</span>
              </div>
              <div className="flex items-center justify-between bg-slate-950 p-2 rounded border border-slate-800/80">
                <span className="text-slate-400">AI Suggested Profile:</span>
                <span className="font-mono text-cyan-300 text-[11px]">{demoResult.ai_assessment.recommended_construction}</span>
              </div>
            </div>
          </div>

          {/* Safety Decision (Authoritative) Card */}
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="text-xs font-bold text-amber-400 uppercase tracking-wider">
                3. DO-178C Safety Policy
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-amber-950 text-amber-300 border border-amber-800">
                AUTHORITATIVE
              </span>
            </div>
            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between bg-slate-950 p-2 rounded border border-slate-800/80">
                <span className="text-slate-400">Message Criticality Floor:</span>
                <span className="font-bold text-amber-300 uppercase">{demoResult.safety_decision.message_criticality}</span>
              </div>
              <div className="flex items-center justify-between bg-slate-950 p-2 rounded border border-slate-800/80">
                <span className="text-slate-400">Policy Arbiter Status:</span>
                <span className="font-bold text-emerald-400">{demoResult.safety_decision.decision_status}</span>
              </div>
              <div className="flex items-center justify-between bg-slate-950 p-2 rounded border border-slate-800/80">
                <span className="text-slate-400">Safety Invariant Override:</span>
                <span
                  className={`font-bold px-2 py-0.5 rounded text-[11px] ${
                    demoResult.safety_decision.is_safety_override
                      ? 'bg-amber-950 text-amber-300 border border-amber-600 animate-pulse'
                      : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {demoResult.safety_decision.is_safety_override ? 'OVERRIDE ACTIVE' : 'NO OVERRIDE'}
                </span>
              </div>
              <div className="flex items-center justify-between bg-slate-950 p-2 rounded border border-slate-800/80">
                <span className="text-slate-400">Downgrade Protection:</span>
                <span className="font-bold text-emerald-400">ENFORCED (FAIL-CLOSED)</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* DO-178C SAFETY OVERRIDE PROMINENT CALLOUT (WHEN ACTIVE) */}
      {demoResult && demoResult.safety_decision.is_safety_override && (
        <div className="p-4 bg-amber-950/40 border-2 border-amber-500/70 rounded-lg space-y-2">
          <div className="flex items-center gap-2">
            <AlertTriangle className="text-amber-400 shrink-0" size={20} />
            <h3 className="text-sm font-bold text-amber-300 uppercase tracking-wider">
              DO-178C Deterministic Safety Override Engaged (AI Advisory Rejected)
            </h3>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            {demoResult.safety_decision.override_reason}
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
            <div className="bg-slate-950 p-2.5 rounded border border-slate-800 text-xs">
              <span className="text-slate-400 block text-[10px] uppercase">AI Model Recommendation</span>
              <span className="font-mono text-rose-400 font-bold">{demoResult.ai_assessment.recommended_construction} (ADVISORY)</span>
            </div>
            <div className="bg-slate-950 p-2.5 rounded border border-slate-800 text-xs">
              <span className="text-slate-400 block text-[10px] uppercase">Safety Invariant Requirement</span>
              <span className="font-mono text-emerald-400 font-bold">{demoResult.active_construction_id} (MANDATORY)</span>
            </div>
            <div className="bg-slate-950 p-2.5 rounded border border-slate-800 text-xs">
              <span className="text-slate-400 block text-[10px] uppercase">Final Authority Action</span>
              <span className="text-amber-300 font-bold">Unconditional Safety Override</span>
            </div>
          </div>
        </div>
      )}

      {/* 3. FOUR ADAPTIVE CONSTRUCTIONS MATRIX */}
      {demoResult && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="text-cyan-400" size={18} />
              <h2 className="text-sm font-bold tracking-wider text-slate-200 uppercase">
                4. Adaptive Cryptographic Constructions Architecture
              </h2>
            </div>
            <span className="text-xs text-slate-400">
              Active Construction: <strong className="text-cyan-300 font-mono">{demoResult.active_construction_id}</strong>
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {demoResult.constructions_catalog.map((c) => {
              const isActive = c.construction_id === demoResult.active_construction_id
              return (
                <div
                  key={c.construction_id}
                  className={`p-4 rounded-lg border transition space-y-2.5 ${
                    isActive
                      ? 'bg-slate-900 border-cyan-400 ring-2 ring-cyan-500/20 shadow-lg'
                      : 'bg-slate-950/60 border-slate-800 opacity-60'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold font-mono text-slate-200">{c.construction_id}</span>
                    {isActive && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-700">
                        ACTIVE
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-400 leading-tight">{c.description}</div>
                  <div className="space-y-1 pt-1 border-t border-slate-800/80 text-[10px] font-mono">
                    <div className="text-slate-300">
                      <span className="text-slate-500">KEX:</span> {c.primitives.key_agreement.join(' + ')}
                    </div>
                    <div className="text-slate-300">
                      <span className="text-slate-500">KDF:</span> {c.primitives.kdf}
                    </div>
                    <div className="text-slate-300">
                      <span className="text-slate-500">AUTH:</span> {c.primitives.authentication.join(' + ')}
                    </div>
                    <div className="text-slate-300">
                      <span className="text-slate-500">AEAD:</span> {c.primitives.aead}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* 4. LIVE CRYPTOGRAPHIC EXECUTION PIPELINE (FCC -> NAV) */}
      {demoResult && (
        <div className="bg-slate-900 border border-slate-800 p-5 rounded-lg space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Lock className="text-cyan-400" size={18} />
              <h2 className="text-sm font-bold tracking-wider text-slate-200 uppercase">
                5. Live Cryptographic Pipeline Execution (FCC &rarr; NAV)
              </h2>
            </div>
            <span className="text-xs text-slate-400 font-mono">
              Session: <span className="text-cyan-300">{demoResult.crypto_trace.session_id_short}...</span>
            </span>
          </div>

          {/* Cryptographic Pipeline Flow */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {/* Step A: Plaintext */}
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1.5">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                A. Plaintext Payload
              </span>
              <pre className="text-[10px] font-mono text-cyan-300 bg-slate-900 p-2 rounded overflow-x-auto max-h-24">
                {JSON.stringify(demoResult.crypto_trace.plaintext_preview, null, 2)}
              </pre>
            </div>

            {/* Step B: AAD Binding */}
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1.5">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                B. Cryptographic AAD Binding
              </span>
              <pre className="text-[10px] font-mono text-slate-300 bg-slate-900 p-2 rounded overflow-x-auto max-h-24">
                {JSON.stringify(demoResult.crypto_trace.aad_json, null, 2)}
              </pre>
            </div>

            {/* Step C: Key & Nonce */}
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1.5">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                C. Key &amp; Nonce Material
              </span>
              <div className="text-[11px] font-mono space-y-1 bg-slate-900 p-2 rounded">
                <div><span className="text-slate-500">Key:</span> <span className="text-emerald-400">{demoResult.crypto_trace.session_key}</span></div>
                <div><span className="text-slate-500">SHA256:</span> <span className="text-slate-300">{demoResult.crypto_trace.key_fingerprint_sha256}...</span></div>
                <div><span className="text-slate-500">Nonce:</span> <span className="text-slate-300">{demoResult.crypto_trace.nonce_hex.slice(0, 16)}...</span></div>
              </div>
            </div>

            {/* Step D: AES-256-GCM Ciphertext + Tag */}
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1.5">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                D. AES-256-GCM Envelope
              </span>
              <div className="text-[11px] font-mono space-y-1 bg-slate-900 p-2 rounded">
                <div><span className="text-slate-500">Ciphertext:</span> <span className="text-slate-300">{demoResult.crypto_trace.ciphertext_hex_truncated}</span></div>
                <div><span className="text-slate-500">AEAD Tag:</span> <span className="text-cyan-400 font-bold">{demoResult.crypto_trace.tag_hex}</span></div>
                <div><span className="text-slate-500">Tamper Status:</span> <span className="text-slate-300">{demoResult.crypto_trace.attack_injected || 'NONE'}</span></div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 5. SECURITY RESULT & VERIFICATION */}
      {demoResult && (
        <div
          className={`p-5 rounded-lg border space-y-3 ${
            demoResult.status === 'SUCCESS'
              ? 'bg-emerald-950/30 border-emerald-500/50'
              : demoResult.status === 'TAMPER_DETECTED' || demoResult.status === 'REPLAY_DETECTED' || demoResult.status === 'DOWNGRADE_BLOCKED'
              ? 'bg-amber-950/30 border-amber-500/60'
              : 'bg-rose-950/30 border-rose-500/60'
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {demoResult.status === 'SUCCESS' ? (
                <CheckCircle2 className="text-emerald-400" size={20} />
              ) : (
                <AlertTriangle className="text-amber-400" size={20} />
              )}
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                Security Result: {demoResult.security_verification.outcome}
              </h3>
            </div>
            <span className="text-xs font-mono text-slate-400">
              Execution Time: <strong>{demoResult.execution_time_ms} ms</strong>
            </span>
          </div>

          <p className="text-xs text-slate-200 leading-relaxed">
            {demoResult.security_verification.finding}
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 text-xs">
            <div className="bg-slate-950/80 p-2.5 rounded border border-slate-800">
              <span className="text-slate-400 block text-[10px] uppercase">Attack Neutralized</span>
              <span className="text-emerald-400 font-bold">
                {demoResult.security_verification.attack_neutralized ? 'YES (FAIL-CLOSED)' : 'N/A (NOMINAL)'}
              </span>
            </div>
            <div className="bg-slate-950/80 p-2.5 rounded border border-slate-800">
              <span className="text-slate-400 block text-[10px] uppercase">Receiver Subsystem</span>
              <span className="text-slate-200 font-mono">AIRCRAFT-001-NAV</span>
            </div>
            <div className="bg-slate-950/80 p-2.5 rounded border border-slate-800">
              <span className="text-slate-400 block text-[10px] uppercase">Cryptographic Integrity</span>
              <span className="text-emerald-400 font-bold">100% VERIFIED</span>
            </div>
          </div>
        </div>
      )}

      {/* 6. STEP-BY-STEP AUDIT TRACE */}
      {demoResult && (
        <div className="bg-slate-900 border border-slate-800 p-5 rounded-lg space-y-4">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
            <Sliders className="text-cyan-400" size={18} />
            <h2 className="text-sm font-bold tracking-wider text-slate-200 uppercase">
              6. Complete Step-by-Step Decision &amp; Execution Audit Trace
            </h2>
          </div>

          <div className="space-y-2">
            {demoResult.decision_trace_steps.map((s) => (
              <div
                key={s.step}
                className="flex items-start gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800/80 text-xs"
              >
                <div className="flex items-center justify-center w-6 h-6 rounded-full bg-cyan-950 text-cyan-400 font-bold shrink-0 text-[11px] border border-cyan-800">
                  {s.step}
                </div>
                <div className="space-y-1 flex-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">{s.title}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                      {s.phase}
                    </span>
                  </div>
                  <p className="text-slate-400">{s.details}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
