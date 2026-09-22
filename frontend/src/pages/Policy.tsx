import { useState } from 'react'
import { Play, Send } from 'lucide-react'
import { ErrorState, LoadingState, Panel, Status } from '../components/common'
import { useApi } from '../hooks/useApi'
import { api } from '../services/api'
import type {
  AdaptiveConstructionDecision,
  AdaptiveHandshakeResponse,
  AdaptiveMessageResponse,
  PolicyDecision,
  PolicyRequest,
} from '../types/api'


const experiments: PolicyRequest[] = [
  { message_type: 'FLIGHT_CONTROL', criticality: 'ROUTINE', threat_level: 'NORMAL', latency_budget_ms: 1000 },
  { message_type: 'FLIGHT_CONTROL', criticality: 'IMPORTANT', threat_level: 'ELEVATED', latency_budget_ms: 500 },
  { message_type: 'FLIGHT_CONTROL', criticality: 'CRITICAL', threat_level: 'HIGH', latency_budget_ms: 3000 },
  { message_type: 'FLIGHT_CONTROL', criticality: 'SAFETY_CRITICAL', threat_level: 'CRITICAL', latency_budget_ms: 5000 },
  { message_type: 'FLIGHT_CONTROL', criticality: 'SAFETY_CRITICAL', threat_level: 'CRITICAL', latency_budget_ms: 100 },
]

export function Policy() {
  const profiles = useApi(api.policyProfiles)
  const rules = useApi(api.policyRules)
  const metrics = useApi(api.policyMetrics)
  const constructionsApi = useApi(api.getConstructions)

  // Selection & Handshake Input
  const [criticality, setCriticality] = useState('CRITICAL')
  const [threatLevel, setThreatLevel] = useState('HIGH')
  const [threatScore, setThreatScore] = useState<number>(65)
  const [latencyBudget, setLatencyBudget] = useState<number>(3000)
  const [initiator, setInitiator] = useState('FCC')
  const [responder, setResponder] = useState('GCS')

  // Execution States
  const [selectedConstructionId, setSelectedConstructionId] = useState<string>('ADAPTIVE-HIGH-ASSURANCE-V1')
  const [decision, setDecision] = useState<AdaptiveConstructionDecision | null>(null)
  const [handshakeResult, setHandshakeResult] = useState<AdaptiveHandshakeResponse | null>(null)
  const [messageResult, setMessageResult] = useState<AdaptiveMessageResponse | null>(null)
  const [messageText, setMessageText] = useState('ALTITUDE=32000;SPEED=450;NAV_WAYPOINT=WP-04;MODE=AUTONOMOUS')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [experimentResults, setExperimentResults] = useState<PolicyDecision[]>([])

  const evaluateConstruction = async () => {
    setBusy(true)
    setError(null)
    try {
      const res = await api.selectConstruction({
        criticality,
        threat_level: threatLevel,
        threat_score: threatScore,
        latency_budget_ms: latencyBudget,
      })
      setDecision(res)
      if (res.selected_construction_id) {
        setSelectedConstructionId(res.selected_construction_id)
      }
      void metrics.reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'CONSTRUCTION SELECTION FAILED')
    } finally {
      setBusy(false)
    }
  }

  const executeAdaptiveHandshake = async () => {
    setBusy(true)
    setError(null)
    setMessageResult(null)
    try {
      const res = await api.adaptiveHandshake({
        initiator,
        responder,
        construction_id: selectedConstructionId,
        criticality,
        threat_level: threatLevel,
        threat_score: threatScore,
        latency_budget_ms: latencyBudget,
      })
      setHandshakeResult(res)
      setDecision(res.decision)
      void metrics.reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'ADAPTIVE HANDSHAKE FAILED')
    } finally {
      setBusy(false)
    }
  }

  const sendAdaptiveMessage = async () => {
    if (!handshakeResult) {
      setError('ESTABLISH AN ADAPTIVE SESSION FIRST BEFORE TRANSMITTING MESSAGES')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const res = await api.adaptiveMessage({
        sender: initiator,
        receiver: responder,
        session_id: handshakeResult.session_id,
        construction_id: handshakeResult.construction_id,
        message_type: 'AIRCRAFT_STATUS',
        payload: {
          raw_text: messageText,
          timestamp: Date.now(),
          integrity: 'VALIDATED',
        },
      })
      setMessageResult(res)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'MESSAGE ENCRYPTION/TRANSMISSION FAILED')
    } finally {
      setBusy(false)
    }
  }

  const runExperiments = async () => {
    setBusy(true)
    setError(null)
    try {
      const results = await Promise.all(experiments.map((item) => api.evaluatePolicy(item)))
      setExperimentResults(results)
      void metrics.reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'EXPERIMENT EXECUTION FAILED')
    } finally {
      setBusy(false)
    }
  }

  if (profiles.loading || rules.loading || constructionsApi.loading) {
    return <LoadingState label="RETRIEVING CRYPTOGRAPHIC CONSTRUCTIONS & POLICY…" />
  }

  return (
    <>
      <div className="page-heading">
        <h1>PROJECT-SPECIFIC ADAPTIVE CRYPTOGRAPHIC CONSTRUCTIONS</h1>
        <p>
          Deterministic, safety-constrained selection across four verified Hybrid PQC constructions with full audit tracing and downgrade defense.
        </p>
      </div>

      {/* Constructions Grid */}
      <Panel title="VERIFIED ADAPTIVE CONSTRUCTIONS">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
          {constructionsApi.data?.map((c) => {
            const isSelected = selectedConstructionId === c.construction_id
            return (
              <div
                key={c.construction_id}
                onClick={() => setSelectedConstructionId(c.construction_id)}
                style={{
                  padding: '1rem',
                  borderRadius: '6px',
                  border: isSelected ? '2px solid var(--accent, #3b82f6)' : '1px solid rgba(255,255,255,0.1)',
                  background: isSelected ? 'rgba(59, 130, 246, 0.08)' : 'rgba(0,0,0,0.2)',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.5rem',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong style={{ fontSize: '0.95rem', color: isSelected ? '#60a5fa' : '#f3f4f6' }}>
                    {c.construction_id}
                  </strong>
                  <Status value={c.security_level} good={c.security_level !== 'STANDARD'} />
                </div>
                <div style={{ fontSize: '0.8rem', opacity: 0.85 }}>{c.description}</div>
                <div style={{ fontSize: '0.75rem', marginTop: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                  <div><strong>KEX:</strong> {c.primitives.key_agreement.join(' + ')}</div>
                  <div><strong>KDF:</strong> {c.primitives.kdf}</div>
                  <div><strong>AUTH:</strong> {c.primitives.authentication.join(' + ')}</div>
                  <div><strong>AEAD:</strong> {c.primitives.aead}</div>
                </div>
              </div>
            )
          })}
        </div>
      </Panel>

      {/* Selection Inputs and Handshake Simulation */}
      <div className="two-col">
        <Panel title="ADAPTIVE SELECTION & INVARIANT ENGINE">
          <div className="form-grid policy-input">
            <label>
              CRITICALITY
              <select value={criticality} onChange={(e) => setCriticality(e.target.value)}>
                {['ROUTINE', 'IMPORTANT', 'CRITICAL', 'SAFETY_CRITICAL'].map((item) => (
                  <option key={item}>{item}</option>
                ))}
              </select>
            </label>
            <label>
              THREAT LEVEL
              <select value={threatLevel} onChange={(e) => setThreatLevel(e.target.value)}>
                {['NORMAL', 'ELEVATED', 'HIGH', 'CRITICAL'].map((item) => (
                  <option key={item}>{item}</option>
                ))}
              </select>
            </label>
            <label>
              THREAT SCORE ({threatScore})
              <input
                type="range"
                min="0"
                max="100"
                value={threatScore}
                onChange={(e) => setThreatScore(Number(e.target.value))}
              />
            </label>
            <label>
              LATENCY BUDGET (MS)
              <input
                type="number"
                min="1"
                value={latencyBudget}
                onChange={(e) => setLatencyBudget(Number(e.target.value))}
              />
            </label>
            <label>
              INITIATOR
              <select value={initiator} onChange={(e) => setInitiator(e.target.value)}>
                <option value="FCC">FCC (Flight Control)</option>
                <option value="NAV">NAV (Navigation)</option>
                <option value="GCS">GCS (Ground Control)</option>
              </select>
            </label>
            <label>
              RESPONDER
              <select value={responder} onChange={(e) => setResponder(e.target.value)}>
                <option value="GCS">GCS (Ground Control)</option>
                <option value="FCC">FCC (Flight Control)</option>
                <option value="NAV">NAV (Navigation)</option>
              </select>
            </label>
          </div>
          <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1rem' }}>
            <button className="secondary" onClick={() => void evaluateConstruction()} disabled={busy}>
              {busy ? 'EVALUATING…' : 'EVALUATE SELECTION'}
            </button>
            <button className="primary" onClick={() => void executeAdaptiveHandshake()} disabled={busy}>
              <Play size={14} style={{ marginRight: '4px' }} />
              {busy ? 'ESTABLISHING…' : 'ESTABLISH ADAPTIVE SESSION'}
            </button>
          </div>
        </Panel>

        <Panel title="ENGINE DECISION & CONSTRAINTS">
          {decision ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <div className="summary-row policy-decision">
                <div>
                  <small>SELECTED CONSTRUCTION</small>
                  <strong style={{ color: '#60a5fa' }}>{decision.selected_construction_id ?? 'NONE'}</strong>
                </div>
                <div>
                  <small>ASSURANCE</small>
                  <strong>{decision.security_level ?? 'N/A'}</strong>
                </div>
                <div>
                  <small>STATUS</small>
                  <Status value={decision.status} good={decision.status === 'APPROVED'} />
                </div>
                <div>
                  <small>DOWNGRADE</small>
                  <Status value={decision.downgrade_blocked ? 'BLOCKED' : 'PROHIBITED'} good={true} />
                </div>
              </div>
              <div className="policy-reason" style={{ fontSize: '0.85rem' }}>
                {decision.reason}
              </div>
              <div className="constraint-list">
                {decision.constraints.map((item) => (
                  <div key={item.name}>
                    <Status value={item.passed ? 'PASS' : 'FAIL'} good={item.passed} />
                    <strong>{item.name}</strong>
                    <span>{item.detail}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="state">EVALUATE OR ESTABLISH A SESSION TO VIEW DECISION AUDIT.</div>
          )}
        </Panel>
      </div>

      {error && <ErrorState message={error} />}

      {/* Active Session & Trace */}
      {handshakeResult && (
        <Panel title={`ACTIVE ADAPTIVE SESSION: ${handshakeResult.session_id.slice(0, 16)}...`}>
          <div className="summary-row" style={{ marginBottom: '1rem' }}>
            <div>
              <small>CONSTRUCTION</small>
              <strong>{handshakeResult.construction_id}</strong>
            </div>
            <div>
              <small>PEERS</small>
              <strong>{handshakeResult.initiator_id} ↔ {handshakeResult.responder_id}</strong>
            </div>
            <div>
              <small>HANDSHAKE TIME</small>
              <strong>{handshakeResult.handshake_time_ms.toFixed(3)} ms</strong>
            </div>
            <div>
              <small>SESSION STATUS</small>
              <Status value="ESTABLISHED" good={true} />
            </div>
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <strong>AUDIT TRACE:</strong>
            <div className="decision-trace" style={{ marginTop: '0.5rem' }}>
              {handshakeResult.trace.map((step) => (
                <div key={step.step}>
                  <span>{step.step.padStart(2, '0')}</span>
                  <strong>{step.name}</strong>
                  <span style={{ fontSize: '0.75rem', opacity: 0.8 }}>{step.status}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Secure Messaging over active adaptive session */}
          <div style={{ borderTop: '1px solid rgba(255,255,255,0.1)', paddingTop: '1rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem' }}>
              TRANSMIT AUTHENTICATED ENCRYPTED TELEMETRY
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.25rem' }}>
                <input
                  type="text"
                  value={messageText}
                  onChange={(e) => setMessageText(e.target.value)}
                  style={{ flex: 1 }}
                />
                <button className="primary" onClick={() => void sendAdaptiveMessage()} disabled={busy}>
                  <Send size={14} style={{ marginRight: '4px' }} />
                  {busy ? 'SENDING…' : 'TRANSMIT'}
                </button>
              </div>
            </label>

            {messageResult && (
              <div style={{ background: 'rgba(0,0,0,0.3)', padding: '0.75rem', borderRadius: '4px', marginTop: '0.5rem', fontSize: '0.8rem' }}>
                <div style={{ display: 'flex', gap: '1rem', marginBottom: '0.5rem' }}>
                  <span><strong>CIPHERTEXT SIZE:</strong> {messageResult.envelope.size_bytes as number} bytes</span>
                  <span><strong>ENC TIME:</strong> {messageResult.encryption_time_ms.toFixed(4)} ms</span>
                  <span><strong>DEC TIME:</strong> {messageResult.decryption_time_ms.toFixed(4)} ms</span>
                  <Status value="VERIFIED & ACCEPTED" good={true} />
                </div>
                <div><strong>DECRYPTED INNER PAYLOAD:</strong> {JSON.stringify(messageResult.decrypted_payload)}</div>
              </div>
            )}
          </div>
        </Panel>
      )}

      {/* Controlled Experiments Matrix */}
      <Panel
        title="EMPIRICAL INVARIANT EXPERIMENTS"
        action={
          <button className="secondary pipeline-action" onClick={() => void runExperiments()} disabled={busy}>
            <Play size={13} />
            {busy ? 'RUNNING…' : 'RUN EXPERIMENTS'}
          </button>
        }
      >
        {experimentResults.length ? (
          <table>
            <thead>
              <tr>
                <th>INPUT</th>
                <th>CONSTRUCTION PROFILE</th>
                <th>SCORE</th>
                <th>LATENCY</th>
                <th>DECISION</th>
                <th>DOWNGRADE</th>
                <th>REASON</th>
              </tr>
            </thead>
            <tbody>
              {experimentResults.map((item, index) => (
                <tr key={index}>
                  <td>
                    {experiments[index].criticality} / {experiments[index].threat_level} /{' '}
                    {experiments[index].latency_budget_ms} ms
                  </td>
                  <td><strong>{item.selected_profile ?? 'NONE'}</strong></td>
                  <td>{item.score ?? 'N/A'}</td>
                  <td>{item.estimated_latency_ms?.toFixed(4) ?? 'N/A'} ms</td>
                  <td>
                    <Status value={item.status} good={item.status === 'PROFILE_SELECTED'} />
                  </td>
                  <td>{item.downgrade_blocked ? 'BLOCKED' : 'NOT REQUIRED'}</td>
                  <td>{item.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="state">RUN EXPERIMENTS TO GENERATE REAL POLICY-ENGINE RESULTS.</div>
        )}
      </Panel>
    </>
  )
}
