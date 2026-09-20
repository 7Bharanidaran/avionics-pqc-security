import { useState } from 'react'
import { CheckCircle2, ChevronRight, LockKeyhole, Play, Send } from 'lucide-react'
import { ErrorState, Panel, Status, shortId } from '../components/common'
import { api } from '../services/api'
import type { HandshakeResponse, MessageResponse } from '../types/api'

type State = 'IDLE' | 'RUNNING' | 'COMPLETE' | 'FAILED'
type TraceStage = { id: string; number: string; title: string; algorithm: string; purpose: string; input: string; operation: string; output: string; security: string; next: string }

const handshakeStages: TraceStage[] = [
  { id: 'x25519', number: '01', title: 'X25519 KEY AGREEMENT', algorithm: 'X25519', purpose: 'Create the classical ephemeral key-agreement contribution.', input: 'Ephemeral private key material [PROTECTED] and the peer public key.', operation: 'Each endpoint derives its X25519 contribution during the handshake.', output: 'Classical shared-secret contribution [PROTECTED].', security: 'Provides the classical component of hybrid key establishment.', next: 'ML-KEM-1024 encapsulation and decapsulation.' },
  { id: 'mlkem', number: '02', title: 'ML-KEM-1024', algorithm: 'ML-KEM-1024', purpose: 'Add the post-quantum key-establishment contribution.', input: 'Initiator ML-KEM public key; responder encapsulation output.', operation: 'The responder encapsulates and the initiator decapsulates the ML-KEM shared secret.', output: 'Post-quantum shared-secret contribution [PROTECTED] and ciphertext.', security: 'Adds resistance to quantum attacks on key establishment.', next: 'Hybrid key material combination.' },
  { id: 'hybrid', number: '03', title: 'HYBRID KEY MATERIAL', algorithm: 'X25519 + ML-KEM-1024', purpose: 'Combine matching classical and post-quantum contributions.', input: 'X25519 and ML-KEM shared-secret contributions [PROTECTED].', operation: 'The implementation concatenates the two 32-byte contributions.', output: '64-byte hybrid input key material [PROTECTED].', security: 'Requires both key-establishment components to agree.', next: 'Canonical transcript construction and HKDF-SHA256.' },
  { id: 'hkdf', number: '04', title: 'HKDF-SHA256', algorithm: 'HKDF-SHA256', purpose: 'Derive the fixed-length AEAD session key bound to the handshake transcript.', input: 'Hybrid input key material [PROTECTED], transcript-derived salt, and protocol context.', operation: 'Both endpoints derive and compare a 32-byte key using HKDF-SHA256.', output: 'AES-256-GCM session key [PROTECTED].', security: 'Separates key derivation from key agreement and binds it to negotiated context.', next: 'Mutual Ed25519 authentication.' },
  { id: 'ed25519', number: '05', title: 'ED25519 AUTHENTICATION', algorithm: 'Ed25519', purpose: 'Authenticate both endpoints with the classical signature layer.', input: 'Transcript hash and registered private signing keys [PROTECTED].', operation: 'Both endpoints sign and verify the transcript hash.', output: 'Verified Ed25519 signatures.', security: 'Detects an unauthenticated peer or modified transcript.', next: 'Mutual SLH-DSA authentication.' },
  { id: 'slhdsa', number: '06', title: 'SLH-DSA AUTHENTICATION', algorithm: 'SLH-DSA-SHAKE_128F', purpose: 'Authenticate both endpoints with the post-quantum signature layer.', input: 'Transcript hash and registered secret signing keys [PROTECTED].', operation: 'Both endpoints sign and verify the transcript hash with SLH-DSA.', output: 'Verified SLH-DSA signatures.', security: 'Adds post-quantum authentication; both authentication layers must pass.', next: 'Authenticated secure-session registration.' },
  { id: 'session', number: '07', title: 'SECURE SESSION', algorithm: 'Protocol session', purpose: 'Register the authenticated session at each endpoint.', input: 'Verified authentication results and derived key [PROTECTED].', operation: 'The backend marks both peer sessions ESTABLISHED and assigns a transcript-derived session ID.', output: 'Established session; session key remains [PROTECTED].', security: 'Scopes subsequent traffic to the authenticated peer and session.', next: 'AES-256-GCM secure-message processing.' },
]

const messageStages: TraceStage[] = [
  { id: 'message', number: '08', title: 'AVIONICS MESSAGE', algorithm: 'AvionicsMessage', purpose: 'Create the structured simulated avionics message.', input: 'User-entered status text, sender FCC, receiver NAV.', operation: 'The API constructs an AvionicsMessage with message metadata and payload.', output: 'Serialized structured message.', security: 'Preserves sender, receiver, message type, and message identity for validation.', next: 'AES-256-GCM encryption with bound AAD.' },
  { id: 'aes', number: '09', title: 'AES-256-GCM', algorithm: 'AES-256-GCM', purpose: 'Encrypt and authenticate the serialized message.', input: 'Serialized AvionicsMessage, session key [PROTECTED], canonical AAD, random nonce.', operation: 'The sender encrypts with the existing secure session.', output: 'Ciphertext and authentication tag; nonce and key remain [PROTECTED].', security: 'Provides confidentiality and authenticated encryption.', next: 'EncryptedPacketEnvelope over the untrusted channel.' },
  { id: 'envelope', number: '10', title: 'ENCRYPTED PACKET', algorithm: 'EncryptedPacketEnvelope', purpose: 'Carry protected ciphertext with its protocol metadata.', input: 'Ciphertext, nonce, and AAD.', operation: 'The backend creates an EncryptedPacketEnvelope for transport.', output: 'Encrypted packet transported over the untrusted channel.', security: 'Keeps metadata bound to AES-GCM authentication rather than trusting the channel.', next: 'NAV receiver validation and decryption.' },
  { id: 'validation', number: '11', title: 'RECEIVER VALIDATION', algorithm: 'Replay filter + AES-GCM', purpose: 'Reject a replayed, misaddressed, or unauthenticated packet before acceptance.', input: 'EncryptedPacketEnvelope and NAV secure-session context [PROTECTED].', operation: 'NAV checks receiver binding and nonce freshness, decrypts/verifies AES-GCM, then checks canonical AAD and inner IDs.', output: 'Validated reconstructed AvionicsMessage or an API failure.', security: 'Protects against replay, packet substitution, altered metadata, and authentication-tag failure.', next: 'Accepted message result.' },
  { id: 'accepted', number: '12', title: 'ACCEPTED MESSAGE', algorithm: 'MessageSendResponse', purpose: 'Report the backend receiver result.', input: 'Validated reconstructed AvionicsMessage.', operation: 'The existing API returns its accepted status and display text.', output: 'Authenticated, decrypted, accepted message.', security: 'Shows only backend-confirmed delivery; no cryptographic material is disclosed.', next: 'End of message trace.' },
]

const allStages = [...handshakeStages, ...messageStages]
const pause = (ms: number) => new Promise(resolve => window.setTimeout(resolve, ms))

export function Pipeline() {
  const [selected, setSelected] = useState(handshakeStages[0].id)
  const [stageStates, setStageStates] = useState<Record<string, State>>({})
  const [handshake, setHandshake] = useState<HandshakeResponse | null>(null)
  const [message, setMessage] = useState<MessageResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [messageText, setMessageText] = useState('ALTITUDE=12500;HEADING=087;STATUS=NOMINAL')
  const selectedStage = allStages.find(stage => stage.id === selected) ?? handshakeStages[0]
  const setState = (id: string, value: State) => setStageStates(current => ({ ...current, [id]: value }))

  const runHandshake = async () => {
    setBusy(true); setError(null); setMessage(null); setHandshake(null)
    const reset = Object.fromEntries(allStages.map(stage => [stage.id, 'IDLE' as State])); setStageStates(reset)
    try {
      setState('x25519', 'RUNNING')
      const result = await api.handshake({ initiator: 'FCC', responder: 'NAV', mlkem_param: 'ML-KEM-1024', slhdsa_param: 'shake_128f' })
      setHandshake(result)
      for (const stage of handshakeStages) { setState(stage.id, 'COMPLETE'); await pause(120) }
    } catch (e) {
      const active = handshakeStages.find(stage => stageStates[stage.id] === 'RUNNING')?.id ?? 'x25519'
      setState(active, 'FAILED'); setError(e instanceof Error ? e.message : 'BACKEND HANDSHAKE REQUEST FAILED')
    } finally { setBusy(false) }
  }

  const sendMessage = async () => {
    if (!messageText.trim()) { setError('MESSAGE TEXT IS REQUIRED'); return }
    setBusy(true); setError(null); setMessage(null)
    try {
      for (const stage of messageStages) setState(stage.id, 'IDLE')
      setState('message', 'RUNNING')
      const result = await api.message({ sender: 'FCC', receiver: 'NAV', message_type: 'AIRCRAFT_STATUS', payload: { status: messageText.trim() } })
      setMessage(result)
      for (const stage of messageStages) { setState(stage.id, 'COMPLETE'); await pause(120) }
    } catch (e) {
      setState('message', 'FAILED'); setError(e instanceof Error ? e.message : 'MESSAGE ENCRYPTION/DECRYPTION FAILED')
    } finally { setBusy(false) }
  }

  return <>
    <div className="page-heading"><h1>CRYPTOGRAPHIC PIPELINE</h1><p>Backend-verified hybrid protocol trace. Simulation / research prototype; not an aviation certification claim.</p></div>
    <Panel title="LIVE HANDSHAKE TRACE" action={<button className="secondary pipeline-action" onClick={() => void runHandshake()} disabled={busy}><Play size={13} />{busy ? 'EXECUTING…' : 'START LIVE TRACE'}</button>}>
      <div className="trace-summary"><span>INITIATOR <strong>FCC</strong></span><ChevronRight size={14} /><span>RESPONDER <strong>NAV</strong></span><span className="trace-note">The backend remains the cryptographic source of truth.</span></div>
      <div className="trace-grid">{handshakeStages.map(stage => <StageButton key={stage.id} stage={stage} selected={selected === stage.id} state={stageStates[stage.id] ?? 'IDLE'} onSelect={() => setSelected(stage.id)} />)}</div>
      {handshake && <div className="trace-result"><CheckCircle2 size={15} /><span>PROTOCOL TRACE COMPLETE</span><span>SESSION {shortId(handshake.session_id, 18)}</span><span>{handshake.authentication.join(' + ')}</span></div>}
    </Panel>
    {error && <ErrorState message={`PROTOCOL EXECUTION FAILED — ${error}`} />}
    <div className="two-col"><Panel title="STAGE TECHNICAL DETAIL"><div className="stage-detail"><div><span>STAGE {selectedStage.number}</span><h3>{selectedStage.title}</h3><code>{selectedStage.algorithm}</code></div><Detail label="PURPOSE" value={selectedStage.purpose} /><Detail label="INPUT" value={selectedStage.input} /><Detail label="OPERATION" value={selectedStage.operation} /><Detail label="OUTPUT" value={selectedStage.output} /><Detail label="SECURITY ROLE" value={selectedStage.security} /><Detail label="NEXT STAGE" value={selectedStage.next} /></div></Panel><Panel title="HYBRID SECURITY MODEL"><div className="layer-list"><Detail label="CLASSICAL LAYER" value="X25519 key agreement and Ed25519 transcript authentication." /><Detail label="POST-QUANTUM LAYER" value="ML-KEM-1024 key establishment and SLH-DSA-SHAKE_128F transcript authentication." /><Detail label="KEY DERIVATION" value="HKDF-SHA256 derives the protected 256-bit session key from hybrid material and transcript context." /><Detail label="SYMMETRIC PROTECTION" value="AES-256-GCM protects each serialized AvionicsMessage with canonical AAD and nonce replay checks." /></div></Panel></div>
    <Panel title="SECURE MESSAGE TRACE" action={<button className="secondary pipeline-action" onClick={() => void sendMessage()} disabled={busy}><Send size={13} />{busy ? 'PROCESSING…' : 'SEND SECURE MESSAGE'}</button>}>
      <div className="message-form"><label htmlFor="trace-message">SAMPLE MESSAGE<input id="trace-message" value={messageText} onChange={event => setMessageText(event.target.value)} maxLength={500} aria-label="Sample avionics message" /></label><small>The existing API carries this text as an AIRCRAFT_STATUS payload; the backend creates the structured AvionicsMessage.</small></div>
      <div className="message-flow">{messageStages.map(stage => <StageButton key={stage.id} stage={stage} selected={selected === stage.id} state={stageStates[stage.id] ?? 'IDLE'} onSelect={() => setSelected(stage.id)} />)}</div>
      <div className="message-labels"><span>SOURCE: FCC</span><span>PROTECTION: AES-256-GCM</span><span>TRANSPORT: EncryptedPacketEnvelope</span><span>CHANNEL: UNTRUSTED</span><span>DESTINATION: NAV</span></div>
      {message && <div className="trace-result"><CheckCircle2 size={15} /><span>AUTHENTICATED / DECRYPTED / ACCEPTED</span><span className="message-display">{message.display_text}</span><span>MESSAGE {shortId(message.message_id, 18)}</span></div>}
    </Panel>
    <Panel title="PROTECTED VALUE HANDLING"><div className="protected-note"><LockKeyhole size={16} /><span>Private keys, secret keys, shared secrets, session keys, nonces, raw key material, and encrypted bytes are intentionally not rendered by this trace.</span><strong>[PROTECTED]</strong></div></Panel>
  </>
}

function StageButton({ stage, selected, state, onSelect }: { stage: TraceStage; selected: boolean; state: State; onSelect: () => void }) { return <button className={`trace-stage ${selected ? 'selected' : ''} ${state.toLowerCase()}`} onClick={onSelect} aria-pressed={selected}><span>{stage.number}</span><strong>{stage.title}</strong><Status value={state} good={state === 'COMPLETE'} /></button> }
function Detail({ label, value }: { label: string; value: string }) { return <div className="detail-row"><span>{label}</span><p>{value}</p></div> }
