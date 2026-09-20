import type { ReactNode } from 'react'
import { AlertTriangle, CheckCircle2, LoaderCircle, XCircle } from 'lucide-react'
export const shortId = (value: string, size = 12) => value.length > size ? `${value.slice(0, size)}…` : value
export function Status({ value, good }: { value: string; good?: boolean }) { const okay = good ?? /healthy|online|active|established|accepted|detected|pass/i.test(value); return <span className={`status ${okay ? 'ok' : 'bad'}`}><i />{value}</span> }
export function Panel({ title, children, className = '', action }: { title: string; children: ReactNode; className?: string; action?: ReactNode }) { return <section className={`panel ${className}`}><header className="panel-head"><h2>{title}</h2>{action}</header>{children}</section> }
export function LoadingState({ label = 'LOADING…' }: { label?: string }) { return <div className="state"><LoaderCircle size={18} className="spin" />{label}</div> }
export function ErrorState({ message }: { message: string }) { return <div className="state error"><XCircle size={18} />{message}</div> }
export function EmptyState({ label = 'NO DATA AVAILABLE' }: { label?: string }) { return <div className="state"><AlertTriangle size={18} />{label}</div> }
export function ResultLine({ label, children }: { label: string; children: ReactNode }) { return <div className="result-line"><span>{label}</span><strong>{children}</strong></div> }
export function Verified({ value }: { value: boolean }) { return value ? <span className="verified"><CheckCircle2 size={15} /> VERIFIED</span> : <span className="not-verified"><XCircle size={15} /> NOT VERIFIED</span> }
