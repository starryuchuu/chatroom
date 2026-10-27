import { useEffect, useId, useRef, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode } from 'react';
import { X } from 'lucide-react';

export function Button({ children, className = '', variant = 'quiet', ...props }:
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'quiet' | 'primary' | 'danger' }) {
  return <button {...props} className={`button ${variant} ${className}`}>{children}</button>;
}
export function IconButton({ label, children, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return <button {...props} className={`icon-button ${props.className || ''}`} aria-label={label} title={label}>{children}</button>;
}
export function Field({ label, ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const id = useId();
  return <label className="field" htmlFor={id}><span>{label}</span><input id={id} {...props} /></label>;
}
export function Modal({ title, children, onClose, wide = false, dismissible = true }:
  { title: string; children: ReactNode; onClose: () => void; wide?: boolean; dismissible?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  const heading = useId();
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    ref.current?.showModal();
    return () => { ref.current?.close(); previous?.focus(); };
  }, []);
  return <dialog ref={ref} aria-labelledby={heading} className={`modal ${wide ? 'wide' : ''}`}
    onCancel={event => { event.preventDefault(); if (dismissible) onClose(); }}>
    <div className="modal-header"><h2 id={heading}>{title}</h2>
      <IconButton label="关闭" onClick={onClose} disabled={!dismissible}><X size={18} /></IconButton></div>
    <div className="modal-body">{children}</div>
  </dialog>;
}
export function AsyncButton({ action, children, ...props }:
  Omit<Parameters<typeof Button>[0], 'onClick'> & { action: () => Promise<unknown> }) {
  const [busy, setBusy] = useState(false);
  return <Button {...props} disabled={props.disabled || busy} onClick={() => {
    setBusy(true); void action().finally(() => setBusy(false)).catch(() => {});
  }}>{busy ? '处理中…' : children}</Button>;
}
export function Avatar({ name, group = false, small = false }: { name: string; group?: boolean; small?: boolean }) {
  return <span className={`avatar ${small ? 'small' : ''} ${group ? 'group' : ''}`} aria-hidden="true">
    {group ? '#' : Array.from(name)[0]?.toUpperCase() || 'C'}
  </span>;
}
export function fingerprint(value: string): string { return value.match(/.{1,4}/g)?.join(' ') || ''; }
export function clock(value: string, date = false): string {
  if (!value) return '';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value.slice(0, 40);
  return date ? parsed.toLocaleString() : parsed.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
