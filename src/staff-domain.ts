import { randomInt } from 'node:crypto';
import { Algorithm, hash, verify } from '@node-rs/argon2';

export const staffRoles = ['mechanic', 'workshop_manager', 'admin', 'commercial'] as const;
export type StaffRole = typeof staffRoles[number];
export type Role = 'customer' | StaffRole;
export type TicketStatus = 'new' | 'triage' | 'assigned' | 'in_progress' | 'waiting_customer' | 'completed' | 'cancelled';

const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
export function temporaryPassword(): string {
  return Array.from({ length: 18 }, () => alphabet[randomInt(alphabet.length)]).join('');
}
export function validPassword(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 12 && value.length <= 128;
}
export function hashPassword(value: string): Promise<string> {
  return hash(value, { algorithm: Algorithm.Argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
}
export function verifyPassword(digest: string, value: string): Promise<boolean> {
  return verify(digest, value).catch(() => false);
}
export function staffUsername(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const username = value.trim().toLowerCase();
  return /^[a-z][a-z0-9._-]{2,31}$/.test(username) ? username : null;
}
export function staffEmail(value: unknown): string | null {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
}
export function isStaffRole(value: unknown): value is StaffRole {
  return staffRoles.includes(value as StaffRole);
}

const transitions: Record<TicketStatus, readonly TicketStatus[]> = {
  new: ['triage', 'cancelled'],
  triage: ['assigned', 'cancelled'],
  assigned: ['in_progress', 'triage', 'cancelled'],
  in_progress: ['waiting_customer', 'completed', 'cancelled'],
  waiting_customer: ['in_progress', 'cancelled'],
  completed: [],
  cancelled: [],
};
export function canTransition(from: TicketStatus, to: TicketStatus, role: Role): boolean {
  if (!transitions[from]?.includes(to)) return false;
  if (role === 'customer') return to === 'cancelled' && from === 'new';
  if (role === 'mechanic') return (
    from === 'assigned' && to === 'in_progress' ||
    from === 'in_progress' && (to === 'waiting_customer' || to === 'completed') ||
    from === 'waiting_customer' && to === 'in_progress'
  );
  if (role === 'workshop_manager') return true;
  return false; // Admin is not an atelier operator.
}
export function allowedTransitions(from: TicketStatus, role: Role): TicketStatus[] {
  return (transitions[from] || []).filter(to => canTransition(from, to, role));
}

/** The workshop manager assigns straight from a new request: "triage" is an optional step, not a mandatory click. */
export const assignableStatuses: readonly TicketStatus[] = ['new', 'triage', 'assigned'];
export function canAssign(status: TicketStatus): boolean {
  return assignableStatuses.includes(status);
}

export const waitingReasons = {
  quote: 'Devis à valider par le client',
  parts: 'Pièce à commander',
  unreachable: 'Client injoignable',
  vehicle: 'Moto non disponible',
  other: 'Autre raison',
} as const;
export type WaitingReason = keyof typeof waitingReasons;
export function isWaitingReason(value: unknown): value is WaitingReason {
  return typeof value === 'string' && Object.hasOwn(waitingReasons, value);
}

export type Completion = { operations: string[]; mileageKm: number | null; note: string; customerMessage: string };
/** Validates the closing form sent by the mechanic. Returns null when no completion form was sent. */
export function parseCompletion(value: unknown): Completion | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'object' || Array.isArray(value)) throw new Error('Fiche de clôture invalide.');
  const raw = value as Record<string, unknown>;
  const operations = Array.isArray(raw.operations) ? raw.operations : [];
  if (operations.length > 20 || operations.some(item => typeof item !== 'string' || !item.trim() || item.length > 80)) throw new Error('Liste des travaux invalide.');
  const mileage = raw.mileageKm === undefined || raw.mileageKm === null || raw.mileageKm === '' ? null : Number(raw.mileageKm);
  if (mileage !== null && (!Number.isInteger(mileage) || mileage < 0 || mileage > 2_000_000)) throw new Error('Kilométrage invalide.');
  const note = typeof raw.note === 'string' ? raw.note.trim() : '';
  const customerMessage = typeof raw.customerMessage === 'string' ? raw.customerMessage.trim() : '';
  if (note.length > 2000 || customerMessage.length > 2000) throw new Error('Texte trop long (2000 caractères maximum).');
  return { operations: [...new Set((operations as string[]).map(item => item.trim()))], mileageKm: mileage, note, customerMessage };
}
/** Maintenance book line created when a ticket is closed. */
export function maintenanceEntry(completion: Completion, interventionType: string) {
  const title = completion.operations.length ? completion.operations.join(', ').slice(0, 200) : `Intervention ${interventionType.toLowerCase()}`;
  const note = [completion.note, completion.mileageKm !== null ? `Kilométrage : ${completion.mileageKm.toLocaleString('fr-FR')} km` : ''].filter(Boolean).join('\n');
  return { title, note };
}

export const ticketLabels: Record<TicketStatus, string> = {
  new: 'Nouveau', triage: 'À qualifier', assigned: 'Assigné', in_progress: 'En cours',
  waiting_customer: 'En attente client', completed: 'Terminé', cancelled: 'Annulé',
};
