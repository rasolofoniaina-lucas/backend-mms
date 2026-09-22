import { randomInt } from 'node:crypto';
import { Algorithm, hash, verify } from '@node-rs/argon2';

export const staffRoles = ['mechanic', 'workshop_manager', 'admin'] as const;
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
export function staffEmail(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return /^[a-z][a-z0-9-]{0,30}\.[a-z][a-z0-9-]{0,30}@mms\.mg$/.test(email) ? email : null;
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
export const ticketLabels: Record<TicketStatus, string> = {
  new: 'Nouveau', triage: 'À qualifier', assigned: 'Assigné', in_progress: 'En cours',
  waiting_customer: 'En attente client', completed: 'Terminé', cancelled: 'Annulé',
};
