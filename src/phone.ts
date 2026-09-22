import { parsePhoneNumberFromString } from 'libphonenumber-js';

// Shared by every SMS provider: the domestic leading zero is removed before +261.
export function normalizeMalagasyPhone(raw: string): string | null {
  const candidate = raw.startsWith('+') ? raw : `+261${raw.replace(/^0/, '')}`;
  const phone = parsePhoneNumberFromString(candidate, 'MG');
  return phone?.isValid() && phone.country === 'MG' ? phone.number : null;
}
