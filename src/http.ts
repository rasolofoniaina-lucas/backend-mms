export class HttpError extends Error {
  constructor(public status: number, message: string, public code?: string) { super(message); }
}

export function textField(value: unknown, label: string, min = 0, max = 255): string {
  if (typeof value !== 'string' || value.trim().length < min || value.trim().length > max) throw new HttpError(400, `${label} invalide.`);
  return value.trim();
}
export function integerField(value: unknown, label: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) throw new HttpError(400, `${label} invalide.`);
  return value;
}
