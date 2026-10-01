// Pure shop rules shared by the API and its unit tests. No database access here.

export const productStatuses = ['draft', 'published', 'archived'] as const;
export type ProductStatus = typeof productStatuses[number];
export const compatibilityTypes = ['universal', 'vehicle_specific'] as const;
export type CompatibilityType = typeof compatibilityTypes[number];
export const orderStatuses = ['submitted', 'confirmed', 'preparing', 'ready', 'completed', 'cancelled'] as const;
export type OrderStatus = typeof orderStatuses[number];
export const commerceRoles = ['commercial', 'admin'] as const;

export const LOW_STOCK_THRESHOLD = 5;
export const MAX_PRODUCT_IMAGES = 8;
export const MAX_ORDER_LINES = 30;
export const MAX_LINE_QUANTITY = 99;
export const MAX_PRICE_ARIARY = 100_000_000;
export const MAX_ORDER_TOTAL_ARIARY = 2_000_000_000;
export const MAX_CATEGORY_DEPTH = 3;

const orderTransitions: Record<OrderStatus, readonly OrderStatus[]> = {
  submitted: ['confirmed', 'cancelled'],
  confirmed: ['preparing', 'cancelled'],
  preparing: ['ready'],
  ready: ['completed'],
  completed: [],
  cancelled: [],
};
export function canTransitionOrder(from: OrderStatus, to: OrderStatus): boolean {
  return orderTransitions[from]?.includes(to) ?? false;
}
export function nextOrderStatuses(from: OrderStatus): readonly OrderStatus[] {
  return orderTransitions[from] ?? [];
}
/** Stock is reserved only once the order is confirmed, so only those states hold stock. */
export function orderHoldsStock(status: OrderStatus): boolean {
  return status === 'confirmed' || status === 'preparing' || status === 'ready' || status === 'completed';
}

export function slugify(value: string): string {
  return value.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase()
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);
}
export function validSlug(value: unknown): value is string {
  return typeof value === 'string' && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value) && value.length <= 80;
}
export function validSku(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{1,47}$/.test(value.trim());
}

export type StockState = 'in_stock' | 'low_stock' | 'out_of_stock';
export function stockState(quantity: number): StockState {
  if (quantity <= 0) return 'out_of_stock';
  return quantity <= LOW_STOCK_THRESHOLD ? 'low_stock' : 'in_stock';
}

export type BannerState = 'active' | 'scheduled' | 'expired' | 'inactive';
export function bannerState(banner: { active: boolean; startAt: Date | string | null; endAt: Date | string | null }, now = new Date()): BannerState {
  if (!banner.active) return 'inactive';
  if (banner.endAt && new Date(banner.endAt) < now) return 'expired';
  if (banner.startAt && new Date(banner.startAt) > now) return 'scheduled';
  return 'active';
}

/** Only same-site paths or https links: never javascript:, data: or protocol-relative URLs. */
export function safeCtaUrl(value: string): boolean {
  if (value === '') return true;
  if (value.length > 300 || /[\s<>"'`\\]/.test(value)) return false;
  if (value.startsWith('/')) return !value.startsWith('//');
  try { return new URL(value).protocol === 'https:'; } catch { return false; }
}

export type Fitment = { make: string; model: string | null; yearMin: number | null; yearMax: number | null; displacementCc: number | null };
export type VehicleProfile = { make: string; model?: string | null; year?: number | null; displacementCc?: number | null };
export type Compatibility = 'compatible' | 'incompatible' | 'unknown';
const same = (left: string, right: string) => left.trim().toLowerCase() === right.trim().toLowerCase();

function fitmentResult(fitment: Fitment, vehicle: VehicleProfile): Compatibility {
  if (!same(fitment.make, vehicle.make)) return 'incompatible';
  let missing = false;
  if (fitment.model) {
    if (!vehicle.model?.trim()) missing = true;
    else if (!same(fitment.model, vehicle.model)) return 'incompatible';
  }
  if (fitment.yearMin !== null || fitment.yearMax !== null) {
    if (!vehicle.year) missing = true;
    else if ((fitment.yearMin !== null && vehicle.year < fitment.yearMin) || (fitment.yearMax !== null && vehicle.year > fitment.yearMax)) return 'incompatible';
  }
  if (fitment.displacementCc !== null) {
    if (!vehicle.displacementCc) missing = true;
    else if (fitment.displacementCc !== vehicle.displacementCc) return 'incompatible';
  }
  return missing ? 'unknown' : 'compatible';
}
/**
 * "compatible" is only returned when the data proves it. A vehicle-specific
 * product without fitments, or a vehicle missing a required field, is unknown.
 */
export function compatibilityFor(type: CompatibilityType, fitments: Fitment[], vehicle: VehicleProfile | null): Compatibility {
  if (type === 'universal') return 'compatible';
  if (!vehicle || !vehicle.make.trim() || fitments.length === 0) return 'unknown';
  const results = fitments.map(fitment => fitmentResult(fitment, vehicle));
  if (results.includes('compatible')) return 'compatible';
  return results.includes('unknown') ? 'unknown' : 'incompatible';
}

export type VariantAttributes = Record<string, string>;
export function variantAttributes(value: unknown): VariantAttributes | null {
  if (value === undefined || value === null) return {};
  if (typeof value !== 'object' || Array.isArray(value)) return null;
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > 6) return null;
  const result: VariantAttributes = {};
  for (const [key, raw] of entries) {
    if (!/^[a-z][a-z0-9_]{0,23}$/.test(key) || typeof raw !== 'string' || !raw.trim() || raw.trim().length > 40) return null;
    result[key] = raw.trim();
  }
  return result;
}

/** Merge duplicate cart lines and bound quantities; returns null when the cart is invalid. */
export function normalizeOrderLines(value: unknown): Array<{ productId: string; variantId: string | null; quantity: number }> | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_ORDER_LINES) return null;
  const merged = new Map<string, { productId: string; variantId: string | null; quantity: number }>();
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  for (const raw of value) {
    if (!raw || typeof raw !== 'object') return null;
    const { productId, variantId, quantity } = raw as Record<string, unknown>;
    if (typeof productId !== 'string' || !uuid.test(productId)) return null;
    if (variantId !== undefined && variantId !== null && (typeof variantId !== 'string' || !uuid.test(variantId))) return null;
    if (typeof quantity !== 'number' || !Number.isInteger(quantity) || quantity < 1 || quantity > MAX_LINE_QUANTITY) return null;
    const key = `${productId}:${variantId || ''}`;
    const current = merged.get(key);
    const total = (current?.quantity || 0) + quantity;
    if (total > MAX_LINE_QUANTITY) return null;
    merged.set(key, { productId, variantId: (variantId as string | undefined) || null, quantity: total });
  }
  return [...merged.values()];
}

export function orderReference(sequence: string | number, date = new Date()): string {
  return `CMD-${date.getFullYear()}-${String(sequence).padStart(6, '0')}`;
}
