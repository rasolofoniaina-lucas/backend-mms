import type { IncomingMessage, ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { HttpError, integerField, textField } from './http.js';
import {
  bannerState, canTransitionOrder, commerceRoles, compatibilityFor, compatibilityTypes, LOW_STOCK_THRESHOLD, MAX_CATEGORY_DEPTH,
  MAX_ORDER_TOTAL_ARIARY, MAX_PRICE_ARIARY, MAX_PRODUCT_IMAGES, nextOrderStatuses, normalizeOrderLines, orderReference, orderStatuses,
  productStatuses, safeCtaUrl, slugify, stockState, validSku, validSlug, variantAttributes,
  type CompatibilityType, type Fitment, type OrderStatus, type VehicleProfile,
} from './shop-domain.js';
import type { Role } from './staff-domain.js';

export type ShopDeps = {
  pool: Pool;
  send: (res: ServerResponse, status: number, data: unknown) => void;
  body: (req: IncomingMessage) => Promise<Record<string, unknown>>;
  requireRole: (req: IncomingMessage, roles: readonly Role[]) => Promise<{ userId: string; role: Role }>;
  optionalCustomerId: (req: IncomingMessage) => Promise<string | null>;
  limit: (key: string, max: number, windowMs: number) => void;
  clientIp: (req: IncomingMessage) => string;
  photoBody: (req: IncomingMessage, mimeType: string) => Promise<Buffer>;
  normalizePhone: (value: unknown) => string;
  customerEmail: (value: unknown) => string;
};

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const mediaUrl = (id: string | null | undefined) => id ? `/api/shop/media/${id}` : null;
type Db = Pool | PoolClient;
type Row = Record<string, any>;

function uuid(value: unknown, label = 'Identifiant'): string {
  if (typeof value !== 'string' || !uuidPattern.test(value)) throw new HttpError(400, `${label} invalide.`);
  return value;
}
function optionalUuid(value: unknown, label: string): string | null {
  return value === undefined || value === null || value === '' ? null : uuid(value, label);
}
function optionalText(value: unknown, label: string, max: number): string {
  if (value === undefined || value === null) return '';
  return textField(value, label, 0, max);
}
function nullableInt(value: unknown, label: string, min: number, max: number): number | null {
  return value === undefined || value === null || value === '' ? null : integerField(value, label, min, max);
}
function bool(value: unknown, label: string): boolean {
  if (typeof value !== 'boolean') throw new HttpError(400, `${label} invalide.`);
  return value;
}
function has(input: Record<string, unknown>, key: string) { return Object.prototype.hasOwnProperty.call(input, key); }
function oneOf<T extends string>(value: unknown, allowed: readonly T[], label: string): T {
  if (!allowed.includes(value as T)) throw new HttpError(400, `${label} invalide.`);
  return value as T;
}
function plainText(value: string, label: string): string {
  // Catalogue text is rendered as text by React; markup is refused rather than stored.
  if (/<\s*\/?\s*[a-z!]/i.test(value)) throw new HttpError(400, `${label} : le HTML n'est pas autorisé.`);
  return value;
}
function likePattern(value: string) { return `%${value.replace(/[\\%_]/g, match => `\\${match}`)}%`; }
function pageParams(path: URL, max: number) {
  const page = Math.max(1, Math.min(500, Number.parseInt(path.searchParams.get('page') || '1', 10) || 1));
  const pageSize = Math.max(1, Math.min(max, Number.parseInt(path.searchParams.get('pageSize') || String(Math.min(24, max)), 10) || 24));
  return { page, pageSize, offset: (page - 1) * pageSize };
}
function queryInt(path: URL, key: string, min: number, max: number): number | null {
  const raw = path.searchParams.get(key);
  if (raw === null || raw === '') return null;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) throw new HttpError(400, 'Paramètre de recherche invalide.');
  return value;
}
function sqlParams() {
  const values: unknown[] = [];
  return { values, p: (value: unknown) => { values.push(value); return `$${values.length}`; } };
}
async function inTransaction<T>(deps: ShopDeps, work: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await deps.pool.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    const code = (error as { code?: string }).code;
    if (code === '23505') throw new HttpError(409, 'Cette valeur (SKU, slug ou nom) est déjà utilisée.');
    if (code === '23503') throw new HttpError(400, 'Référence invalide.');
    if (code === '23514') throw new HttpError(400, 'Valeur refusée par les règles du catalogue.');
    throw error;
  } finally { client.release(); }
}

// ---------------------------------------------------------------- catalogue reads
const effectiveStock = `CASE WHEN vs.variant_count > 0 THEN vs.variant_stock ELSE p.stock_quantity END`;
const productListSelect = `SELECT p.id,p.slug,p.sku,p.name,p.short_description AS "shortDescription",p.price_ariary AS "priceAriary",
  p.price_on_request AS "priceOnRequest",
  p.compare_at_price_ariary AS "compareAtPriceAriary",p.new_product AS "newProduct",p.featured,p.status,p.active,
  p.compatibility_type AS "compatibilityType",p.updated_at AS "updatedAt",p.created_at AS "createdAt",
  b.name AS "brandName",b.slug AS "brandSlug",c.name AS "categoryName",c.slug AS "categorySlug",c.id AS "categoryId",b.id AS "brandId",
  vs.variant_count AS "variantCount",${effectiveStock} AS "stockQuantity",img.media_id AS "imageId",img.alt_text AS "imageAlt"
  FROM shop_products p JOIN shop_categories c ON c.id=p.category_id LEFT JOIN shop_brands b ON b.id=p.brand_id
  LEFT JOIN LATERAL (SELECT count(*)::integer AS variant_count, COALESCE(sum(stock_quantity),0)::integer AS variant_stock
    FROM shop_product_variants v WHERE v.product_id=p.id AND v.active) vs ON true
  LEFT JOIN LATERAL (SELECT media_id, alt_text FROM shop_product_images i WHERE i.product_id=p.id
    ORDER BY i.is_primary DESC, i.display_order, i.created_at LIMIT 1) img ON true`;
const publicProduct = `p.status='published' AND p.active AND c.active`;

function productCard(row: Row) {
  return {
    id: row.id, slug: row.slug, sku: row.sku, name: row.name, shortDescription: row.shortDescription,
    brand: row.brandName ? { name: row.brandName, slug: row.brandSlug } : null,
    category: { name: row.categoryName, slug: row.categorySlug },
    priceAriary: row.priceAriary, priceOnRequest: row.priceOnRequest, compareAtPriceAriary: row.compareAtPriceAriary, promo: row.compareAtPriceAriary !== null,
    newProduct: row.newProduct, featured: row.featured, hasVariants: row.variantCount > 0,
    stockState: stockState(row.stockQuantity), compatibilityType: row.compatibilityType as CompatibilityType,
    image: row.imageId ? { url: mediaUrl(row.imageId), alt: row.imageAlt || row.name } : null,
  };
}
async function fitmentsFor(db: Db, productIds: string[]): Promise<Map<string, Fitment[]>> {
  const result = new Map<string, Fitment[]>();
  if (!productIds.length) return result;
  const rows = await db.query(`SELECT product_id AS "productId",make,model,year_min AS "yearMin",year_max AS "yearMax",
    displacement_cc AS "displacementCc" FROM shop_product_fitments WHERE product_id = ANY($1::uuid[]) ORDER BY make,model`, [productIds]);
  for (const row of rows.rows) {
    const list = result.get(row.productId) || [];
    list.push({ make: row.make, model: row.model, yearMin: row.yearMin, yearMax: row.yearMax, displacementCc: row.displacementCc });
    result.set(row.productId, list);
  }
  return result;
}
function vehicleFromQuery(path: URL): VehicleProfile | null {
  const make = path.searchParams.get('vehicleMake')?.trim();
  if (!make) return null;
  if (make.length > 80) throw new HttpError(400, 'Moto invalide.');
  const model = path.searchParams.get('vehicleModel')?.trim() || null;
  if (model && model.length > 100) throw new HttpError(400, 'Moto invalide.');
  return { make, model, year: queryInt(path, 'vehicleYear', 1885, 2100), displacementCc: queryInt(path, 'vehicleCc', 1, 5000) };
}
// SQL twin of compatibilityFor(): only proven fits pass the "compatible with my motorcycle" filter.
function compatibleSql(p: (value: unknown) => string, vehicle: VehicleProfile) {
  const make = p(vehicle.make); const model = p(vehicle.model || ''); const year = p(vehicle.year ?? null); const cc = p(vehicle.displacementCc ?? null);
  return `(p.compatibility_type='universal' OR EXISTS (SELECT 1 FROM shop_product_fitments f WHERE f.product_id=p.id
    AND lower(f.make)=lower(${make}::text)
    AND (f.model IS NULL OR (${model}::text<>'' AND lower(f.model)=lower(${model}::text)))
    AND ((f.year_min IS NULL AND f.year_max IS NULL) OR (${year}::integer IS NOT NULL AND (f.year_min IS NULL OR ${year}::integer>=f.year_min) AND (f.year_max IS NULL OR ${year}::integer<=f.year_max)))
    AND (f.displacement_cc IS NULL OR f.displacement_cc=${cc}::integer)))`;
}
function categoryTreeSql(p: (value: unknown) => string, slug: string, onlyActive: boolean) {
  const active = onlyActive ? ' AND active' : '';
  return `p.category_id IN (WITH RECURSIVE tree AS (SELECT id FROM shop_categories WHERE slug=${p(slug)}${active}
    UNION ALL SELECT c2.id FROM shop_categories c2 JOIN tree t ON c2.parent_id=t.id WHERE true${active.replace('active', 'c2.active')}) SELECT id FROM tree)`;
}

async function listPublicProducts(deps: ShopDeps, path: URL) {
  const { values, p } = sqlParams();
  const where = [publicProduct];
  const q = path.searchParams.get('q')?.trim() || '';
  if (q.length > 80) throw new HttpError(400, 'Recherche trop longue.');
  if (q) {
    const like = p(likePattern(q));
    where.push(`(p.name ILIKE ${like} OR p.sku ILIKE ${like} OR b.name ILIKE ${like} OR c.name ILIKE ${like} OR p.short_description ILIKE ${like})`);
  }
  const category = path.searchParams.get('category');
  if (category) { if (!validSlug(category)) throw new HttpError(400, 'Catégorie invalide.'); where.push(categoryTreeSql(p, category, true)); }
  const brands = (path.searchParams.get('brand') || '').split(',').filter(Boolean);
  if (brands.length) {
    if (brands.length > 20 || !brands.every(validSlug)) throw new HttpError(400, 'Marque invalide.');
    where.push(`b.slug = ANY(${p(brands)}::text[]) AND b.active`);
  }
  const minPrice = queryInt(path, 'minPrice', 0, MAX_PRICE_ARIARY); const maxPrice = queryInt(path, 'maxPrice', 0, MAX_PRICE_ARIARY);
  if (minPrice !== null) where.push(`p.price_ariary >= ${p(minPrice)}`);
  if (maxPrice !== null) where.push(`p.price_ariary <= ${p(maxPrice)}`);
  if (path.searchParams.get('inStock') === '1') where.push(`${effectiveStock} > 0`);
  if (path.searchParams.get('orderable') === '1') where.push(`NOT p.price_on_request AND ${effectiveStock} > 0`);
  if (path.searchParams.get('new') === '1') where.push('p.new_product');
  if (path.searchParams.get('promo') === '1') where.push('p.compare_at_price_ariary IS NOT NULL');
  if (path.searchParams.get('featured') === '1') where.push('p.featured');
  const vehicle = vehicleFromQuery(path);
  if (vehicle && path.searchParams.get('compatible') === '1') where.push(compatibleSql(p, vehicle));
  // The count query must not receive the parameters used only by ORDER BY.
  const filterValues = [...values];
  const sort = path.searchParams.get('sort') || 'relevance';
  const orders: Record<string, string> = {
    relevance: q ? `CASE WHEN upper(p.sku)=upper(${p(q)}) THEN 0 WHEN p.name ILIKE ${p(`${q.replace(/[\\%_]/g, m => `\\${m}`)}%`)} THEN 1 ELSE 2 END, p.featured DESC, p.created_at DESC` : 'p.featured DESC, p.created_at DESC',
    new: 'p.new_product DESC, p.created_at DESC', price_asc: 'p.price_ariary ASC, p.name', price_desc: 'p.price_ariary DESC, p.name', name: 'p.name ASC',
  };
  if (!orders[sort]) throw new HttpError(400, 'Tri invalide.');
  const { page, pageSize, offset } = pageParams(path, 48);
  const filter = where.join(' AND ');
  const [rows, count] = await Promise.all([
    deps.pool.query(`${productListSelect} WHERE ${filter} ORDER BY ${orders[sort]}, p.id LIMIT ${pageSize} OFFSET ${offset}`, values),
    deps.pool.query(`SELECT count(*)::integer AS total FROM shop_products p JOIN shop_categories c ON c.id=p.category_id LEFT JOIN shop_brands b ON b.id=p.brand_id
      LEFT JOIN LATERAL (SELECT count(*)::integer AS variant_count, COALESCE(sum(stock_quantity),0)::integer AS variant_stock
      FROM shop_product_variants v WHERE v.product_id=p.id AND v.active) vs ON true WHERE ${filter}`, filterValues),
  ]);
  const fitments = vehicle ? await fitmentsFor(deps.pool, rows.rows.filter(row => row.compatibilityType === 'vehicle_specific').map(row => row.id)) : new Map();
  return {
    items: rows.rows.map(row => ({ ...productCard(row), ...(vehicle ? { compatibility: compatibilityFor(row.compatibilityType, fitments.get(row.id) || [], vehicle) } : {}) })),
    total: count.rows[0].total, page, pageSize,
  };
}

async function publicProduct_(deps: ShopDeps, slug: string, path: URL) {
  if (!validSlug(slug)) throw new HttpError(404, 'Produit introuvable.');
  const found = await deps.pool.query(`${productListSelect} WHERE p.slug=$1 AND ${publicProduct}`, [slug]);
  if (!found.rowCount) throw new HttpError(404, 'Produit introuvable.');
  const row = found.rows[0];
  const [detail, images, variants, fitments, crumbs] = await Promise.all([
    deps.pool.query('SELECT description,stock_quantity FROM shop_products WHERE id=$1', [row.id]),
    deps.pool.query(`SELECT media_id,alt_text FROM shop_product_images WHERE product_id=$1 ORDER BY is_primary DESC,display_order,created_at`, [row.id]),
    deps.pool.query(`SELECT id,sku,label,attributes,COALESCE(price_override_ariary,$2) AS "priceAriary",stock_quantity AS "stockQuantity"
      FROM shop_product_variants WHERE product_id=$1 AND active ORDER BY display_order,label`, [row.id, row.priceAriary]),
    fitmentsFor(deps.pool, [row.id]),
    deps.pool.query(`WITH RECURSIVE up AS (SELECT id,parent_id,name,slug,0 AS depth FROM shop_categories WHERE id=$1
      UNION ALL SELECT c.id,c.parent_id,c.name,c.slug,up.depth+1 FROM shop_categories c JOIN up ON c.id=up.parent_id)
      SELECT name,slug FROM up ORDER BY depth DESC`, [row.categoryId]),
  ]);
  const vehicle = vehicleFromQuery(path);
  const list = fitments.get(row.id) || [];
  return {
    ...productCard(row), description: detail.rows[0].description, stockQuantity: row.stockQuantity,
    images: images.rows.map(image => ({ url: mediaUrl(image.media_id), alt: image.alt_text || row.name })),
    variants: variants.rows.map(variant => ({ id: variant.id, sku: variant.sku, label: variant.label, attributes: variant.attributes,
      priceAriary: variant.priceAriary, stockQuantity: variant.stockQuantity, stockState: stockState(variant.stockQuantity) })),
    fitments: list, breadcrumb: crumbs.rows,
    ...(vehicle ? { compatibility: compatibilityFor(row.compatibilityType, list, vehicle) } : {}),
  };
}

async function publicCategories(deps: ShopDeps) {
  const rows = await deps.pool.query(`SELECT c.id,c.parent_id AS "parentId",c.name,c.slug,c.description,c.image_media_id AS "imageId",c.active,
    (SELECT count(*)::integer FROM shop_products p WHERE p.category_id=c.id AND ${publicProduct}) AS "productCount"
    FROM shop_categories c ORDER BY c.display_order,c.name`);
  const byId = new Map(rows.rows.map(row => [row.id, row]));
  const visible = (row: Row): boolean => {
    for (let current: Row | undefined = row, guard = 0; current && guard < 10; current = current.parentId ? byId.get(current.parentId) : undefined, guard++) {
      if (!current.active) return false;
    }
    return true;
  };
  return rows.rows.filter(visible).map(row => ({ id: row.id, parentId: row.parentId, name: row.name, slug: row.slug,
    description: row.description, imageUrl: mediaUrl(row.imageId), productCount: row.productCount }));
}

async function sendMedia(deps: ShopDeps, res: ServerResponse, id: string) {
  const found = await deps.pool.query('SELECT mime_type,image_data FROM shop_media WHERE id=$1', [id]);
  if (!found.rowCount) throw new HttpError(404, 'Image introuvable.');
  res.writeHead(200, {
    'Content-Type': found.rows[0].mime_type, 'Cache-Control': 'public, max-age=31536000, immutable',
    'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; sandbox", 'Content-Disposition': 'inline',
  });
  res.end(found.rows[0].image_data);
}

// ---------------------------------------------------------------- orders
async function submitOrder(deps: ShopDeps, req: IncomingMessage) {
  deps.limit(`shop-order:${deps.clientIp(req)}`, 10, 60 * 60_000);
  const input = await deps.body(req);
  const lines = normalizeOrderLines(input.items);
  if (!lines) throw new HttpError(400, 'Panier invalide.');
  const firstName = plainText(textField(input.firstName, 'Prénom', 1, 80), 'Prénom');
  const lastName = plainText(textField(input.lastName, 'Nom', 1, 80), 'Nom');
  const phone = deps.normalizePhone(input.phone);
  const email = input.email === undefined || input.email === null || input.email === '' ? null : deps.customerEmail(input.email);
  const notes = plainText(optionalText(input.notes, 'Remarque', 1000), 'Remarque');
  const customerId = await deps.optionalCustomerId(req);
  return inTransaction(deps, async client => {
    const productIds = [...new Set(lines.map(line => line.productId))];
    const products = await client.query(`SELECT p.id,p.sku,p.name,p.price_ariary,p.price_on_request,p.stock_quantity,
      (SELECT count(*)::integer FROM shop_product_variants v WHERE v.product_id=p.id AND v.active) AS variant_count
      FROM shop_products p JOIN shop_categories c ON c.id=p.category_id WHERE p.id = ANY($1::uuid[]) AND ${publicProduct}`, [productIds]);
    const productById = new Map(products.rows.map(row => [row.id, row]));
    const variantIds = lines.map(line => line.variantId).filter((id): id is string => Boolean(id));
    const variants = variantIds.length ? await client.query(`SELECT id,product_id,sku,label,price_override_ariary,stock_quantity
      FROM shop_product_variants WHERE id = ANY($1::uuid[]) AND active`, [variantIds]) : { rows: [] as Row[] };
    const variantById = new Map(variants.rows.map(row => [row.id, row]));
    let subtotal = 0;
    const items = lines.map(line => {
      const product = productById.get(line.productId);
      if (!product) throw new HttpError(409, 'Un article du panier n’est plus disponible.');
      if (product.price_on_request) throw new HttpError(409, 'Cet article est présenté uniquement en vitrine. Contactez l’atelier.');
      let sku = product.sku; let unit = product.price_ariary; let stock = product.stock_quantity; let variantLabel: string | null = null;
      if (product.variant_count > 0) {
        const variant = line.variantId ? variantById.get(line.variantId) : null;
        if (!variant || variant.product_id !== product.id) throw new HttpError(400, `Choisissez une option pour « ${product.name} ».`);
        sku = variant.sku; unit = variant.price_override_ariary ?? product.price_ariary; stock = variant.stock_quantity; variantLabel = variant.label;
      } else if (line.variantId) throw new HttpError(400, 'Option de produit invalide.');
      if (unit <= 0) throw new HttpError(409, 'Cet article ne peut pas être commandé en ligne.');
      if (stock < line.quantity) throw new HttpError(409, `Stock insuffisant pour « ${product.name}${variantLabel ? ` – ${variantLabel}` : ''} ».`);
      const total = unit * line.quantity;
      subtotal += total;
      return { ...line, sku, productName: product.name, variantLabel, unit, total };
    });
    if (subtotal > MAX_ORDER_TOTAL_ARIARY) throw new HttpError(400, 'Commande trop importante : contactez la boutique.');
    const id = randomUUID();
    const sequence = await client.query(`SELECT nextval('shop_order_reference_seq')::text AS value`);
    const reference = orderReference(sequence.rows[0].value);
    await client.query(`INSERT INTO shop_orders(id,reference,customer_id,first_name,last_name,phone,email,status,subtotal_ariary,total_ariary,notes)
      VALUES($1,$2,$3,$4,$5,$6,$7,'submitted',$8,$8,$9)`, [id, reference, customerId, firstName, lastName, phone, email, subtotal, notes]);
    for (const item of items) {
      await client.query(`INSERT INTO shop_order_items(id,order_id,product_id,variant_id,sku,product_name,variant_label,quantity,unit_price_ariary,total_ariary)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [randomUUID(), id, item.productId, item.variantId, item.sku, item.productName, item.variantLabel, item.quantity, item.unit, item.total]);
    }
    await client.query(`INSERT INTO shop_order_events(order_id,actor_user_id,old_status,new_status) VALUES($1,NULL,NULL,'submitted')`, [id]);
    return { reference, status: 'submitted', subtotalAriary: subtotal, totalAriary: subtotal,
      items: items.map(item => ({ sku: item.sku, productName: item.productName, variantLabel: item.variantLabel, quantity: item.quantity, unitPriceAriary: item.unit, totalAriary: item.total })) };
  });
}

async function orderDetail(db: Db, id: string) {
  const order = await db.query(`SELECT o.id,o.reference,o.customer_id AS "customerId",o.first_name AS "firstName",o.last_name AS "lastName",o.phone,o.email,
    o.status,o.subtotal_ariary AS "subtotalAriary",o.total_ariary AS "totalAriary",o.notes,o.created_at AS "createdAt",o.updated_at AS "updatedAt"
    FROM shop_orders o WHERE o.id=$1`, [id]);
  if (!order.rowCount) throw new HttpError(404, 'Commande introuvable.');
  const [items, events] = await Promise.all([
    db.query(`SELECT id,product_id AS "productId",variant_id AS "variantId",sku,product_name AS "productName",variant_label AS "variantLabel",
      quantity,unit_price_ariary AS "unitPriceAriary",total_ariary AS "totalAriary" FROM shop_order_items WHERE order_id=$1 ORDER BY product_name`, [id]),
    db.query(`SELECT e.old_status AS "oldStatus",e.new_status AS "newStatus",e.created_at AS "createdAt",
      NULLIF(concat_ws(' ',u.first_name,u.last_name),'') AS actor FROM shop_order_events e LEFT JOIN users u ON u.id=e.actor_user_id
      WHERE e.order_id=$1 ORDER BY e.created_at,e.id`, [id]),
  ]);
  const row = order.rows[0];
  return { ...row, items: items.rows, events: events.rows, nextStatuses: nextOrderStatuses(row.status) };
}

async function changeOrderStatus(deps: ShopDeps, actorId: string, id: string, to: OrderStatus) {
  return inTransaction(deps, async client => {
    const found = await client.query('SELECT status FROM shop_orders WHERE id=$1 FOR UPDATE', [id]);
    if (!found.rowCount) throw new HttpError(404, 'Commande introuvable.');
    const from = found.rows[0].status as OrderStatus;
    if (!canTransitionOrder(from, to)) throw new HttpError(409, 'Ce changement de statut n’est pas autorisé.');
    const reserve = to === 'confirmed';
    const release = to === 'cancelled' && from === 'confirmed';
    if (reserve || release) {
      const items = await client.query(`SELECT product_id,variant_id,quantity,product_name,variant_label FROM shop_order_items WHERE order_id=$1
        ORDER BY product_id,variant_id NULLS FIRST`, [id]);
      for (const item of items.rows) {
        const table = item.variant_id ? 'shop_product_variants' : 'shop_products';
        const targetId = item.variant_id || item.product_id;
        // Row lock in a stable order (product, then variant) prevents both overselling and deadlocks.
        const stock = await client.query(`SELECT stock_quantity FROM ${table} WHERE id=$1 FOR UPDATE`, [targetId]);
        const current = stock.rows[0]?.stock_quantity as number | undefined;
        if (current === undefined) throw new HttpError(409, 'Un article de la commande n’existe plus.');
        const next = reserve ? current - item.quantity : current + item.quantity;
        if (next < 0) throw new HttpError(409, `Stock insuffisant pour « ${item.product_name}${item.variant_label ? ` – ${item.variant_label}` : ''} » (${current} disponible).`);
        await client.query(`UPDATE ${table} SET stock_quantity=$2,updated_at=now() WHERE id=$1`, [targetId, next]);
        await client.query(`INSERT INTO shop_stock_events(product_id,variant_id,order_id,actor_user_id,reason,old_quantity,new_quantity)
          VALUES($1,$2,$3,$4,$5,$6,$7)`, [item.product_id, item.variant_id, id, actorId, reserve ? 'order_confirmed' : 'order_cancelled', current, next]);
      }
    }
    await client.query('UPDATE shop_orders SET status=$2,updated_at=now() WHERE id=$1', [id, to]);
    await client.query('INSERT INTO shop_order_events(order_id,actor_user_id,old_status,new_status) VALUES($1,$2,$3,$4)', [id, actorId, from, to]);
    return orderDetail(client, id);
  });
}

// ---------------------------------------------------------------- commerce: products
type ProductInput = Partial<{ sku: string; name: string; slug: string; shortDescription: string; description: string; categoryId: string;
  brandId: string | null; priceAriary: number; priceOnRequest: boolean; compareAtPriceAriary: number | null; stockQuantity: number; compatibilityType: CompatibilityType;
  status: string; featured: boolean; newProduct: boolean; active: boolean }>;
function productInput(input: Record<string, unknown>, creating: boolean): ProductInput {
  const out: ProductInput = {};
  const required = (key: string) => creating || has(input, key);
  if (required('name')) out.name = plainText(textField(input.name, 'Nom du produit', 2, 140), 'Nom du produit');
  if (required('sku')) { if (!validSku(input.sku)) throw new HttpError(400, 'SKU invalide : 2 à 48 caractères, lettres, chiffres, point, tiret ou underscore.'); out.sku = (input.sku as string).trim().toUpperCase(); }
  if (has(input, 'slug') && input.slug !== '' && input.slug !== null) { if (!validSlug(input.slug)) throw new HttpError(400, 'Slug invalide.'); out.slug = input.slug as string; }
  if (has(input, 'shortDescription')) out.shortDescription = plainText(optionalText(input.shortDescription, 'Description courte', 280), 'Description courte');
  if (has(input, 'description')) out.description = plainText(optionalText(input.description, 'Description', 5000), 'Description');
  if (required('categoryId')) out.categoryId = uuid(input.categoryId, 'Catégorie');
  if (has(input, 'brandId')) out.brandId = optionalUuid(input.brandId, 'Marque');
  if (required('priceAriary')) out.priceAriary = integerField(input.priceAriary, 'Prix', 0, MAX_PRICE_ARIARY);
  if (has(input, 'priceOnRequest')) out.priceOnRequest = bool(input.priceOnRequest, 'Prix sur demande');
  if (has(input, 'compareAtPriceAriary')) out.compareAtPriceAriary = nullableInt(input.compareAtPriceAriary, 'Ancien prix', 1, MAX_PRICE_ARIARY);
  if (has(input, 'stockQuantity')) out.stockQuantity = integerField(input.stockQuantity, 'Stock', 0, 1_000_000);
  if (has(input, 'compatibilityType')) out.compatibilityType = oneOf(input.compatibilityType, compatibilityTypes, 'Compatibilité');
  if (has(input, 'status')) out.status = oneOf(input.status, productStatuses, 'Statut');
  if (has(input, 'featured')) out.featured = bool(input.featured, 'Mis en avant');
  if (has(input, 'newProduct')) out.newProduct = bool(input.newProduct, 'Nouveauté');
  if (has(input, 'active')) out.active = bool(input.active, 'Actif');
  return out;
}
async function uniqueSlug(db: Db, table: 'shop_products' | 'shop_categories' | 'shop_brands', base: string, excludeId?: string) {
  const root = slugify(base) || 'element';
  for (let index = 1; index < 50; index++) {
    const candidate = index === 1 ? root : `${root.slice(0, 74)}-${index}`;
    const taken = await db.query(`SELECT 1 FROM ${table} WHERE slug=$1 AND ($2::uuid IS NULL OR id<>$2::uuid)`, [candidate, excludeId ?? null]);
    if (!taken.rowCount) return candidate;
  }
  throw new HttpError(409, 'Impossible de générer un slug unique.');
}
async function commerceProduct(db: Db, id: string) {
  const found = await db.query(`${productListSelect} WHERE p.id=$1`, [id]);
  if (!found.rowCount) throw new HttpError(404, 'Produit introuvable.');
  const row = found.rows[0];
  const [detail, images, variants, fitments] = await Promise.all([
    db.query('SELECT description,stock_quantity FROM shop_products WHERE id=$1', [id]),
    db.query(`SELECT id,media_id AS "mediaId",alt_text AS "altText",display_order AS "displayOrder",is_primary AS "isPrimary"
      FROM shop_product_images WHERE product_id=$1 ORDER BY is_primary DESC,display_order,created_at`, [id]),
    db.query(`SELECT id,sku,label,attributes,price_override_ariary AS "priceOverrideAriary",stock_quantity AS "stockQuantity",
      display_order AS "displayOrder",active FROM shop_product_variants WHERE product_id=$1 ORDER BY display_order,label`, [id]),
    fitmentsFor(db, [id]),
  ]);
  return {
    id: row.id, sku: row.sku, name: row.name, slug: row.slug, shortDescription: row.shortDescription, description: detail.rows[0].description,
    categoryId: row.categoryId, brandId: row.brandId, priceAriary: row.priceAriary, priceOnRequest: row.priceOnRequest, compareAtPriceAriary: row.compareAtPriceAriary,
    stockQuantity: detail.rows[0].stock_quantity, effectiveStock: row.stockQuantity, stockState: stockState(row.stockQuantity),
    compatibilityType: row.compatibilityType, status: row.status, featured: row.featured, newProduct: row.newProduct, active: row.active,
    images: images.rows.map(image => ({ ...image, url: mediaUrl(image.mediaId) })), variants: variants.rows, fitments: fitments.get(id) || [],
    updatedAt: row.updatedAt, createdAt: row.createdAt,
  };
}
async function assertPublishable(db: Db, id: string) {
  const found = await db.query(`SELECT p.price_ariary,p.price_on_request,p.compare_at_price_ariary,c.active AS category_active FROM shop_products p JOIN shop_categories c ON c.id=p.category_id WHERE p.id=$1`, [id]);
  if (!found.rows[0]?.category_active) throw new HttpError(409, 'Publiez d’abord dans une catégorie active.');
  if (found.rows[0].price_on_request) {
    if (found.rows[0].price_ariary !== 0 || found.rows[0].compare_at_price_ariary !== null) throw new HttpError(409, 'Un article vitrine ne doit pas afficher de prix.');
  } else if (found.rows[0].price_ariary <= 0) throw new HttpError(409, 'Un produit commandable doit avoir un prix.');
}
async function saveProduct(deps: ShopDeps, actorId: string, input: Record<string, unknown>, id?: string) {
  const values = productInput(input, !id);
  return inTransaction(deps, async client => {
    if (id) {
      const current = await client.query('SELECT price_ariary,price_on_request,compare_at_price_ariary,stock_quantity FROM shop_products WHERE id=$1 FOR UPDATE', [id]);
      if (!current.rowCount) throw new HttpError(404, 'Produit introuvable.');
      const price = values.priceAriary ?? current.rows[0].price_ariary;
      const compare = values.compareAtPriceAriary !== undefined ? values.compareAtPriceAriary : current.rows[0].compare_at_price_ariary;
      if (compare !== null && compare <= price) throw new HttpError(400, 'L’ancien prix doit être supérieur au prix actuel.');
      const columns: Record<string, string> = { sku: 'sku', name: 'name', slug: 'slug', shortDescription: 'short_description', description: 'description',
        categoryId: 'category_id', brandId: 'brand_id', priceAriary: 'price_ariary', priceOnRequest: 'price_on_request', compareAtPriceAriary: 'compare_at_price_ariary', stockQuantity: 'stock_quantity',
        compatibilityType: 'compatibility_type', status: 'status', featured: 'featured', newProduct: 'new_product', active: 'active' };
      const { values: params, p } = sqlParams();
      const sets = Object.entries(values).map(([key, value]) => `${columns[key]}=${p(value)}`);
      if (sets.length) await client.query(`UPDATE shop_products SET ${sets.join(',')},updated_at=now() WHERE id=${p(id)}`, params);
      if (values.stockQuantity !== undefined && values.stockQuantity !== current.rows[0].stock_quantity) {
        // Direct stock edits from the product form are audited like the stock screen.
        await client.query(`INSERT INTO shop_stock_events(product_id,actor_user_id,reason,old_quantity,new_quantity) VALUES($1,$2,'manual',$3,$4)`,
          [id, actorId, current.rows[0].stock_quantity, values.stockQuantity]);
      }
      const resultingStatus = values.status ?? (await client.query('SELECT status FROM shop_products WHERE id=$1', [id])).rows[0].status;
      if (resultingStatus === 'published') await assertPublishable(client, id);
      return commerceProduct(client, id);
    }
    if (values.compareAtPriceAriary != null && values.compareAtPriceAriary <= values.priceAriary!) throw new HttpError(400, 'L’ancien prix doit être supérieur au prix actuel.');
    const newId = randomUUID();
    const slug = values.slug || await uniqueSlug(client, 'shop_products', values.name!);
    await client.query(`INSERT INTO shop_products(id,sku,name,slug,short_description,description,category_id,brand_id,price_ariary,price_on_request,compare_at_price_ariary,
      stock_quantity,compatibility_type,status,featured,new_product,active,created_by_user_id)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, [newId, values.sku, values.name, slug, values.shortDescription ?? '',
      values.description ?? '', values.categoryId, values.brandId ?? null, values.priceAriary, values.priceOnRequest ?? false, values.compareAtPriceAriary ?? null, values.stockQuantity ?? 0,
      values.compatibilityType ?? 'universal', values.status ?? 'draft', values.featured ?? false, values.newProduct ?? false, values.active ?? true, actorId]);
    if (values.status === 'published') await assertPublishable(client, newId);
    return commerceProduct(client, newId);
  });
}

async function saveVariants(deps: ShopDeps, productId: string, input: Record<string, unknown>) {
  if (!Array.isArray(input.variants) || input.variants.length > 40) throw new HttpError(400, 'Variantes invalides (40 maximum).');
  const variants = (input.variants as unknown[]).map((raw, index) => {
    if (!raw || typeof raw !== 'object') throw new HttpError(400, 'Variante invalide.');
    const value = raw as Record<string, unknown>;
    if (!validSku(value.sku)) throw new HttpError(400, 'SKU de variante invalide.');
    const attributes = variantAttributes(value.attributes);
    if (!attributes) throw new HttpError(400, 'Attributs de variante invalides (ex. taille, couleur).');
    return { id: optionalUuid(value.id, 'Variante'), sku: (value.sku as string).trim().toUpperCase(), label: plainText(textField(value.label, 'Libellé de variante', 1, 80), 'Libellé'),
      attributes, priceOverrideAriary: nullableInt(value.priceOverrideAriary, 'Prix de variante', 0, MAX_PRICE_ARIARY),
      stockQuantity: integerField(value.stockQuantity ?? 0, 'Stock de variante', 0, 1_000_000), active: value.active === undefined ? true : bool(value.active, 'Variante active'), displayOrder: index };
  });
  return inTransaction(deps, async client => {
    const product = await client.query('SELECT 1 FROM shop_products WHERE id=$1 FOR UPDATE', [productId]);
    if (!product.rowCount) throw new HttpError(404, 'Produit introuvable.');
    const kept: string[] = [];
    for (const variant of variants) {
      if (variant.id) {
        const updated = await client.query(`UPDATE shop_product_variants SET sku=$3,label=$4,attributes=$5,price_override_ariary=$6,stock_quantity=$7,active=$8,display_order=$9,updated_at=now()
          WHERE id=$1 AND product_id=$2`, [variant.id, productId, variant.sku, variant.label, JSON.stringify(variant.attributes), variant.priceOverrideAriary, variant.stockQuantity, variant.active, variant.displayOrder]);
        if (!updated.rowCount) throw new HttpError(404, 'Variante introuvable.');
        kept.push(variant.id);
      } else {
        const id = randomUUID();
        await client.query(`INSERT INTO shop_product_variants(id,product_id,sku,label,attributes,price_override_ariary,stock_quantity,active,display_order)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [id, productId, variant.sku, variant.label, JSON.stringify(variant.attributes), variant.priceOverrideAriary, variant.stockQuantity, variant.active, variant.displayOrder]);
        kept.push(id);
      }
    }
    // Variants referenced by past orders must survive: removal deactivates instead of deleting.
    await client.query(`UPDATE shop_product_variants SET active=false,updated_at=now() WHERE product_id=$1 AND NOT (id = ANY($2::uuid[]))`, [productId, kept]);
    await client.query('UPDATE shop_products SET updated_at=now() WHERE id=$1', [productId]);
    return commerceProduct(client, productId);
  });
}

async function saveFitments(deps: ShopDeps, productId: string, input: Record<string, unknown>) {
  if (!Array.isArray(input.fitments) || input.fitments.length > 60) throw new HttpError(400, 'Compatibilités invalides (60 maximum).');
  const fitments = (input.fitments as unknown[]).map(raw => {
    if (!raw || typeof raw !== 'object') throw new HttpError(400, 'Compatibilité invalide.');
    const value = raw as Record<string, unknown>;
    const yearMin = nullableInt(value.yearMin, 'Année minimum', 1885, 2100); const yearMax = nullableInt(value.yearMax, 'Année maximum', 1885, 2100);
    if (yearMin !== null && yearMax !== null && yearMin > yearMax) throw new HttpError(400, 'L’année minimum doit précéder l’année maximum.');
    return { make: plainText(textField(value.make, 'Marque de moto', 1, 80), 'Marque de moto'), model: plainText(optionalText(value.model, 'Modèle', 100), 'Modèle') || null,
      yearMin, yearMax, displacementCc: nullableInt(value.displacementCc, 'Cylindrée', 1, 5000) };
  });
  return inTransaction(deps, async client => {
    const product = await client.query('SELECT 1 FROM shop_products WHERE id=$1 FOR UPDATE', [productId]);
    if (!product.rowCount) throw new HttpError(404, 'Produit introuvable.');
    await client.query('DELETE FROM shop_product_fitments WHERE product_id=$1', [productId]);
    for (const fitment of fitments) {
      await client.query(`INSERT INTO shop_product_fitments(id,product_id,make,model,year_min,year_max,displacement_cc) VALUES($1,$2,$3,$4,$5,$6,$7)`,
        [randomUUID(), productId, fitment.make, fitment.model, fitment.yearMin, fitment.yearMax, fitment.displacementCc]);
    }
    await client.query('UPDATE shop_products SET updated_at=now() WHERE id=$1', [productId]);
    return commerceProduct(client, productId);
  });
}

async function addImage(deps: ShopDeps, productId: string, input: Record<string, unknown>) {
  const mediaId = uuid(input.mediaId, 'Image');
  const altText = plainText(optionalText(input.altText, 'Texte alternatif', 160), 'Texte alternatif');
  return inTransaction(deps, async client => {
    const product = await client.query('SELECT 1 FROM shop_products WHERE id=$1 FOR UPDATE', [productId]);
    if (!product.rowCount) throw new HttpError(404, 'Produit introuvable.');
    const count = await client.query('SELECT count(*)::integer AS n FROM shop_product_images WHERE product_id=$1', [productId]);
    if (count.rows[0].n >= MAX_PRODUCT_IMAGES) throw new HttpError(409, `${MAX_PRODUCT_IMAGES} images maximum par produit.`);
    const media = await client.query('SELECT 1 FROM shop_media WHERE id=$1', [mediaId]);
    if (!media.rowCount) throw new HttpError(404, 'Image introuvable.');
    await client.query(`INSERT INTO shop_product_images(id,product_id,media_id,alt_text,display_order,is_primary) VALUES($1,$2,$3,$4,$5,$6)`,
      [randomUUID(), productId, mediaId, altText, count.rows[0].n, count.rows[0].n === 0]);
    return commerceProduct(client, productId);
  });
}
async function updateImage(deps: ShopDeps, productId: string, imageId: string, input: Record<string, unknown>) {
  return inTransaction(deps, async client => {
    const found = await client.query('SELECT 1 FROM shop_product_images WHERE id=$1 AND product_id=$2 FOR UPDATE', [imageId, productId]);
    if (!found.rowCount) throw new HttpError(404, 'Image introuvable.');
    if (has(input, 'altText')) await client.query('UPDATE shop_product_images SET alt_text=$2 WHERE id=$1', [imageId, plainText(optionalText(input.altText, 'Texte alternatif', 160), 'Texte alternatif')]);
    if (has(input, 'displayOrder')) await client.query('UPDATE shop_product_images SET display_order=$2 WHERE id=$1', [imageId, integerField(input.displayOrder, 'Ordre', 0, 100)]);
    if (input.isPrimary === true) {
      await client.query('UPDATE shop_product_images SET is_primary=false WHERE product_id=$1', [productId]);
      await client.query('UPDATE shop_product_images SET is_primary=true WHERE id=$1', [imageId]);
    }
    return commerceProduct(client, productId);
  });
}
async function deleteImage(deps: ShopDeps, productId: string, imageId: string) {
  return inTransaction(deps, async client => {
    const removed = await client.query('DELETE FROM shop_product_images WHERE id=$1 AND product_id=$2 RETURNING is_primary', [imageId, productId]);
    if (!removed.rowCount) throw new HttpError(404, 'Image introuvable.');
    if (removed.rows[0].is_primary) await client.query(`UPDATE shop_product_images SET is_primary=true WHERE id=(SELECT id FROM shop_product_images
      WHERE product_id=$1 ORDER BY display_order,created_at LIMIT 1)`, [productId]);
    return commerceProduct(client, productId);
  });
}

async function commerceProductList(deps: ShopDeps, path: URL) {
  const { values, p } = sqlParams();
  const where = ['true'];
  const q = path.searchParams.get('q')?.trim();
  if (q) { if (q.length > 80) throw new HttpError(400, 'Recherche trop longue.'); const like = p(likePattern(q)); where.push(`(p.name ILIKE ${like} OR p.sku ILIKE ${like} OR b.name ILIKE ${like})`); }
  const status = path.searchParams.get('status');
  if (status) where.push(`p.status=${p(oneOf(status, productStatuses, 'Statut'))}`);
  const category = path.searchParams.get('categoryId');
  if (category) where.push(`p.category_id=${p(uuid(category, 'Catégorie'))}`);
  const brand = path.searchParams.get('brandId');
  if (brand) where.push(`p.brand_id=${p(uuid(brand, 'Marque'))}`);
  const stock = path.searchParams.get('stock');
  if (stock === 'out') where.push(`${effectiveStock} <= 0`);
  else if (stock === 'low') where.push(`${effectiveStock} BETWEEN 1 AND ${LOW_STOCK_THRESHOLD}`);
  else if (stock === 'in') where.push(`${effectiveStock} > 0`);
  else if (stock) throw new HttpError(400, 'Filtre de stock invalide.');
  const { page, pageSize, offset } = pageParams(path, 50);
  const filter = where.join(' AND ');
  const [rows, count] = await Promise.all([
    deps.pool.query(`${productListSelect} WHERE ${filter} ORDER BY p.updated_at DESC, p.id LIMIT ${pageSize} OFFSET ${offset}`, values),
    deps.pool.query(`SELECT count(*)::integer AS total FROM shop_products p LEFT JOIN shop_brands b ON b.id=p.brand_id
      LEFT JOIN LATERAL (SELECT count(*)::integer AS variant_count, COALESCE(sum(stock_quantity),0)::integer AS variant_stock
      FROM shop_product_variants v WHERE v.product_id=p.id AND v.active) vs ON true WHERE ${filter}`, values),
  ]);
  return { items: rows.rows.map(row => ({ ...productCard(row), status: row.status, active: row.active, stockQuantity: row.stockQuantity, updatedAt: row.updatedAt })),
    total: count.rows[0].total, page, pageSize };
}

// ---------------------------------------------------------------- commerce: taxonomy, banners, stock
async function saveCategory(deps: ShopDeps, input: Record<string, unknown>, id?: string) {
  return inTransaction(deps, async client => {
    if (id) { const current = await client.query('SELECT 1 FROM shop_categories WHERE id=$1 FOR UPDATE', [id]); if (!current.rowCount) throw new HttpError(404, 'Catégorie introuvable.'); }
    const name = !id || has(input, 'name') ? plainText(textField(input.name, 'Nom de catégorie', 2, 80), 'Nom') : undefined;
    const parentId = has(input, 'parentId') ? optionalUuid(input.parentId, 'Catégorie parente') : undefined;
    if (parentId) {
      if (parentId === id) throw new HttpError(409, 'Une catégorie ne peut pas être son propre parent.');
      const ancestors = await client.query(`WITH RECURSIVE up AS (SELECT id,parent_id FROM shop_categories WHERE id=$1
        UNION ALL SELECT c.id,c.parent_id FROM shop_categories c JOIN up ON c.id=up.parent_id) SELECT id FROM up`, [parentId]);
      if (!ancestors.rowCount) throw new HttpError(404, 'Catégorie parente introuvable.');
      if (id && ancestors.rows.some(row => row.id === id)) throw new HttpError(409, 'Ce choix créerait une boucle dans les catégories.');
      const height = id ? (await client.query(`WITH RECURSIVE down AS (SELECT id,1 AS level FROM shop_categories WHERE id=$1
        UNION ALL SELECT c.id,down.level+1 FROM shop_categories c JOIN down ON c.parent_id=down.id WHERE down.level<10) SELECT max(level) AS height FROM down`, [id])).rows[0].height : 1;
      if (ancestors.rowCount! + height > MAX_CATEGORY_DEPTH) throw new HttpError(409, `${MAX_CATEGORY_DEPTH} niveaux de catégories maximum.`);
    }
    const slug = has(input, 'slug') && input.slug ? (validSlug(input.slug) ? input.slug as string : (() => { throw new HttpError(400, 'Slug invalide.'); })()) : (!id ? await uniqueSlug(client, 'shop_categories', name!) : undefined);
    const fields: Record<string, unknown> = {
      ...(name !== undefined ? { name } : {}), ...(slug !== undefined ? { slug } : {}), ...(parentId !== undefined ? { parent_id: parentId } : {}),
      ...(has(input, 'description') ? { description: plainText(optionalText(input.description, 'Description', 500), 'Description') || null } : {}),
      ...(has(input, 'imageMediaId') ? { image_media_id: optionalUuid(input.imageMediaId, 'Image') } : {}),
      ...(has(input, 'displayOrder') ? { display_order: integerField(input.displayOrder, 'Ordre', 0, 10_000) } : {}),
      ...(has(input, 'active') ? { active: bool(input.active, 'Active') } : {}),
    };
    const newId = id || randomUUID();
    const { values, p } = sqlParams();
    if (id) {
      const sets = Object.entries(fields).map(([column, value]) => `${column}=${p(value)}`);
      if (sets.length) await client.query(`UPDATE shop_categories SET ${sets.join(',')},updated_at=now() WHERE id=${p(id)}`, values);
    } else {
      const columns = ['id', ...Object.keys(fields)]; const params = [newId, ...Object.values(fields)];
      await client.query(`INSERT INTO shop_categories(${columns.join(',')}) VALUES(${params.map((_, index) => `$${index + 1}`).join(',')})`, params);
    }
    return (await client.query(`SELECT id,parent_id AS "parentId",name,slug,description,image_media_id AS "imageMediaId",display_order AS "displayOrder",active
      FROM shop_categories WHERE id=$1`, [newId])).rows.map(row => ({ ...row, imageUrl: mediaUrl(row.imageMediaId) }))[0];
  });
}
async function saveBrand(deps: ShopDeps, input: Record<string, unknown>, id?: string) {
  return inTransaction(deps, async client => {
    if (id) { const current = await client.query('SELECT 1 FROM shop_brands WHERE id=$1 FOR UPDATE', [id]); if (!current.rowCount) throw new HttpError(404, 'Marque introuvable.'); }
    const name = !id || has(input, 'name') ? plainText(textField(input.name, 'Nom de marque', 1, 80), 'Nom') : undefined;
    if (has(input, 'slug') && input.slug && !validSlug(input.slug)) throw new HttpError(400, 'Slug invalide.');
    const slug = has(input, 'slug') && input.slug ? input.slug as string : (!id ? await uniqueSlug(client, 'shop_brands', name!) : undefined);
    const fields: Record<string, unknown> = {
      ...(name !== undefined ? { name } : {}), ...(slug !== undefined ? { slug } : {}),
      ...(has(input, 'logoMediaId') ? { logo_media_id: optionalUuid(input.logoMediaId, 'Logo') } : {}),
      ...(has(input, 'active') ? { active: bool(input.active, 'Active') } : {}),
    };
    const newId = id || randomUUID();
    const { values, p } = sqlParams();
    if (id) {
      const sets = Object.entries(fields).map(([column, value]) => `${column}=${p(value)}`);
      if (sets.length) await client.query(`UPDATE shop_brands SET ${sets.join(',')},updated_at=now() WHERE id=${p(id)}`, values);
    } else {
      const columns = ['id', ...Object.keys(fields)]; const params = [newId, ...Object.values(fields)];
      await client.query(`INSERT INTO shop_brands(${columns.join(',')}) VALUES(${params.map((_, index) => `$${index + 1}`).join(',')})`, params);
    }
    return (await client.query(`SELECT id,name,slug,logo_media_id AS "logoMediaId",active FROM shop_brands WHERE id=$1`, [newId])).rows.map(row => ({ ...row, logoUrl: mediaUrl(row.logoMediaId) }))[0];
  });
}

const bannerSelect = `SELECT id,title,subtitle,desktop_media_id AS "desktopMediaId",mobile_media_id AS "mobileMediaId",cta_label AS "ctaLabel",cta_url AS "ctaUrl",
  active,display_order AS "displayOrder",start_at AS "startAt",end_at AS "endAt",created_at AS "createdAt",updated_at AS "updatedAt" FROM shop_banners`;
function bannerView(row: Row): Row {
  return { ...row, desktopImageUrl: mediaUrl(row.desktopMediaId), mobileImageUrl: mediaUrl(row.mobileMediaId),
    state: bannerState({ active: row.active, startAt: row.startAt, endAt: row.endAt }) };
}
function dateField(value: unknown, label: string): string | null {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string' || value.length > 40 || Number.isNaN(Date.parse(value))) throw new HttpError(400, `${label} invalide.`);
  return new Date(value).toISOString();
}
async function saveBanner(deps: ShopDeps, actorId: string, input: Record<string, unknown>, id?: string) {
  return inTransaction(deps, async client => {
    const current = id ? await client.query(`${bannerSelect} WHERE id=$1 FOR UPDATE`, [id]) : null;
    if (id && !current!.rowCount) throw new HttpError(404, 'Publicité introuvable.');
    const fields: Record<string, unknown> = {};
    if (!id || has(input, 'title')) fields.title = plainText(textField(input.title, 'Titre', 2, 90), 'Titre');
    if (has(input, 'subtitle')) fields.subtitle = plainText(optionalText(input.subtitle, 'Sous-titre', 180), 'Sous-titre');
    if (has(input, 'ctaLabel')) fields.cta_label = plainText(optionalText(input.ctaLabel, 'Bouton', 40), 'Bouton');
    if (has(input, 'ctaUrl')) { const url = optionalText(input.ctaUrl, 'Lien', 300); if (!safeCtaUrl(url)) throw new HttpError(400, 'Lien invalide : utilisez un chemin MMS (/boutique/…) ou une adresse https.'); fields.cta_url = url; }
    if (has(input, 'desktopMediaId')) fields.desktop_media_id = optionalUuid(input.desktopMediaId, 'Image desktop');
    if (has(input, 'mobileMediaId')) fields.mobile_media_id = optionalUuid(input.mobileMediaId, 'Image mobile');
    if (has(input, 'active')) fields.active = bool(input.active, 'Active');
    if (has(input, 'displayOrder')) fields.display_order = integerField(input.displayOrder, 'Ordre', 0, 1000);
    if (has(input, 'startAt')) fields.start_at = dateField(input.startAt, 'Date de début');
    if (has(input, 'endAt')) fields.end_at = dateField(input.endAt, 'Date de fin');
    const start = fields.start_at !== undefined ? fields.start_at : current?.rows[0]?.startAt ?? null;
    const end = fields.end_at !== undefined ? fields.end_at : current?.rows[0]?.endAt ?? null;
    if (start && end && new Date(start as string) >= new Date(end as string)) throw new HttpError(400, 'La date de fin doit suivre la date de début.');
    const newId = id || randomUUID();
    const { values, p } = sqlParams();
    if (id) {
      const sets = Object.entries(fields).map(([column, value]) => `${column}=${p(value)}`);
      if (sets.length) await client.query(`UPDATE shop_banners SET ${sets.join(',')},updated_at=now() WHERE id=${p(id)}`, values);
    } else {
      const all = { id: newId, created_by_user_id: actorId, ...fields };
      await client.query(`INSERT INTO shop_banners(${Object.keys(all).join(',')}) VALUES(${Object.keys(all).map((_, index) => `$${index + 1}`).join(',')})`, Object.values(all));
    }
    return bannerView((await client.query(`${bannerSelect} WHERE id=$1`, [newId])).rows[0]);
  });
}

async function stockRows(deps: ShopDeps, path: URL) {
  const { values, p } = sqlParams();
  const where = ['p.status<>\'archived\''];
  const q = path.searchParams.get('q')?.trim();
  if (q) { if (q.length > 80) throw new HttpError(400, 'Recherche trop longue.'); const like = p(likePattern(q)); where.push(`(p.name ILIKE ${like} OR s.sku ILIKE ${like})`); }
  const state = path.searchParams.get('state');
  if (state === 'out') where.push('s.stock <= 0'); else if (state === 'low') where.push(`s.stock BETWEEN 1 AND ${LOW_STOCK_THRESHOLD}`); else if (state === 'in') where.push('s.stock > 0');
  else if (state) throw new HttpError(400, 'Filtre de stock invalide.');
  const { page, pageSize, offset } = pageParams(path, 100);
  // One row per stock holder: the product itself, or each active variant when it has some.
  const source = `(SELECT p.id AS product_id,NULL::uuid AS variant_id,p.sku,NULL::text AS label,p.stock_quantity AS stock FROM shop_products p
      WHERE NOT EXISTS (SELECT 1 FROM shop_product_variants v WHERE v.product_id=p.id AND v.active)
    UNION ALL SELECT v.product_id,v.id,v.sku,v.label,v.stock_quantity FROM shop_product_variants v WHERE v.active) s JOIN shop_products p ON p.id=s.product_id`;
  const filter = where.join(' AND ');
  const [rows, count] = await Promise.all([
    deps.pool.query(`SELECT s.product_id AS "productId",s.variant_id AS "variantId",s.sku,p.name AS "productName",s.label AS "variantLabel",s.stock AS "stockQuantity",p.status
      FROM ${source} WHERE ${filter} ORDER BY s.stock ASC,p.name,s.label NULLS FIRST LIMIT ${pageSize} OFFSET ${offset}`, values),
    deps.pool.query(`SELECT count(*)::integer AS total FROM ${source} WHERE ${filter}`, values),
  ]);
  return { items: rows.rows.map(row => ({ ...row, stockState: stockState(row.stockQuantity) })), total: count.rows[0].total, page, pageSize };
}
async function setStock(deps: ShopDeps, actorId: string, input: Record<string, unknown>) {
  const productId = uuid(input.productId, 'Produit'); const variantId = optionalUuid(input.variantId, 'Variante');
  const quantity = integerField(input.stockQuantity, 'Stock', 0, 1_000_000);
  return inTransaction(deps, async client => {
    const found = variantId
      ? await client.query('SELECT stock_quantity FROM shop_product_variants WHERE id=$1 AND product_id=$2 FOR UPDATE', [variantId, productId])
      : await client.query('SELECT stock_quantity FROM shop_products WHERE id=$1 FOR UPDATE', [productId]);
    if (!found.rowCount) throw new HttpError(404, 'Article introuvable.');
    const old = found.rows[0].stock_quantity;
    await client.query(`UPDATE ${variantId ? 'shop_product_variants' : 'shop_products'} SET stock_quantity=$2,updated_at=now() WHERE id=$1`, [variantId || productId, quantity]);
    if (old !== quantity) await client.query(`INSERT INTO shop_stock_events(product_id,variant_id,actor_user_id,reason,old_quantity,new_quantity) VALUES($1,$2,$3,'manual',$4,$5)`,
      [productId, variantId, actorId, old, quantity]);
    return { productId, variantId, stockQuantity: quantity, stockState: stockState(quantity) };
  });
}

async function dashboard(deps: ShopDeps) {
  const [products, orders, banners, recent] = await Promise.all([
    deps.pool.query(`SELECT count(*)::integer AS total,
      count(*) FILTER (WHERE p.status='published')::integer AS published, count(*) FILTER (WHERE p.status='draft')::integer AS draft,
      count(*) FILTER (WHERE p.status='archived')::integer AS archived,
      count(*) FILTER (WHERE p.status<>'archived' AND ${effectiveStock} BETWEEN 1 AND ${LOW_STOCK_THRESHOLD})::integer AS "lowStock",
      count(*) FILTER (WHERE p.status<>'archived' AND ${effectiveStock} <= 0)::integer AS "outOfStock",
      count(*) FILTER (WHERE p.status='published' AND p.compare_at_price_ariary IS NOT NULL)::integer AS promotions
      FROM shop_products p LEFT JOIN LATERAL (SELECT count(*)::integer AS variant_count, COALESCE(sum(stock_quantity),0)::integer AS variant_stock
      FROM shop_product_variants v WHERE v.product_id=p.id AND v.active) vs ON true`),
    deps.pool.query(`SELECT count(*) FILTER (WHERE status='submitted')::integer AS "toConfirm", count(*)::integer AS total FROM shop_orders`),
    deps.pool.query(`SELECT count(*)::integer AS active FROM shop_banners WHERE active AND (start_at IS NULL OR start_at<=now()) AND (end_at IS NULL OR end_at>=now())`),
    deps.pool.query(`SELECT id,reference,concat_ws(' ',first_name,last_name) AS customer,total_ariary AS "totalAriary",status,created_at AS "createdAt"
      FROM shop_orders ORDER BY created_at DESC LIMIT 6`),
  ]);
  return { products: products.rows[0], orders: { ...orders.rows[0], recent: recent.rows }, banners: { active: banners.rows[0].active } };
}

// ---------------------------------------------------------------- routers
export async function shopRoute(deps: ShopDeps, req: IncomingMessage, res: ServerResponse, parts: string[], method: string, path: URL) {
  const { send } = deps;
  if (method === 'GET' && parts[2] === 'categories' && parts.length === 3) return send(res, 200, await publicCategories(deps));
  if (method === 'GET' && parts[2] === 'brands' && parts.length === 3) {
    const rows = await deps.pool.query(`SELECT b.id,b.name,b.slug,b.logo_media_id AS "logoId",(SELECT count(*)::integer FROM shop_products p JOIN shop_categories c ON c.id=p.category_id
      WHERE p.brand_id=b.id AND ${publicProduct}) AS "productCount" FROM shop_brands b WHERE b.active ORDER BY b.name`);
    return send(res, 200, rows.rows.map(row => ({ id: row.id, name: row.name, slug: row.slug, logoUrl: mediaUrl(row.logoId), productCount: row.productCount })));
  }
  if (method === 'GET' && parts[2] === 'products' && parts.length === 3) return send(res, 200, await listPublicProducts(deps, path));
  if (method === 'GET' && parts[2] === 'products' && parts[3] && parts.length === 4) return send(res, 200, await publicProduct_(deps, parts[3], path));
  if (method === 'GET' && parts[2] === 'banners' && parts.length === 3) {
    const rows = await deps.pool.query(`${bannerSelect} WHERE active AND (start_at IS NULL OR start_at<=now()) AND (end_at IS NULL OR end_at>=now())
      ORDER BY display_order,created_at LIMIT 10`);
    return send(res, 200, rows.rows.map(row => { const view = bannerView(row); return { id: view.id, title: view.title, subtitle: view.subtitle,
      ctaLabel: view.ctaLabel, ctaUrl: view.ctaUrl, desktopImageUrl: view.desktopImageUrl, mobileImageUrl: view.mobileImageUrl }; }));
  }
  if (method === 'GET' && parts[2] === 'media' && parts[3] && parts.length === 4) return sendMedia(deps, res, uuid(parts[3], 'Image'));
  if (method === 'POST' && parts[2] === 'orders' && parts.length === 3) return send(res, 201, await submitOrder(deps, req));
  throw new HttpError(404, 'Route introuvable.');
}

export async function commerceRoute(deps: ShopDeps, req: IncomingMessage, res: ServerResponse, parts: string[], method: string, path: URL) {
  const { send } = deps;
  const auth = await deps.requireRole(req, commerceRoles);
  const [, , section, id, sub, subId] = parts;
  if (method === 'GET' && section === 'dashboard' && parts.length === 3) return send(res, 200, await dashboard(deps));

  if (section === 'media' && method === 'PUT' && parts.length === 3) {
    deps.limit(`shop-media:${auth.userId}`, 120, 60 * 60_000);
    const mime = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    const image = await deps.photoBody(req, mime);
    const mediaId = randomUUID();
    await deps.pool.query('INSERT INTO shop_media(id,mime_type,image_data,byte_size,created_by_user_id) VALUES($1,$2,$3,$4,$5)', [mediaId, mime, image, image.length, auth.userId]);
    return send(res, 201, { id: mediaId, url: mediaUrl(mediaId) });
  }

  if (section === 'products') {
    if (method === 'GET' && parts.length === 3) return send(res, 200, await commerceProductList(deps, path));
    if (method === 'POST' && parts.length === 3) return send(res, 201, await saveProduct(deps, auth.userId, await deps.body(req)));
    const productId = uuid(id, 'Produit');
    if (method === 'GET' && parts.length === 4) return send(res, 200, await commerceProduct(deps.pool, productId));
    if (method === 'PATCH' && parts.length === 4) return send(res, 200, await saveProduct(deps, auth.userId, await deps.body(req), productId));
    if (method === 'PUT' && sub === 'variants' && parts.length === 5) return send(res, 200, await saveVariants(deps, productId, await jsonBody(deps, req)));
    if (method === 'PUT' && sub === 'fitments' && parts.length === 5) return send(res, 200, await saveFitments(deps, productId, await jsonBody(deps, req)));
    if (method === 'POST' && sub === 'images' && parts.length === 5) return send(res, 201, await addImage(deps, productId, await deps.body(req)));
    if (method === 'PATCH' && sub === 'images' && subId && parts.length === 6) return send(res, 200, await updateImage(deps, productId, uuid(subId, 'Image'), await deps.body(req)));
    if (method === 'DELETE' && sub === 'images' && subId && parts.length === 6) return send(res, 200, await deleteImage(deps, productId, uuid(subId, 'Image')));
  }
  if (section === 'categories') {
    if (method === 'GET' && parts.length === 3) {
      const rows = await deps.pool.query(`SELECT c.id,c.parent_id AS "parentId",c.name,c.slug,c.description,c.image_media_id AS "imageMediaId",c.display_order AS "displayOrder",c.active,
        (SELECT count(*)::integer FROM shop_products p WHERE p.category_id=c.id) AS "productCount" FROM shop_categories c ORDER BY c.display_order,c.name`);
      return send(res, 200, rows.rows.map(row => ({ ...row, imageUrl: mediaUrl(row.imageMediaId) })));
    }
    if (method === 'POST' && parts.length === 3) return send(res, 201, await saveCategory(deps, await deps.body(req)));
    if (method === 'PATCH' && parts.length === 4) return send(res, 200, await saveCategory(deps, await deps.body(req), uuid(id, 'Catégorie')));
  }
  if (section === 'brands') {
    if (method === 'GET' && parts.length === 3) {
      const rows = await deps.pool.query(`SELECT b.id,b.name,b.slug,b.logo_media_id AS "logoMediaId",b.active,(SELECT count(*)::integer FROM shop_products p WHERE p.brand_id=b.id) AS "productCount"
        FROM shop_brands b ORDER BY b.name`);
      return send(res, 200, rows.rows.map(row => ({ ...row, logoUrl: mediaUrl(row.logoMediaId) })));
    }
    if (method === 'POST' && parts.length === 3) return send(res, 201, await saveBrand(deps, await deps.body(req)));
    if (method === 'PATCH' && parts.length === 4) return send(res, 200, await saveBrand(deps, await deps.body(req), uuid(id, 'Marque')));
  }
  if (section === 'banners') {
    if (method === 'GET' && parts.length === 3) return send(res, 200, (await deps.pool.query(`${bannerSelect} ORDER BY display_order,created_at`)).rows.map(bannerView));
    if (method === 'POST' && parts.length === 3) return send(res, 201, await saveBanner(deps, auth.userId, await deps.body(req)));
    if (method === 'PATCH' && parts.length === 4) return send(res, 200, await saveBanner(deps, auth.userId, await deps.body(req), uuid(id, 'Publicité')));
    if (method === 'DELETE' && parts.length === 4) {
      // Only switched-off banners can be removed, so a live campaign is never deleted by accident.
      const removed = await deps.pool.query('DELETE FROM shop_banners WHERE id=$1 AND NOT active RETURNING id', [uuid(id, 'Publicité')]);
      if (!removed.rowCount) throw new HttpError(409, 'Désactivez la publicité avant de la supprimer.');
      return send(res, 200, { ok: true });
    }
  }
  if (section === 'stock') {
    if (method === 'GET' && parts.length === 3) return send(res, 200, await stockRows(deps, path));
    if (method === 'PATCH' && parts.length === 3) return send(res, 200, await setStock(deps, auth.userId, await deps.body(req)));
  }
  if (section === 'orders') {
    if (method === 'GET' && parts.length === 3) {
      const { values, p } = sqlParams(); const where = ['true'];
      const status = path.searchParams.get('status');
      if (status) where.push(`status=${p(oneOf(status, orderStatuses, 'Statut'))}`);
      const q = path.searchParams.get('q')?.trim();
      if (q) { if (q.length > 80) throw new HttpError(400, 'Recherche trop longue.'); const like = p(likePattern(q)); where.push(`(reference ILIKE ${like} OR first_name ILIKE ${like} OR last_name ILIKE ${like} OR phone ILIKE ${like})`); }
      const { page, pageSize, offset } = pageParams(path, 50);
      const [rows, count] = await Promise.all([
        deps.pool.query(`SELECT id,reference,concat_ws(' ',first_name,last_name) AS customer,phone,total_ariary AS "totalAriary",status,created_at AS "createdAt"
          FROM shop_orders WHERE ${where.join(' AND ')} ORDER BY created_at DESC,id LIMIT ${pageSize} OFFSET ${offset}`, values),
        deps.pool.query(`SELECT count(*)::integer AS total FROM shop_orders WHERE ${where.join(' AND ')}`, values),
      ]);
      return send(res, 200, { items: rows.rows, total: count.rows[0].total, page, pageSize });
    }
    if (method === 'GET' && parts.length === 4) return send(res, 200, await orderDetail(deps.pool, uuid(id, 'Commande')));
    if (method === 'PATCH' && sub === 'status' && parts.length === 5) {
      const to = oneOf((await deps.body(req)).status, orderStatuses, 'Statut');
      return send(res, 200, await changeOrderStatus(deps, auth.userId, uuid(id, 'Commande'), to));
    }
  }
  throw new HttpError(404, 'Route introuvable.');
}

// PUT is not covered by the global JSON content-type guard, so JSON PUT routes check it here.
async function jsonBody(deps: ShopDeps, req: IncomingMessage) {
  if (!req.headers['content-type']?.startsWith('application/json')) throw new HttpError(415, 'Content-Type application/json requis.');
  return deps.body(req);
}
