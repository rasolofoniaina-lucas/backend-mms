// Shop data seeding, run by hand only:
//   node dist/shop-seed.js            -> MMS category taxonomy (idempotent, inserts missing slugs)
//   MMS_ALLOW_DEMO_SEED=1 node dist/shop-seed.js --demo
//                                     -> taxonomy + fictitious demo catalogue + commercial_demo account
// The demo mode is for local development only: it is never triggered by the API or by Compose.
import { randomUUID } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { Pool, type PoolClient } from 'pg';
import { hashPassword } from './staff-domain.js';

type CategorySeed = { slug: string; name: string; children?: Array<{ slug: string; name: string }> };
const taxonomy: CategorySeed[] = [
  { slug: 'pieces-moto', name: 'Pièces moto', children: [
    { slug: 'pieces-moteur', name: 'Pièces moteur' }, { slug: 'echappement', name: 'Échappement' }, { slug: 'freinage', name: 'Freinage' },
    { slug: 'transmission', name: 'Transmission' }, { slug: 'partie-cycle', name: 'Partie cycle' }, { slug: 'filtration', name: 'Filtration' },
    { slug: 'electrique', name: 'Électrique' }, { slug: 'batteries', name: 'Batteries' }, { slug: 'bougies', name: 'Bougies' },
    { slug: 'plastiques', name: 'Plastiques' }, { slug: 'guidons-commandes', name: 'Guidons / commandes' }, { slug: 'eclairage', name: 'Éclairage' },
  ] },
  { slug: 'pneus', name: 'Pneus' },
  { slug: 'equipement-pilote', name: 'Équipement pilote', children: [
    { slug: 'casques', name: 'Casques' }, { slug: 'lunettes-motocross', name: 'Lunettes motocross' }, { slug: 'gants', name: 'Gants' },
    { slug: 'vestes', name: 'Vestes' }, { slug: 'pantalons', name: 'Pantalons' }, { slug: 'bottes', name: 'Bottes' },
    { slug: 'protections-pilote', name: 'Protections pilote' }, { slug: 'equipement-motocross', name: 'Équipement motocross' },
    { slug: 'equipement-enduro', name: 'Équipement enduro' },
  ] },
  { slug: 'equipements-moto', name: 'Équipements moto', children: [
    { slug: 'protections-moto', name: 'Protections' }, { slug: 'bagagerie', name: 'Bagagerie' }, { slug: 'paddock-transport', name: 'Paddock / transport' },
  ] },
];

async function seedTaxonomy(client: PoolClient) {
  let created = 0;
  for (const [index, root] of taxonomy.entries()) {
    const rootId = await upsertCategory(client, root.slug, root.name, null, index * 10);
    if (rootId.created) created++;
    for (const [childIndex, child] of (root.children || []).entries()) {
      if ((await upsertCategory(client, child.slug, child.name, rootId.id, childIndex * 10)).created) created++;
    }
  }
  return created;
}
async function upsertCategory(client: PoolClient, slug: string, name: string, parentId: string | null, order: number) {
  const found = await client.query('SELECT id FROM shop_categories WHERE slug=$1', [slug]);
  if (found.rowCount) return { id: found.rows[0].id as string, created: false };
  const id = randomUUID();
  await client.query('INSERT INTO shop_categories(id,parent_id,name,slug,display_order) VALUES($1,$2,$3,$4,$5)', [id, parentId, name, slug, order]);
  return { id, created: true };
}

// ------------------------------------------------------------- tiny PNG generator for demo visuals
const crcTable = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
function crc32(buffer: Buffer) { let c = 0xffffffff; for (const byte of buffer) c = crcTable[(c ^ byte) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
function chunk(type: string, data: Buffer) {
  const length = Buffer.alloc(4); length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
}
/** Abstract gradient with a soft disc: a neutral placeholder, never a copied product photo. */
function demoPng(width: number, height: number, from: [number, number, number], to: [number, number, number], accent: [number, number, number]) {
  const raw = Buffer.alloc((width * 3 + 1) * height);
  const cx = width * 0.68, cy = height * 0.5, radius = Math.min(width, height) * 0.32;
  for (let y = 0; y < height; y++) {
    const row = y * (width * 3 + 1); raw[row] = 0;
    for (let x = 0; x < width; x++) {
      const t = (x / width + y / height) / 2;
      let pixel = from.map((value, index) => value + (to[index] - value) * t);
      const distance = Math.hypot(x - cx, y - cy);
      if (distance < radius) { const mix = 0.55 * Math.min(1, (radius - distance) / 18); pixel = pixel.map((value, index) => value + (accent[index] - value) * mix); }
      raw.set(pixel.map(Math.round), row + 1 + x * 3);
    }
  }
  const header = Buffer.alloc(13); header.writeUInt32BE(width, 0); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = 2;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', header), chunk('IDAT', deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}
const navy: [number, number, number] = [18, 59, 93]; const orange: [number, number, number] = [242, 140, 40];
const black: [number, number, number] = [23, 25, 28]; const offwhite: [number, number, number] = [245, 245, 247];
async function media(client: PoolClient, png: Buffer) {
  const id = randomUUID();
  await client.query('INSERT INTO shop_media(id,mime_type,image_data,byte_size) VALUES($1,$2,$3,$4)', [id, 'image/png', png, png.length]);
  return id;
}

type DemoProduct = { sku: string; name: string; category: string; brand: string; price: number; compareAt?: number; stock: number; short: string; description: string;
  featured?: boolean; isNew?: boolean; compatibility?: 'universal' | 'vehicle_specific'; colors: [[number, number, number], [number, number, number]];
  variants?: Array<{ sku: string; label: string; attributes: Record<string, string>; stock: number; price?: number }>;
  fitments?: Array<{ make: string; model?: string; yearMin?: number; yearMax?: number; cc?: number }> };
const demoProducts: DemoProduct[] = [
  { sku: 'DEMO-CASQ-MX1', name: 'Casque motocross Volana MX1', category: 'casques', brand: 'Volana Gear', price: 689000, compareAt: 790000, stock: 0, featured: true, isNew: true,
    short: 'Coque composite légère, ventilation généreuse.', description: 'Casque tout-terrain à coque composite, mousses amovibles et lavables, visière réglable. Produit de démonstration MMS.',
    colors: [navy, orange], variants: [
      { sku: 'DEMO-CASQ-MX1-S', label: 'Taille S', attributes: { taille: 'S' }, stock: 2 }, { sku: 'DEMO-CASQ-MX1-M', label: 'Taille M', attributes: { taille: 'M' }, stock: 6 },
      { sku: 'DEMO-CASQ-MX1-L', label: 'Taille L', attributes: { taille: 'L' }, stock: 4 }, { sku: 'DEMO-CASQ-MX1-XL', label: 'Taille XL', attributes: { taille: 'XL' }, stock: 0, price: 719000 }] },
  { sku: 'DEMO-GANT-AIR', name: 'Gants enduro Volana Air', category: 'gants', brand: 'Volana Gear', price: 89000, stock: 0, isNew: true,
    short: 'Paume renforcée, dos aéré.', description: 'Gants légers pour l’enduro et le motocross, paume renforcée et fermeture velcro. Produit de démonstration MMS.',
    colors: [black, orange], variants: [
      { sku: 'DEMO-GANT-AIR-M', label: 'Taille M', attributes: { taille: 'M' }, stock: 12 }, { sku: 'DEMO-GANT-AIR-L', label: 'Taille L', attributes: { taille: 'L' }, stock: 3 }] },
  { sku: 'DEMO-BOTT-TRK', name: 'Bottes cross Tsara Track', category: 'bottes', brand: 'Tsara Moto', price: 1150000, stock: 0, featured: true,
    short: 'Protection tibia et cheville, semelle cousue.', description: 'Bottes de motocross avec boucles alu, protection malléolaire et semelle remplaçable. Produit de démonstration MMS.',
    colors: [offwhite, navy], variants: [
      { sku: 'DEMO-BOTT-TRK-42', label: 'Pointure 42', attributes: { pointure: '42' }, stock: 2 }, { sku: 'DEMO-BOTT-TRK-43', label: 'Pointure 43', attributes: { pointure: '43' }, stock: 1 },
      { sku: 'DEMO-BOTT-TRK-44', label: 'Pointure 44', attributes: { pointure: '44' }, stock: 0 }] },
  { sku: 'DEMO-FILT-H01', name: 'Filtre à huile Rivotra H01', category: 'filtration', brand: 'Rivotra Parts', price: 32000, stock: 40, compatibility: 'vehicle_specific',
    short: 'Filtre à huile papier haute filtration.', description: 'Filtre à huile pour moteurs 4 temps. Vérifiez la compatibilité avec votre moto avant commande. Produit de démonstration MMS.',
    colors: [orange, black], fitments: [{ make: 'Yamaha', model: 'YZ250F', yearMin: 2019, yearMax: 2024 }, { make: 'Honda', model: 'CRF250R', yearMin: 2018, yearMax: 2024 }] },
  { sku: 'DEMO-PLAQ-F2', name: 'Plaquettes de frein avant Rivotra F2', category: 'freinage', brand: 'Rivotra Parts', price: 74000, compareAt: 89000, stock: 4, compatibility: 'vehicle_specific', featured: true,
    short: 'Mélange fritté, mordant constant.', description: 'Plaquettes avant frittées pour usage tout-terrain. Produit de démonstration MMS.',
    colors: [navy, black], fitments: [{ make: 'KTM', yearMin: 2017, yearMax: 2024 }] },
  { sku: 'DEMO-KIT-520', name: 'Kit chaîne 520 Rivotra', category: 'transmission', brand: 'Rivotra Parts', price: 265000, stock: 7, compatibility: 'vehicle_specific', isNew: true,
    short: 'Chaîne, pignon et couronne acier.', description: 'Kit chaîne complet au pas 520. Produit de démonstration MMS.',
    colors: [black, navy], fitments: [{ make: 'Yamaha', model: 'YZ250F', yearMin: 2014, yearMax: 2024, cc: 250 }] },
  { sku: 'DEMO-PNEU-MX', name: 'Pneu tout-terrain Tsara Grip', category: 'pneus', brand: 'Tsara Moto', price: 245000, stock: 0, compareAt: 275000,
    short: 'Crampons pour terrain mixte.', description: 'Pneu tout-terrain pour sols mixtes, carcasse renforcée. Produit de démonstration MMS.',
    colors: [black, offwhite], variants: [
      { sku: 'DEMO-PNEU-MX-80', label: '80/100-21 (avant)', attributes: { dimension: '80/100-21' }, stock: 5 },
      { sku: 'DEMO-PNEU-MX-110', label: '110/90-19 (arrière)', attributes: { dimension: '110/90-19' }, stock: 3, price: 265000 }] },
  { sku: 'DEMO-BATT-12', name: 'Batterie lithium Tsara 12V', category: 'batteries', brand: 'Tsara Moto', price: 385000, stock: 2, compatibility: 'vehicle_specific',
    short: 'Batterie légère sans entretien.', description: 'Batterie lithium 12 V. Compatibilité à confirmer avec l’atelier MMS. Produit de démonstration MMS.',
    colors: [orange, navy] },
];

async function seedDemo(client: PoolClient) {
  const categories = new Map((await client.query('SELECT id,slug FROM shop_categories')).rows.map(row => [row.slug, row.id]));
  const brands = new Map<string, string>();
  for (const name of ['Volana Gear', 'Tsara Moto', 'Rivotra Parts']) {
    const slug = name.toLowerCase().replace(/\s+/g, '-');
    const found = await client.query('SELECT id FROM shop_brands WHERE slug=$1', [slug]);
    const id = found.rows[0]?.id || randomUUID();
    if (!found.rowCount) await client.query('INSERT INTO shop_brands(id,name,slug) VALUES($1,$2,$3)', [id, name, slug]);
    brands.set(name, id);
  }
  let created = 0;
  for (const product of demoProducts) {
    if ((await client.query('SELECT 1 FROM shop_products WHERE upper(sku)=$1', [product.sku])).rowCount) continue;
    const id = randomUUID();
    const slug = product.name.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    await client.query(`INSERT INTO shop_products(id,sku,name,slug,short_description,description,category_id,brand_id,price_ariary,compare_at_price_ariary,stock_quantity,
      compatibility_type,status,featured,new_product) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'published',$13,$14)`,
      [id, product.sku, product.name, slug, product.short, product.description, categories.get(product.category), brands.get(product.brand), product.price,
        product.compareAt ?? null, product.stock, product.compatibility || 'universal', product.featured || false, product.isNew || false]);
    for (const [index, colors] of [product.colors, [product.colors[1], product.colors[0]] as typeof product.colors].entries()) {
      const mediaId = await media(client, demoPng(640, 640, colors[0], colors[1], offwhite));
      await client.query('INSERT INTO shop_product_images(id,product_id,media_id,alt_text,display_order,is_primary) VALUES($1,$2,$3,$4,$5,$6)',
        [randomUUID(), id, mediaId, `${product.name} – visuel ${index + 1}`, index, index === 0]);
    }
    for (const [index, variant] of (product.variants || []).entries()) {
      await client.query(`INSERT INTO shop_product_variants(id,product_id,sku,label,attributes,price_override_ariary,stock_quantity,display_order) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
        [randomUUID(), id, variant.sku, variant.label, JSON.stringify(variant.attributes), variant.price ?? null, variant.stock, index]);
    }
    for (const fitment of product.fitments || []) {
      await client.query('INSERT INTO shop_product_fitments(id,product_id,make,model,year_min,year_max,displacement_cc) VALUES($1,$2,$3,$4,$5,$6,$7)',
        [randomUUID(), id, fitment.make, fitment.model ?? null, fitment.yearMin ?? null, fitment.yearMax ?? null, fitment.cc ?? null]);
    }
    created++;
  }
  if (!(await client.query('SELECT 1 FROM shop_banners LIMIT 1')).rowCount) {
    const banners = [
      { title: 'Saison enduro', subtitle: 'Équipez-vous pour les pistes : casques, gants et bottes.', cta: 'Voir l’équipement', url: '/boutique?category=equipement-pilote', colors: [navy, black] as const },
      { title: 'Freinage au top', subtitle: 'Plaquettes en promotion ce mois-ci.', cta: 'Découvrir', url: '/boutique?promo=1', colors: [black, navy] as const },
    ];
    for (const [index, banner] of banners.entries()) {
      const desktop = await media(client, demoPng(1600, 560, banner.colors[0], banner.colors[1], orange));
      const mobile = await media(client, demoPng(800, 900, banner.colors[0], banner.colors[1], orange));
      await client.query(`INSERT INTO shop_banners(id,title,subtitle,desktop_media_id,mobile_media_id,cta_label,cta_url,active,display_order) VALUES($1,$2,$3,$4,$5,$6,$7,true,$8)`,
        [randomUUID(), banner.title, banner.subtitle, desktop, mobile, banner.cta, banner.url, index]);
    }
  }
  const demoUser = await client.query(`SELECT 1 FROM users WHERE lower(username)='commercial_demo'`);
  if (!demoUser.rowCount) {
    const userId = randomUUID();
    await client.query(`INSERT INTO users(id,role,username,first_name,last_name) VALUES($1,'commercial','commercial_demo','Commercial','Démo')`, [userId]);
    await client.query(`INSERT INTO user_identities(id,user_id,provider,provider_subject) VALUES($1,$2,'local','commercial_demo')`, [randomUUID(), userId]);
    await client.query(`INSERT INTO local_credentials(user_id,password_hash,must_change_password,password_changed_at) VALUES($1,$2,false,now())`,
      [userId, await hashPassword(demoPassword)]);
  }
  return created;
}
const demoPassword = 'CommercialDemo-2026';

async function main() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL est requis.');
  const demo = process.argv.includes('--demo');
  if (demo && process.env.MMS_ALLOW_DEMO_SEED !== '1') throw new Error('Données de démo refusées : relancez avec MMS_ALLOW_DEMO_SEED=1, uniquement en local.');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(481731, 2)');
    const categories = await seedTaxonomy(client);
    const products = demo ? await seedDemo(client) : 0;
    await client.query('COMMIT');
    console.log(`Catégories créées : ${categories}${demo ? `\nProduits de démo créés : ${products}\nCompte local : commercial_demo / ${demoPassword}` : ''}`);
  } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); await pool.end(); }
}
main().catch(error => { console.error(error instanceof Error ? error.message : 'Initialisation boutique impossible.'); process.exitCode = 1; });
