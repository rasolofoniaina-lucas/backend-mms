// Manual, idempotent catalogue curation. Run only after the API has applied schema.sql:
//   node dist/shop-showcase-seed.js
// No prices, stock or product photographs are inferred from the BIHR website.
import { randomUUID } from 'node:crypto';
import { Pool, type PoolClient } from 'pg';

type Selection = {
  reference: string; name: string; brand: string; category: string; short: string;
  source: string; featured?: boolean;
};

// Supplier references and names are from BIHR catalogue pages. The public site
// does not provide trustworthy live stock or professional prices without login.
const selection: Selection[] = [
  {
    reference: '1000519', name: 'Filtre à huile HIFLOFILTRO HF204', brand: 'HIFLOFILTRO', category: 'filtration',
    short: 'Filtre à huile moto, référence fabricant HF204.', featured: true,
    source: 'https://www.mybihr.com/fr/fr/all-products/catalogue/engine/c/NAV_852',
  },
  {
    reference: '1043292', name: 'Plaquettes BRAKING Off-Road 890CM46', brand: 'BRAKING', category: 'freinage',
    short: 'Plaquettes de frein semi-métalliques pour usage tout-terrain.', featured: true,
    source: 'https://www.mybihr.com/fr/fr/all-products/brands/braking/c/BRN_1062',
  },
  {
    reference: '3042704', name: 'Kit chaîne JT 420HDR 12/47 renforcée', brand: 'JT Drive Chain', category: 'transmission',
    short: 'Kit de transmission avec chaîne 420HDR, pignon et couronne standards.', featured: true,
    source: 'https://www.mybihr.com/fr/fr/all-products/brands/jt-drive-chain/jt-chain-kit-420hdr-12-47-reinforced---standard-rear-sprocket/p/3042704',
  },
  {
    reference: '1080626', name: 'Batterie lithium SKYRICH HJ01', brand: 'SKYRICH', category: 'batteries',
    short: 'Batterie moto lithium 12 V, 2 Ah. Dimensions et compatibilité à vérifier.', featured: true,
    source: 'https://www.mybihr.com/fr/fr/tous-les-produits/marques/skyrich/batterie-skyrich-lithium-ion---hj01/p/1080626',
  },
  {
    reference: '9005945', name: 'Pneu MICHELIN Road 6 160/60 ZR17', brand: 'MICHELIN', category: 'pneus',
    short: 'Pneu route arrière 160/60 ZR17 M/C (69W) TL.',
    source: 'https://www.mybihr.com/fr/fr/all-products/brands/michelin/c/BRN_1210',
  },
  {
    reference: '1122670', name: 'Lubrifiant chaîne MOTUL C2 Road 400 ml', brand: 'MOTUL', category: 'entretien-moto',
    short: 'Lubrifiant chaîne en aérosol pour usage routier, 400 ml.',
    source: 'https://www.mybihr.com/be/fr/all-products/catalogue/lubricant-%26-cleaners/chainlube/c/NAV_846',
  },
];

async function category(client: PoolClient, slug: string, name: string, parentId: string | null, order: number) {
  const found = await client.query<{ id: string }>('SELECT id FROM shop_categories WHERE slug=$1', [slug]);
  if (found.rows[0]) return found.rows[0].id;
  const id = randomUUID();
  await client.query('INSERT INTO shop_categories(id,parent_id,name,slug,display_order) VALUES($1,$2,$3,$4,$5)', [id, parentId, name, slug, order]);
  return id;
}

async function main() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL est requis.');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(481731, 3)');
    const moto = await category(client, 'pieces-moto', 'Pièces moto', null, 0);
    const categoryIds = new Map<string, string>();
    for (const [index, item] of [
      ['filtration', 'Filtration'], ['freinage', 'Freinage'], ['transmission', 'Transmission'], ['batteries', 'Batteries'],
    ].entries()) categoryIds.set(item[0], await category(client, item[0], item[1], moto, index * 10));
    categoryIds.set('pneus', await category(client, 'pneus', 'Pneus', null, 10));
    categoryIds.set('entretien-moto', await category(client, 'entretien-moto', 'Entretien moto', null, 20));
    let created = 0;
    for (const item of selection) {
      const sku = `BIHR-${item.reference}`;
      if ((await client.query('SELECT 1 FROM shop_products WHERE upper(sku)=$1', [sku])).rowCount) continue;
      const brandSlug = item.brand.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      const existingBrand = await client.query<{ id: string }>('SELECT id FROM shop_brands WHERE slug=$1', [brandSlug]);
      const brandId = existingBrand.rows[0]?.id ?? randomUUID();
      if (!existingBrand.rows[0]) await client.query('INSERT INTO shop_brands(id,name,slug) VALUES($1,$2,$3)', [brandId, item.brand, brandSlug]);
      const slug = item.name.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      const description = `${item.short}\nRéférence fournisseur BIHR : ${item.reference}. Vérifiez la compatibilité avec votre moto avant toute demande. Prix et disponibilité à confirmer auprès de MMS.`;
      await client.query(`INSERT INTO shop_products(id,sku,name,slug,short_description,description,category_id,brand_id,price_ariary,price_on_request,
        stock_quantity,compatibility_type,status,featured) VALUES($1,$2,$3,$4,$5,$6,$7,$8,0,true,0,'vehicle_specific','published',$9)`,
      [randomUUID(), sku, item.name, slug, item.short, description, categoryIds.get(item.category), brandId, item.featured ?? false]);
      created++;
    }
    const bannerTitle = 'L’essentiel pour votre moto';
    if (!(await client.query('SELECT 1 FROM shop_banners WHERE title=$1', [bannerTitle])).rowCount) {
      await client.query(`INSERT INTO shop_banners(id,title,subtitle,cta_label,cta_url,active,display_order)
        VALUES($1,$2,$3,'Explorer la sélection','/boutique/catalogue',true,0)`,
      [randomUUID(), bannerTitle, 'Pièces et entretien sélectionnés dans le catalogue BIHR. Prix et disponibilité sur demande.']);
    }
    await client.query('COMMIT');
    console.log(`Sélection BIHR : ${created} articles créés, ${selection.length - created} déjà présents.`);
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch(error => { console.error(error instanceof Error ? error.message : 'Initialisation de la vitrine impossible.'); process.exitCode = 1; });
