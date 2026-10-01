import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomInt, randomUUID } from 'node:crypto';

// Runs against the isolated B1 stack (test/run-b1-isolated.sh) or any MMS_TEST_MODE API.
const base = process.env.MMS_API_URL || 'http://127.0.0.1:3001';
const container = process.env.MMS_API_CONTAINER || 'mms-b1-test-api-1';
const run = randomUUID().slice(0, 8);
let ipCounter = randomInt(10, 200);
const nextIp = () => `198.18.${randomInt(0, 250)}.${(ipCounter = (ipCounter % 250) + 1)}`;

async function api(path, { method = 'GET', body, token, raw, contentType, ip } = {}) {
  const headers = { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(ip ? { 'X-Real-IP': ip } : {}) };
  if (raw) headers['Content-Type'] = contentType; else if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(`${base}/api${path}`, { method, headers, body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined) });
  const text = await response.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: response.status, data };
}
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC', 'base64');

function createAdmin(username, password) {
  const script = `import pg from 'pg'; import { randomUUID } from 'node:crypto'; import { hashPassword } from '/app/dist/staff-domain.js';
    const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL }); const id = randomUUID();
    await pool.query("INSERT INTO users(id,role,username,first_name,last_name) VALUES($1,'admin',$2,'Boutique','Admin')", [id, process.env.U]);
    await pool.query("INSERT INTO user_identities(id,user_id,provider,provider_subject) VALUES($1,$2,'local',$3)", [randomUUID(), id, process.env.U]);
    await pool.query("INSERT INTO local_credentials(user_id,password_hash,must_change_password,password_changed_at) VALUES($1,$2,false,now())", [id, await hashPassword(process.env.P)]);
    await pool.end();`;
  execFileSync('docker', ['exec', '-e', `U=${username}`, '-e', `P=${password}`, '-w', '/app', container, 'node', '--input-type=module', '-e', script]);
}
async function staffLogin(username, password) {
  const login = await api('/staff/login', { method: 'POST', body: { username, password }, ip: nextIp() });
  assert.equal(login.status, 200, `connexion ${username}`);
  return login.data;
}
async function createStaff(adminToken, role) {
  const username = `${role.slice(0, 4)}_${run}`;
  const created = await api('/admin/users', { method: 'POST', token: adminToken, body: { role, username, firstName: 'Recette', lastName: role } });
  assert.equal(created.status, 201, `création ${role}`);
  const first = await staffLogin(username, created.data.temporaryPassword);
  assert.equal(first.user.mustChangePassword, true);
  if (role === 'commercial') assert.equal((await api('/commerce/dashboard', { token: first.accessToken })).status, 403, 'mot de passe à changer d’abord');
  const permanent = `Shop-${randomUUID()}`;
  assert.equal((await api('/staff/change-password', { method: 'POST', token: first.accessToken, body: { currentPassword: created.data.temporaryPassword, newPassword: permanent } })).status, 200);
  const login = await staffLogin(username, permanent);
  return { id: created.data.id, token: login.accessToken, user: login.user };
}

test('Boutique S1 : RBAC commercial, catalogue, publicités, commandes et stock', async t => {
  const adminUsername = `shopadmin_${run}`; const adminPassword = `Admin-${randomUUID()}`;
  createAdmin(adminUsername, adminPassword);
  const admin = (await staffLogin(adminUsername, adminPassword)).accessToken;
  const commercial = await createStaff(admin, 'commercial');
  const mechanic = await createStaff(admin, 'mechanic');
  const manager = await createStaff(admin, 'workshop_manager');
  const customerPhone = `+2613815${randomInt(10000, 99999)}`;
  const registered = await api('/auth/customer-register', { method: 'POST', ip: nextIp(), body: { firstName: 'Client', lastName: 'Boutique', phone: customerPhone, email: `shop.${run}@example.test`, password: 'password123' } });
  assert.equal(registered.status, 201);
  const customer = registered.data.accessToken;
  const c = commercial.token;

  await t.test('RBAC : seuls commercial et admin accèdent au commerce', async () => {
    assert.equal(commercial.user.role, 'commercial');
    assert.equal((await api('/commerce/dashboard', { token: c })).status, 200);
    assert.equal((await api('/commerce/dashboard', { token: admin })).status, 200);
    assert.equal((await api('/commerce/dashboard', { token: mechanic.token })).status, 403);
    assert.equal((await api('/commerce/dashboard', { token: manager.token })).status, 403);
    assert.equal((await api('/commerce/dashboard', { token: customer })).status, 403);
    assert.equal((await api('/commerce/dashboard')).status, 401);
    assert.equal((await api('/commerce/products', { method: 'POST', body: {} })).status, 401);
  });
  await t.test('RBAC : le commercial ne touche ni admin ni atelier ni rôles', async () => {
    assert.equal((await api('/admin/users', { token: c })).status, 403);
    assert.equal((await api('/admin/users', { method: 'POST', token: c, body: { role: 'admin', username: `pirate_${run}`, firstName: 'X', lastName: 'Y' } })).status, 403);
    assert.equal((await api(`/admin/users/${commercial.id}/role`, { method: 'PATCH', token: c, body: { role: 'admin' } })).status, 403);
    assert.equal((await api('/staff/tickets', { token: c })).status, 403);
    assert.equal((await api('/staff/schedule', { token: c })).status, 403);
    assert.equal((await api('/staff/summary', { token: c })).status, 403);
    assert.equal((await api('/staff/me', { token: c })).data.role, 'commercial');
    assert.equal((await api('/admin/users?role=commercial', { token: admin })).data.some(user => user.id === commercial.id), true);
  });

  // ---------------------------------------------------------------- taxonomy
  let root, child, grandchild, brand;
  await t.test('catégories : arborescence, slug, cycles et profondeur', async () => {
    root = (await api('/commerce/categories', { method: 'POST', token: c, body: { name: `Racine ${run}` } })).data;
    assert.match(root.slug, /^racine-/);
    child = (await api('/commerce/categories', { method: 'POST', token: c, body: { name: `Enfant ${run}`, parentId: root.id } })).data;
    grandchild = (await api('/commerce/categories', { method: 'POST', token: c, body: { name: `Petit ${run}`, parentId: child.id } })).data;
    assert.equal(grandchild.parentId, child.id);
    assert.equal((await api('/commerce/categories', { method: 'POST', token: c, body: { name: `Trop ${run}`, parentId: grandchild.id } })).status, 409, 'trois niveaux maximum');
    assert.equal((await api(`/commerce/categories/${root.id}`, { method: 'PATCH', token: c, body: { parentId: grandchild.id } })).status, 409, 'boucle refusée');
    assert.equal((await api(`/commerce/categories/${root.id}`, { method: 'PATCH', token: c, body: { parentId: root.id } })).status, 409);
    assert.equal((await api('/commerce/categories', { method: 'POST', token: c, body: { name: '<b>x</b>' } })).status, 400, 'pas de HTML');
    const renamed = await api(`/commerce/categories/${child.id}`, { method: 'PATCH', token: c, body: { displayOrder: 3, description: 'Sous-catégorie' } });
    assert.equal(renamed.data.displayOrder, 3);
  });
  await t.test('marques : création, unicité, désactivation', async () => {
    brand = (await api('/commerce/brands', { method: 'POST', token: c, body: { name: `Marque ${run}` } })).data;
    assert.equal((await api('/commerce/brands', { method: 'POST', token: c, body: { name: `marque ${run}` } })).status, 409);
    assert.equal((await api(`/commerce/brands/${brand.id}`, { method: 'PATCH', token: c, body: { active: true } })).status, 200);
  });

  // ---------------------------------------------------------------- uploads
  let mediaId;
  await t.test('uploads : MIME réel, taille, SVG refusé', async () => {
    const ok = await api('/commerce/media', { method: 'PUT', token: c, raw: png, contentType: 'image/png' });
    assert.equal(ok.status, 201); mediaId = ok.data.id;
    const served = await fetch(`${base}${ok.data.url}`);
    assert.equal(served.headers.get('content-type'), 'image/png');
    assert.equal(served.headers.get('x-content-type-options'), 'nosniff');
    assert.equal((await api('/commerce/media', { method: 'PUT', token: c, raw: Buffer.from('<svg onload="alert(1)"/>'), contentType: 'image/svg+xml' })).status, 415);
    assert.equal((await api('/commerce/media', { method: 'PUT', token: c, raw: Buffer.from('GIF89a-not-a-png'), contentType: 'image/png' })).status, 400);
    assert.equal((await api('/commerce/media', { method: 'PUT', token: c, raw: Buffer.alloc(5 * 1024 * 1024 + 10, 1), contentType: 'image/jpeg' })).status, 413);
    assert.equal((await api('/commerce/media', { method: 'PUT', token: mechanic.token, raw: png, contentType: 'image/png' })).status, 403);
  });

  // ---------------------------------------------------------------- products
  const sku = suffix => `T${run}-${suffix}`.toUpperCase();
  let universal, specific, unknown, sized;
  await t.test('produits : brouillon invisible, publication, validation', async () => {
    const draft = await api('/commerce/products', { method: 'POST', token: c, body: { name: `Huile ${run}`, sku: sku('OIL'), categoryId: grandchild.id, brandId: brand.id, priceAriary: 10000, stockQuantity: 3, newProduct: true } });
    assert.equal(draft.status, 201); universal = draft.data;
    assert.equal(universal.status, 'draft');
    assert.equal((await api(`/shop/products/${universal.slug}`)).status, 404, 'brouillon invisible');
    assert.equal((await api(`/shop/products?q=${encodeURIComponent(universal.sku)}`)).data.total, 0);
    assert.equal((await api('/commerce/products', { method: 'POST', token: c, body: { name: 'Doublon', sku: sku('oil'), categoryId: root.id, priceAriary: 1 } })).status, 409, 'SKU unique');
    assert.equal((await api('/commerce/products', { method: 'POST', token: c, body: { name: 'Prix', sku: sku('P1'), categoryId: root.id, priceAriary: 100, compareAtPriceAriary: 90 } })).status, 400);
    assert.equal((await api('/commerce/products', { method: 'POST', token: c, body: { name: 'Prix', sku: sku('P2'), categoryId: root.id, priceAriary: 1.5 } })).status, 400, 'prix entier');
    assert.equal((await api('/commerce/products', { method: 'POST', token: c, body: { name: '<img src=x onerror=alert(1)>', sku: sku('P3'), categoryId: root.id, priceAriary: 100 } })).status, 400);
    const published = await api(`/commerce/products/${universal.id}`, { method: 'PATCH', token: c, body: { status: 'published', compareAtPriceAriary: 12000 } });
    assert.equal(published.status, 200); assert.equal(published.data.status, 'published');
    const image = await api(`/commerce/products/${universal.id}/images`, { method: 'POST', token: c, body: { mediaId, altText: 'Bidon' } });
    assert.equal(image.data.images[0].isPrimary, true);
    const page = await api(`/shop/products/${universal.slug}`);
    assert.equal(page.status, 200); assert.equal(page.data.promo, true); assert.equal(page.data.images[0].alt, 'Bidon');
    assert.deepEqual(page.data.breadcrumb.map(item => item.slug), [root.slug, child.slug, grandchild.slug]);

    specific = (await api('/commerce/products', { method: 'POST', token: c, body: { name: `Filtre ${run}`, sku: sku('FLT'), categoryId: child.id, priceAriary: 30000, stockQuantity: 10, compatibilityType: 'vehicle_specific', status: 'published' } })).data;
    const fitted = await api(`/commerce/products/${specific.id}/fitments`, { method: 'PUT', token: c, body: { fitments: [{ make: 'Yamaha', model: 'YZ250F', yearMin: 2019, yearMax: 2024 }] } });
    assert.equal(fitted.data.fitments.length, 1);
    assert.equal((await api(`/commerce/products/${specific.id}/fitments`, { method: 'PUT', token: c, body: { fitments: [{ make: 'Yamaha', yearMin: 2024, yearMax: 2019 }] } })).status, 400);
    unknown = (await api('/commerce/products', { method: 'POST', token: c, body: { name: `Batterie ${run}`, sku: sku('BAT'), categoryId: child.id, priceAriary: 50000, stockQuantity: 2, compatibilityType: 'vehicle_specific', status: 'published' } })).data;
    sized = (await api('/commerce/products', { method: 'POST', token: c, body: { name: `Casque ${run}`, sku: sku('HLM'), categoryId: root.id, brandId: brand.id, priceAriary: 400000, status: 'published', featured: true } })).data;
    const variants = await api(`/commerce/products/${sized.id}/variants`, { method: 'PUT', token: c, body: { variants: [
      { sku: sku('HLM-S'), label: 'Taille S', attributes: { taille: 'S' }, stockQuantity: 1 },
      { sku: sku('HLM-XL'), label: 'Taille XL', attributes: { taille: 'XL' }, stockQuantity: 0, priceOverrideAriary: 420000 }] } });
    assert.equal(variants.status, 200); assert.equal(variants.data.variants.length, 2);
    assert.equal((await api(`/commerce/products/${sized.id}/variants`, { method: 'PUT', token: c, body: { variants: [{ sku: sku('BAD'), label: 'x', attributes: { 'Bad Key': 1 } }] } })).status, 400);
    sized = variants.data;
  });
  await t.test('recherche, filtres, tri et pagination publics', async () => {
    const bySku = await api(`/shop/products?q=${encodeURIComponent(sku('flt'))}`);
    assert.deepEqual(bySku.data.items.map(item => item.id), [specific.id]);
    const tree = await api(`/shop/products?category=${root.slug}&pageSize=48`);
    assert.equal(tree.data.total, 4, 'la catégorie racine inclut ses descendants');
    assert.equal((await api(`/shop/products?category=${grandchild.slug}`)).data.total, 1);
    assert.equal((await api(`/shop/products?brand=${brand.slug}`)).data.total, 2);
    assert.equal((await api(`/shop/products?category=${root.slug}&promo=1`)).data.total, 1);
    assert.equal((await api(`/shop/products?category=${root.slug}&new=1`)).data.total, 1);
    assert.equal((await api(`/shop/products?category=${root.slug}&minPrice=40000&maxPrice=60000`)).data.total, 1);
    const sorted = await api(`/shop/products?category=${root.slug}&sort=price_asc`);
    assert.deepEqual(sorted.data.items.map(item => item.priceAriary), [10000, 30000, 50000, 400000]);
    const paged = await api(`/shop/products?category=${root.slug}&sort=name&pageSize=1&page=2`);
    assert.equal(paged.data.items.length, 1); assert.equal(paged.data.total, 4);
    assert.equal((await api('/shop/products?sort=evil')).status, 400);
    assert.equal((await api(`/shop/products?q=${encodeURIComponent("'; DROP TABLE shop_products; --")}`)).status, 200, 'SQL paramétré');
    assert.equal((await api(`/shop/products?q=${encodeURIComponent('%')}&category=${root.slug}`)).data.total, 0, 'jokers échappés');
  });
  await t.test('compatibilité avec ma moto', async () => {
    const yamaha = 'vehicleMake=Yamaha&vehicleModel=YZ250F&vehicleYear=2024&vehicleCc=250';
    const all = await api(`/shop/products?category=${root.slug}&${yamaha}`);
    const status = Object.fromEntries(all.data.items.map(item => [item.id, item.compatibility]));
    assert.equal(status[universal.id], 'compatible'); assert.equal(status[specific.id], 'compatible'); assert.equal(status[unknown.id], 'unknown');
    const only = await api(`/shop/products?category=${root.slug}&${yamaha}&compatible=1`);
    assert.deepEqual(new Set(only.data.items.map(item => item.id)), new Set([universal.id, specific.id, sized.id]));
    const honda = await api(`/shop/products/${specific.slug}?vehicleMake=Honda&vehicleModel=CRF250R&vehicleYear=2020`);
    assert.equal(honda.data.compatibility, 'incompatible');
    const noModel = await api(`/shop/products/${specific.slug}?vehicleMake=Yamaha&vehicleYear=2020`);
    assert.equal(noModel.data.compatibility, 'unknown', 'données moto insuffisantes');
  });

  // ---------------------------------------------------------------- banners
  await t.test('publicités : programmation, liens sûrs, suppression', async () => {
    const day = 24 * 3600_000; const now = Date.now();
    const live = await api('/commerce/banners', { method: 'POST', token: c, body: { title: `Live ${run}`, active: true, ctaLabel: 'Voir', ctaUrl: '/boutique?promo=1', desktopMediaId: mediaId } });
    assert.equal(live.status, 201); assert.equal(live.data.state, 'active');
    const scheduled = await api('/commerce/banners', { method: 'POST', token: c, body: { title: `Future ${run}`, active: true, startAt: new Date(now + day).toISOString() } });
    assert.equal(scheduled.data.state, 'scheduled');
    const expired = await api('/commerce/banners', { method: 'POST', token: c, body: { title: `Passée ${run}`, active: true, startAt: new Date(now - 3 * day).toISOString(), endAt: new Date(now - day).toISOString() } });
    assert.equal(expired.data.state, 'expired');
    const off = await api('/commerce/banners', { method: 'POST', token: c, body: { title: `Off ${run}`, active: false } });
    assert.equal(off.data.state, 'inactive');
    const visible = (await api('/shop/banners')).data.map(banner => banner.title);
    assert.ok(visible.includes(`Live ${run}`));
    for (const hidden of [`Future ${run}`, `Passée ${run}`, `Off ${run}`]) assert.ok(!visible.includes(hidden), hidden);
    assert.equal((await api('/commerce/banners', { method: 'POST', token: c, body: { title: 'XSS', ctaUrl: 'javascript:alert(1)' } })).status, 400);
    assert.equal((await api('/commerce/banners', { method: 'POST', token: c, body: { title: 'Dates', startAt: new Date(now + day).toISOString(), endAt: new Date(now).toISOString() } })).status, 400);
    assert.equal((await api(`/commerce/banners/${live.data.id}`, { method: 'DELETE', token: c })).status, 409, 'campagne active protégée');
    assert.equal((await api(`/commerce/banners/${live.data.id}`, { method: 'PATCH', token: c, body: { active: false } })).status, 200);
    assert.equal((await api(`/commerce/banners/${live.data.id}`, { method: 'DELETE', token: c })).status, 200);
  });

  // ---------------------------------------------------------------- orders and stock
  const contact = { firstName: 'Rado', lastName: 'Client', phone: '0341234567', email: `order.${run}@example.test` };
  const order = (items, extra = {}) => api('/shop/orders', { method: 'POST', ip: nextIp(), body: { ...contact, items, ...extra }, token: extra.token });
  const stockOf = async id => (await api(`/commerce/products/${id}`, { token: c })).data;
  let first, second;
  await t.test('commande : prix recalculés côté serveur et contrôles', async () => {
    const tampered = await order([{ productId: universal.id, quantity: 2, priceAriary: 1 }], { totalAriary: 2, subtotalAriary: 2 });
    assert.equal(tampered.status, 201);
    assert.equal(tampered.data.totalAriary, 20000); assert.equal(tampered.data.items[0].unitPriceAriary, 10000);
    assert.match(tampered.data.reference, /^CMD-\d{4}-\d{6}$/);
    first = tampered.data;
    assert.equal((await stockOf(universal.id)).stockQuantity, 3, 'pas de décrément à la soumission');
    assert.equal((await order([{ productId: universal.id, quantity: 4 }])).status, 409, 'stock insuffisant');
    assert.equal((await order([{ productId: sized.id, quantity: 1 }])).status, 400, 'variante requise');
    const variant = sized.variants.find(item => item.label === 'Taille XL');
    assert.equal((await order([{ productId: sized.id, variantId: variant.id, quantity: 1 }])).status, 409, 'variante en rupture');
    const draft = (await api('/commerce/products', { method: 'POST', token: c, body: { name: `Brouillon ${run}`, sku: sku('DRF'), categoryId: root.id, priceAriary: 5000, stockQuantity: 5 } })).data;
    assert.equal((await order([{ productId: draft.id, quantity: 1 }])).status, 409, 'brouillon non commandable');
    assert.equal((await order([], {})).status, 400);
    const linked = await order([{ productId: universal.id, quantity: 2 }], { token: customer });
    assert.equal(linked.status, 201); second = linked.data;
    const orders = await api(`/commerce/orders?q=${encodeURIComponent(second.reference)}`, { token: c });
    const detail = await api(`/commerce/orders/${orders.data.items[0].id}`, { token: c });
    assert.ok(detail.data.customerId, 'commande rattachée au client connecté');
    assert.deepEqual(detail.data.nextStatuses, ['confirmed', 'cancelled']);
    second.id = detail.data.id;
    first.id = (await api(`/commerce/orders?q=${encodeURIComponent(first.reference)}`, { token: c })).data.items[0].id;
  });
  await t.test('commande : confirmation transactionnelle du stock et transitions', async () => {
    const confirmed = await api(`/commerce/orders/${first.id}/status`, { method: 'PATCH', token: c, body: { status: 'confirmed' } });
    assert.equal(confirmed.status, 200);
    assert.equal((await stockOf(universal.id)).stockQuantity, 1);
    const refused = await api(`/commerce/orders/${second.id}/status`, { method: 'PATCH', token: c, body: { status: 'confirmed' } });
    assert.equal(refused.status, 409, 'stock insuffisant à la confirmation');
    assert.equal((await stockOf(universal.id)).stockQuantity, 1, 'jamais négatif');
    assert.equal((await api(`/commerce/orders/${first.id}/status`, { method: 'PATCH', token: c, body: { status: 'completed' } })).status, 409, 'transition arbitraire refusée');
    assert.equal((await api(`/commerce/orders/${second.id}/status`, { method: 'PATCH', token: c, body: { status: 'cancelled' } })).status, 200);
    assert.equal((await api(`/commerce/orders/${first.id}/status`, { method: 'PATCH', token: c, body: { status: 'cancelled' } })).status, 200);
    assert.equal((await stockOf(universal.id)).stockQuantity, 3, 'annulation après confirmation : stock rendu');
    const history = await api(`/commerce/orders/${first.id}`, { token: c });
    assert.deepEqual(history.data.events.map(event => event.newStatus), ['submitted', 'confirmed', 'cancelled']);
    assert.equal((await api(`/commerce/orders/${first.id}/status`, { method: 'PATCH', token: mechanic.token, body: { status: 'confirmed' } })).status, 403);
  });
  await t.test('commande : deux confirmations simultanées ne survendent pas', async () => {
    const a = await order([{ productId: universal.id, quantity: 2 }]); const b = await order([{ productId: universal.id, quantity: 2 }]);
    const ids = await Promise.all([a, b].map(async created => (await api(`/commerce/orders?q=${encodeURIComponent(created.data.reference)}`, { token: c })).data.items[0].id));
    const results = await Promise.all(ids.map(id => api(`/commerce/orders/${id}/status`, { method: 'PATCH', token: c, body: { status: 'confirmed' } })));
    assert.deepEqual(results.map(result => result.status).sort(), [200, 409]);
    assert.equal((await stockOf(universal.id)).stockQuantity, 1);
  });
  await t.test('stock : écran dédié et ajustement validé', async () => {
    const xl = sized.variants.find(item => item.label === 'Taille XL');
    const out = await api(`/commerce/stock?state=out&q=${encodeURIComponent(sku('HLM'))}`, { token: c });
    assert.ok(out.data.items.some(item => item.variantId === xl.id));
    assert.equal((await api('/commerce/stock', { method: 'PATCH', token: c, body: { productId: sized.id, variantId: xl.id, stockQuantity: -1 } })).status, 400);
    const updated = await api('/commerce/stock', { method: 'PATCH', token: c, body: { productId: sized.id, variantId: xl.id, stockQuantity: 4 } });
    assert.equal(updated.data.stockState, 'low_stock');
    assert.equal((await api('/commerce/stock', { method: 'PATCH', token: manager.token, body: { productId: sized.id, stockQuantity: 4 } })).status, 403);
    const dashboard = await api('/commerce/dashboard', { token: c });
    assert.ok(dashboard.data.products.published >= 4); assert.ok(dashboard.data.orders.recent.length >= 1);
  });
});
