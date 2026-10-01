import test from 'node:test';
import assert from 'node:assert/strict';
import {
  bannerState, canTransitionOrder, compatibilityFor, normalizeOrderLines, orderHoldsStock, orderReference, safeCtaUrl, slugify,
  stockState, validSku, validSlug, variantAttributes,
} from '../src/shop-domain.ts';
import { isStaffRole, canTransition } from '../src/staff-domain.ts';

const P = '11111111-1111-4111-8111-111111111111';
const V = '22222222-2222-4222-8222-222222222222';

test('rôle commercial : staff, sans pouvoir atelier', () => {
  assert.equal(isStaffRole('commercial'), true);
  assert.equal(canTransition('new', 'triage', 'commercial'), false);
});

test('transitions de commande autorisées uniquement', () => {
  assert.equal(canTransitionOrder('submitted', 'confirmed'), true);
  assert.equal(canTransitionOrder('confirmed', 'preparing'), true);
  assert.equal(canTransitionOrder('preparing', 'ready'), true);
  assert.equal(canTransitionOrder('ready', 'completed'), true);
  assert.equal(canTransitionOrder('submitted', 'cancelled'), true);
  assert.equal(canTransitionOrder('confirmed', 'cancelled'), true);
  for (const [from, to] of [['submitted', 'completed'], ['preparing', 'cancelled'], ['ready', 'cancelled'], ['completed', 'cancelled'], ['cancelled', 'submitted'], ['submitted', 'preparing']]) {
    assert.equal(canTransitionOrder(from, to), false, `${from} -> ${to}`);
  }
  assert.equal(orderHoldsStock('submitted'), false);
  assert.equal(orderHoldsStock('confirmed'), true);
});

test('compatibilité moto : jamais « compatible » sans preuve', () => {
  const vehicle = { make: 'Yamaha', model: 'YZ250F', year: 2024, displacementCc: 250 };
  assert.equal(compatibilityFor('universal', [], null), 'compatible');
  assert.equal(compatibilityFor('vehicle_specific', [], vehicle), 'unknown');
  const fits = [{ make: 'yamaha', model: 'yz250f', yearMin: 2019, yearMax: 2024, displacementCc: null }];
  assert.equal(compatibilityFor('vehicle_specific', fits, vehicle), 'compatible');
  assert.equal(compatibilityFor('vehicle_specific', fits, { ...vehicle, year: 2015 }), 'incompatible');
  assert.equal(compatibilityFor('vehicle_specific', fits, { ...vehicle, make: 'Honda' }), 'incompatible');
  assert.equal(compatibilityFor('vehicle_specific', fits, { ...vehicle, model: '' }), 'unknown');
  assert.equal(compatibilityFor('vehicle_specific', fits, { ...vehicle, year: null }), 'unknown');
  assert.equal(compatibilityFor('vehicle_specific', [{ make: 'KTM', model: null, yearMin: null, yearMax: null, displacementCc: 250 }], { make: 'KTM', model: 'EXC', year: 2020, displacementCc: null }), 'unknown');
  assert.equal(compatibilityFor('vehicle_specific', fits, null), 'unknown');
});

test('états de bannière selon la programmation', () => {
  const now = new Date('2026-10-01T12:00:00Z');
  assert.equal(bannerState({ active: false, startAt: null, endAt: null }, now), 'inactive');
  assert.equal(bannerState({ active: true, startAt: null, endAt: null }, now), 'active');
  assert.equal(bannerState({ active: true, startAt: '2026-10-05T00:00:00Z', endAt: null }, now), 'scheduled');
  assert.equal(bannerState({ active: true, startAt: null, endAt: '2026-09-30T00:00:00Z' }, now), 'expired');
});

test('liens de bannière sûrs uniquement', () => {
  for (const url of ['', '/boutique', '/boutique?promo=1', 'https://mms.mg/boutique']) assert.equal(safeCtaUrl(url), true, url);
  for (const url of ['javascript:alert(1)', '//evil.example', 'http://insecure.example', 'data:text/html,x', '/a b', '/"><script>']) assert.equal(safeCtaUrl(url), false, url);
});

test('panier : fusion, bornes et identifiants', () => {
  assert.deepEqual(normalizeOrderLines([{ productId: P, quantity: 2 }, { productId: P, quantity: 3 }, { productId: P, variantId: V, quantity: 1 }]),
    [{ productId: P, variantId: null, quantity: 5 }, { productId: P, variantId: V, quantity: 1 }]);
  assert.equal(normalizeOrderLines([]), null);
  assert.equal(normalizeOrderLines([{ productId: P, quantity: 0 }]), null);
  assert.equal(normalizeOrderLines([{ productId: P, quantity: 1.5 }]), null);
  assert.equal(normalizeOrderLines([{ productId: P, quantity: 60 }, { productId: P, quantity: 60 }]), null);
  assert.equal(normalizeOrderLines([{ productId: 'x', quantity: 1 }]), null);
  assert.equal(normalizeOrderLines([{ productId: P, quantity: 1, priceAriary: 1 }]).length, 1, 'un prix client est ignoré');
  assert.equal(normalizeOrderLines(Array.from({ length: 31 }, () => ({ productId: P, quantity: 1 }))), null);
});

test('slugs, SKU, attributs, stock et références', () => {
  assert.equal(slugify('Équipement Pilote / Été 2026'), 'equipement-pilote-ete-2026');
  assert.equal(validSlug('casques-mx'), true); assert.equal(validSlug('../etc'), false);
  assert.equal(validSku('CASQ-MX1_L.2'), true); assert.equal(validSku('<script>'), false);
  assert.deepEqual(variantAttributes({ taille: ' M ' }), { taille: 'M' });
  assert.equal(variantAttributes({ 'Bad Key': 'x' }), null);
  assert.equal(variantAttributes([1]), null);
  assert.equal(stockState(0), 'out_of_stock'); assert.equal(stockState(5), 'low_stock'); assert.equal(stockState(6), 'in_stock');
  assert.equal(orderReference('42', new Date('2026-10-01')), 'CMD-2026-000042');
});
