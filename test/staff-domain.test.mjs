import assert from 'node:assert/strict';
import { test } from 'node:test';
import { allowedTransitions, canAssign, canTransition, isWaitingReason, maintenanceEntry, parseCompletion, hashPassword, staffEmail, staffUsername, temporaryPassword, validPassword, verifyPassword } from '../src/staff-domain.ts';

test('username staff et email facultatif normalisés', () => {
  assert.equal(staffUsername(' JRakoto '), 'jrakoto');
  assert.equal(staffUsername('2rakoto'), null);
  assert.equal(staffUsername('ab'), null);
  assert.equal(staffUsername('jean rakoto'), null);
  assert.equal(staffEmail(' Jean.Rakoto@MMS.MG '), 'jean.rakoto@mms.mg');
  assert.equal(staffEmail('jean@example.com'), 'jean@example.com');
  assert.equal(staffEmail(''), null);
  assert.equal(staffEmail('invalid'), null);
});
test('mot de passe Argon2id et temporaire non récupérable', async () => {
  const password = temporaryPassword();
  assert.ok(password.length >= 12);
  assert.ok(validPassword(password));
  const digest = await hashPassword(password);
  assert.match(digest, /^\$argon2id\$/);
  assert.ok(await verifyPassword(digest, password));
  assert.equal(await verifyPassword(digest, 'wrong-password'), false);
});
test('transitions RBAC tickets', () => {
  assert.ok(canTransition('new','triage','workshop_manager'));
  assert.ok(canTransition('assigned','in_progress','mechanic'));
  assert.ok(canTransition('in_progress','completed','mechanic'));
  assert.ok(canTransition('new','cancelled','customer'));
  assert.equal(canTransition('new','assigned','mechanic'), false);
  assert.equal(canTransition('assigned','completed','mechanic'), false);
  assert.equal(canTransition('in_progress','completed','admin'), false);
  assert.equal(canTransition('completed','in_progress','workshop_manager'), false);
});
test('actions proposées selon le rôle', () => {
  assert.deepEqual(allowedTransitions('assigned', 'mechanic'), ['in_progress']);
  assert.deepEqual(allowedTransitions('in_progress', 'mechanic'), ['waiting_customer', 'completed']);
  assert.deepEqual(allowedTransitions('in_progress', 'admin'), []);
  assert.deepEqual(allowedTransitions('completed', 'workshop_manager'), []);
});
test('le chef assigne directement une nouvelle demande', () => {
  assert.ok(canAssign('new'));
  assert.ok(canAssign('triage'));
  assert.ok(canAssign('assigned'));
  assert.equal(canAssign('in_progress'), false);
  assert.equal(canAssign('completed'), false);
});
test('motif d’attente obligatoire et contrôlé', () => {
  assert.ok(isWaitingReason('parts'));
  assert.equal(isWaitingReason('toString'), false);
  assert.equal(isWaitingReason(''), false);
});
test('fiche de clôture et ligne de carnet', () => {
  assert.equal(parseCompletion(undefined), null);
  const completion = parseCompletion({ operations: ['Vidange', ' Vidange ', 'Freins'], mileageKm: '12500', note: ' RAS ', customerMessage: 'Moto prête.' });
  assert.deepEqual(completion, { operations: ['Vidange', 'Freins'], mileageKm: 12500, note: 'RAS', customerMessage: 'Moto prête.' });
  const entry = maintenanceEntry(completion, 'En atelier');
  assert.equal(entry.title, 'Vidange, Freins');
  assert.match(entry.note, /^RAS\nKilométrage : 12\s?500 km$/u);
  assert.equal(maintenanceEntry(parseCompletion({}), 'À domicile').title, 'Intervention à domicile');
  assert.throws(() => parseCompletion({ mileageKm: -3 }), /Kilométrage/);
  assert.throws(() => parseCompletion({ operations: [42] }), /travaux/);
});
