import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canTransition, hashPassword, staffEmail, temporaryPassword, validPassword, verifyPassword } from '../src/staff-domain.ts';

test('email staff normalisé et domaine strict', () => {
  assert.equal(staffEmail(' Jean.Rakoto@MMS.MG '), 'jean.rakoto@mms.mg');
  assert.equal(staffEmail('jean@example.com'), null);
  assert.equal(staffEmail('jean..rakoto@mms.mg'), null);
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
