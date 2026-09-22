import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canTransition, hashPassword, staffEmail, staffUsername, temporaryPassword, validPassword, verifyPassword } from '../src/staff-domain.ts';

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
