import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeMalagasyPhone } from '../src/phone.ts';

test('Orange et Yas utilisent la même normalisation E.164 sans zéro national', () => {
  assert.equal(normalizeMalagasyPhone('037 12 345 67'), '+261371234567');
  assert.equal(normalizeMalagasyPhone('034 12 345 67'), '+261341234567');
  assert.equal(normalizeMalagasyPhone('038 12 345 67'), '+261381234567');
  assert.equal(normalizeMalagasyPhone('+261341234567'), '+261341234567');
  assert.equal(normalizeMalagasyPhone('034 12 345 67').startsWith('+261034'), false);
  assert.equal(normalizeMalagasyPhone('038 12 345 67').startsWith('+261038'), false);
});

test('un numéro non malgache ou impossible est refusé', () => {
  assert.equal(normalizeMalagasyPhone('+33612345678'), null);
  assert.equal(normalizeMalagasyPhone('038'), null);
});
