import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { randomUUID } from 'node:crypto';
import { Pool } from 'pg';
import { hashPassword, staffEmail, temporaryPassword } from './staff-domain.js';

async function main() {
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL est requis.');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const ui = stdin.isTTY ? createInterface({ input: stdin, output: stdout }) : null;
try {
  const existing = await pool.query(`SELECT 1 FROM users WHERE role='admin' LIMIT 1`);
  if (existing.rowCount) throw new Error('Un administrateur existe déjà. Utilisez un administrateur connecté pour créer les suivants.');
  let firstName: string; let lastName: string; let rawEmail: string;
  if (ui) {
    firstName = (await ui.question('Prénom : ')).trim();
    lastName = (await ui.question('Nom : ')).trim();
    rawEmail = await ui.question('Email @mms.mg : ');
  } else {
    let raw = ''; for await (const chunk of stdin) raw += chunk.toString();
    [firstName, lastName, rawEmail] = raw.split(/\r?\n/).map(x => x.trim());
  }
  const email = staffEmail(rawEmail);
  if (!firstName || !lastName || firstName.length > 80 || lastName.length > 80 || !email) throw new Error('Nom ou email invalide.');
  const password = temporaryPassword();
  const digest = await hashPassword(password);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(481731, 1)');
    const count = await client.query(`SELECT 1 FROM users WHERE role='admin' LIMIT 1`);
    if (count.rowCount) throw new Error('Un administrateur vient déjà d’être créé.');
    await client.query(`INSERT INTO users(id,role,email,first_name,last_name,password_hash,must_change_password)
      VALUES($1,'admin',$2,$3,$4,$5,true)`, [randomUUID(), email, firstName, lastName, digest]);
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); }
  stdout.write(`Compte admin créé : ${email}\nMot de passe temporaire (affiché une seule fois) : ${password}\n`);
} finally {
  ui?.close();
  await pool.end();
}
}
main().catch(error => { console.error(error instanceof Error ? error.message : 'Bootstrap impossible.'); process.exitCode = 1; });
