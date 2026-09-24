# MMS Backend

API de MMS (Mechanic Mobile Service), orientée mécanique moto. Ce dépôt Node.js/TypeScript est indépendant du frontend et du dépôt d'infrastructure MMS.

## Stack

- Node.js 22
- TypeScript
- serveur HTTP Node natif
- PostgreSQL 17
- `pg`
- Argon2 pour les mots de passe
- `libphonenumber-js` pour les numéros malgaches

## Installation locale

```sh
npm ci
```

Depuis le dépôt root MMS, créez un `.env` local à partir de `.env.example`, avec des valeurs de développement uniquement, puis démarrez la stack :

```sh
docker compose up --build -d
docker compose ps
```

L'API est exposée localement via le frontend sous `/api` et directement sur `127.0.0.1:3000`. PostgreSQL reste interne au réseau Docker.

## Développement

```sh
npm run dev
```

## Build et tests

```sh
npm run build
npm run test:unit
npm run test:integration
npm run test:facebook-integration
npm run test:staff-integration
npm run test:b1
```

Les tests d'intégration créent des données locales ; n'utilisez jamais la base de production pour les exécuter.

## Architecture

- `src/server.ts` : routes API, authentification, sessions, RBAC, tickets, agenda, booking et véhicules.
- `src/schema.sql` : schéma PostgreSQL et évolutions idempotentes appliquées au démarrage.
- `src/facebook-auth.ts` : intégration OAuth Facebook.
- `src/sms-provider.ts` : providers SMS console et Orange.
- `src/staff-domain.ts` : règles métier staff et transitions de tickets.
- `src/phone.ts` : validation et normalisation des numéros.

Les évolutions de `src/schema.sql`, des contrats HTTP, de l'authentification ou des rôles nécessitent une coordination avec le responsable du projet et une recette locale complète.

## Configuration et secrets

Les exemples d'environnement documentent les noms de variables sans contenir de credentials réels. Les fichiers `.env` privés ne sont jamais versionnés.

En développement, `SMS_PROVIDER=console` permet de tester sans appel réel. Le mode Orange exige des credentials privés configurés hors Git. Les secrets, OTP, access tokens et refresh tokens ne doivent jamais être ajoutés dans le code, les tests, les logs ou les commits.
