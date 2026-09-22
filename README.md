# MMS backend

API Node.js/TypeScript et PostgreSQL du service de mécanique moto. Ce dossier possède son propre dépôt Git. Depuis la racine MMS, lancer `docker compose up -d --build api` et vérifier `docker compose ps`.

## Authentification et SMS

Les clients s'inscrivent ou se connectent avec un numéro malgache et un OTP à six chiffres. La demande, la vérification, le changement de numéro et la gestion des sessions sont décrits dans [`../AUTHENTICATION.md`](../AUTHENTICATION.md).

Le choix du transport est fait au démarrage :

- `SMS_PROVIDER=console` exige `MMS_TEST_MODE=1`. Le code est écrit uniquement dans `/tmp/mms-test-otp-<challengeId>` du conteneur API, jamais dans la réponse HTTP ni les logs. Ce fichier est effacé après validation.
- `SMS_PROVIDER=orange` exige `ORANGE_CLIENT_ID` et `ORANGE_CLIENT_SECRET`. Le backend obtient un token OAuth `client_credentials` chez Orange, le garde en mémoire, et envoie l'OTP via SMS Messaging v1. Les codes, secrets et tokens ne sont pas loggés. En cas d'échec, l'API retourne un message générique et annule la création du challenge.

`ORANGE_COUNTRY_SENDER` vaut `tel:+2610000` par défaut. `ORANGE_SENDER_NAME` est facultatif : il doit être approuvé par Orange et ne peut contenir que 11 caractères alphanumériques ou espaces au maximum. Les identifiants réels restent dans le `.env` privé, jamais dans Git. Un abonnement Orange SMS Madagascar actif avec du crédit est requis ; aucun envoi réel n'est effectué par les tests automatisés.

## Vérifications

`npm run build` compile le backend. `npm run test:unit` teste les providers avec des réponses Orange simulées, notamment le cache OAuth, l'expiration, les erreurs et l'absence de retry sur résultat ambigu. `npm run test:integration` vérifie l'API et le parcours client contre une instance Docker locale en mode console ; ce test crée des données de test.
