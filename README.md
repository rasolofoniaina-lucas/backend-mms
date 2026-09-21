# MMS backend

API Node.js/TypeScript et base PostgreSQL pour la V1 de test moto. Ce dossier possède son propre dépôt Git.

Lancement recommandé depuis la racine MMS :

```sh
docker compose up --build -d
docker compose ps
```

L'API est disponible sur <http://localhost:8080/api/health> via Nginx, et sur `127.0.0.1:3000` pour le développement. Le schéma `src/schema.sql` est appliqué au démarrage. Les données PostgreSQL sont dans un volume Compose persistant.

Routes principales : `POST /api/customers`, `GET/PATCH /api/customers/:id`, `POST /api/customers/:id/vehicles`, `POST /api/customers/:id/appointments`, `PATCH /api/customers/:id/appointments/:id/cancel`, `GET /api/availability`, `GET /api/mechanic/appointments`, `PATCH /api/mechanic/appointments/:id`.

La base bloque les doubles réservations actives pour un même type d'intervention, jour et créneau. Le dépannage n'a pas de créneau. Les statuts et notes enregistrés par le mécanicien sont visibles côté client après rafraîchissement.

**Sécurité : mode test uniquement.** Le démarrage exige `MMS_TEST_MODE=1`. Il n'y a pas d'authentification ni de droits par rôle, le mot de passe DB de Compose est une valeur locale de test, et aucune notification/SMS ou prise en charge automatique n'existe. Ne pas exposer ce service à Internet avant d'ajouter les protections nécessaires.
