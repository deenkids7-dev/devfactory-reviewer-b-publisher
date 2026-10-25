# DevFactory — service de reservation financiere local

Etat : **implementation locale isolee, NON AUTORISEE POUR LES DEPENSES** (2026-10-25).

## Composants livres
- `service/finance-reservation-ledger.mjs` : SQLite WAL, `synchronous=FULL`, transactions `BEGIN IMMEDIATE` et journal durable de reservations et de charges.
- `service/finance-reservation-server.mjs` : processus HTTP distinct du Runner, ecoute CLI exclusivement sur `127.0.0.1`, deux tokens differents.
- `test/finance-reservation-{ledger,server}.test.mjs` : tests vrais SQLite et HTTP.

## Regles
- Enveloppe globale : **15 EUR / mois UTC**.
- Reservation reviewer B : **3 USD / mois**, une demande au maximum 0,50 USD.
- Reservation developpement : **10 USD / mois**, une demande au maximum 1 USD.
- Conversion conservatrice interne : **1 USD reserve = 3 EUR d'exposition**. Ceci n'est PAS un taux FX authentifie : c'est un plafond pessimiste pour les tests.
- Charges ajoutees **EN PLUS** des reservations, sans liberation automatique des holds. Les factures tardives restent rattachees au mois d'origine.
- Reemploi identique d'un ID = idempotence ; contenu contradictoire = 409.
- Aucune suppression ni release. Aucun appel a OpenRouter. Toutes les reponses: `maySpend:false`, jamais une attestation.

## Mode manuel de test (sur MSI uniquement, aucun secret en git)
1. Choisir un repertoire de donnees dedie, existant et non partage avec le Runner, avec permissions NTFS restreintes au compte de service.
2. Fournir des tokens aleatoires distincts de 32 caracteres minimum via variables de processus `DF_FINANCE_CLIENT_TOKEN` et `DF_FINANCE_ADMIN_TOKEN`. Ne pas les stocker dans `.env` suivi par git.
3. Fournir `DF_FINANCE_DB` (chemin absolu vers le fichier SQLite) et `DF_FINANCE_PORT` (port libre).
4. Depuis ce dossier, demarrer `node service/finance-reservation-server.mjs` sous une identite OS separee. Message attendu : `FINANCE_LEDGER_LOCAL_READY_NO_SPEND`.
5. `GET http://127.0.0.1:<port>/health` retourne `{"status":"ok","maySpend":false}`.
6. `POST /v1/reservations` avec `Authorization: Bearer <client>` et JSON exact `{"id":"test-001","role":"reviewer_b","pr":940,"head":"<40 hexadecimal>","upperUsdMicros":500000}`. Si l'enveloppe le permet, retourne un hold local, **pas** la permission d'appeler le modele.
7. `POST /v1/charges` demande le token administrateur distinct ; JSON `{"eventId":"facture-001","reservationId":"test-001","amountUsdMicros":120000}`.
8. `GET /v1/status` avec l'un des tokens donne les totaux et `mayReserveForPaidRun:false`.

## Pour un vrai demarrage de Reviewer B / du Runner
Le service est independant **en processus et stockage**, mais n'est pas encore une **autorite independante de confiance** :
- heberger le service et sa base sous un compte/une machine inaccessible en ecriture au Runner ;
- installer et approuver les signataires et l'authentification d'origine, avec rotation et anti-rejeu ;
- acquérir les preuves serveur de tous les workspaces/cles OpenRouter, les charges en vol et les factures, ainsi qu'un FX authentifie ;
- definir la reservation/settlement avec transfert de preuves, audits et refus en cas d'ambiguite ;
- faire une revue de securite independante, verifier les plafonds et le ZDR, puis raccorder explicitement le workflow Publisher protege ;
- ajouter l'autorisation exacte du proprietaire pour les SHA des PR #940/#941 avant chaque paid-call.

**Ne pas** presenter cette version locale comme preuve de `MAY_SPEND=true`, et ne pas activer `DeenKids-DevFactory-Autonomy` sur sa seule base.
