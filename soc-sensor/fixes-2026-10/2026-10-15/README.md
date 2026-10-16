# Intervenții 15.10.2026

Convențiile sunt aceleași ca în `../2026-10-14/README.md`:
- lansatoarele rulează pe Acer, cu `! bash`;
- `*_sensor.sh` rulează ca root pe țintă;
- parola flotei nu e inclusă;
- scripturile verifică hostname-ul.

## Incident CNI (icisoc109): cni.ro inaccesibil

**Cauza:** rezolverul DNS 193.231.252.1, folosit ca forwarder de serverele DNS ale CNI, a fost blocat 90 de zile de permaban, pe 14.10 la 11:37 UTC. Blocarea a pornit de la AR pe alerte de nivel 12 în care rezolverul era **sursa**, adică răspunsul DNS la domenii suspecte cerute din rețea.

| Script | Ce face |
|---|---|
| `fix_cni_resolver.sh` + `fix_cni_resolver_sensor.sh` | Scoate IP-ul din `CYBER3_BLOCK` și din `permaban.list`, îl pune în `ar-allowlist`, salvează `rules.v4`. Nu repornește nimic. |
| `prev_icisoc101_resolver.sh` | Preventiv, pentru icisoc101, care folosește același rezolver |
| `f010_postcablare.sh` | f010 (Evidența Populației Argeș) recablat inline: restart Suricata după cablare și verificare |

**Lecție:** auditul trebuie să verifice și „rezolvere DNS ale clientului blocate” (vezi `../2026-10-16/audit/resolvers.sh`). Varianta „permaban ignoră portul 53” a fost respinsă de operator, pentru că pe portul 53 pot veni și atacuri reale.
