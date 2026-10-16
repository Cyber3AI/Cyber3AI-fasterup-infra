# Intervenții 16.10.2026

Convențiile sunt aceleași ca în `../2026-10-14/README.md`. În plus:
- **fiecare script verifică hostname-ul**;
- intervențiile pe senzori vii se fac **câte un senzor pe rând**, cu măsurarea traficului NFQUEUE înainte și după și cu auto-revert.

## f010 (Evidența Populației Argeș): adus la standardul flotei

| Script | Ce face |
|---|---|
| `f010_pasA.sh` | Doar fișiere: wrapper de domenii fără reload, dataset MISP 597k, allowlist curățat |
| `f010_std14.sh` + `rep_suppress.block` | +367 supresii de reputație (bloc identic cu f012), `modules-load` nfqueue, wait-online `--any`, self-scan corectat |

**L2 Shield NU e armat:** gateway-ul de pe punte nu e confirmat.

## Test funcțional de blocare pe toată flota

| Script | Ce face |
|---|---|
| `test_blocare_flota.sh` + `test_blocare_sensor.sh` | Blochează, verifică și deblochează un IP TEST-NET (192.0.2.234) prin `firewall-drop-real`. Rezultat: 20/20 PASS, de două ori. |

## Rezolvere DNS ale clienților (lecția CNI)

| Script | Ce face |
|---|---|
| `allow_resolvers.sh` + `allow_resolver_sensor.sh` | Adaugă câte un rezolver verificat în trafic în `ar-allowlist`. Doar fișier, fără restart. Aplicat pe f007 (1.1.1.3), f008 (94.140.14.14), icisoc103 (94.140.14.14), icisoc104 (94.140.15.15), icisoc109 (94.140.14.14). |
| `cyber3-resolvers.sh` | Raport cu rezolverele publice interogate de rețea. **NU se aplică automat:** dry-run-ul a arătat că ar pune în allowlist și NS-uri autoritative, adică risc de evaziune prin tunel DNS. Rămâne doar ca raport, iar adăugările se fac manual. |

## Blocare pe reputație (Spamhaus DROP/EDROP, DShield, CINS → 367 de reguli DROP)

| Script | Ce face |
|---|---|
| `rep_precheck_sensor.sh` / `rep_precheck_perim.sh` | Read-only: allowlist-ul și destinațiile reale ale clienților (60 s) nu apar în listele de reputație. Rezultatul e verdictul „SIGUR”. |
| `rep_drop_sensor.sh` | Canonic: `drop.conf` + `suricata-update --no-test --no-reload` + un restart |
| `rep_drop_wrap.sh` + `rep_drop_flota.sh` | Verificare hostname, trafic NFQUEUE pe 10 s înainte și după, alarmă la 0, un senzor pe rând |
| `post_rep_check.sh` / `drop_counters.sh` | Read-only: trafic pe 4 intervale și contoarele `ips.*` din `suricatasc dump-counters` |

**Armat pe 18 din 20 de senzori.** Excepții:
- icisoc107 nu e inline;
- icisoc110 are altă arhitectură.

**Atenție:** drop-urile de reputație sunt silențioase (alertele de reputație sunt suprimate). Se văd doar în contorul `ips.drop_reason.rules`.

## HOME_NET cu adresele publice proprii (lecția ANRE)

| Script | Ce face |
|---|---|
| `homenet_sensor.sh` + `homenet_flota.sh` | Backup, editarea liniei HOME_NET, validare YAML cu python (nu cu `suricata -T`), un restart, auto-revert, observare 180 s |

Aplicat pe:
- icisoc101: 5.2.180.41;
- icisoc105: 213.177.4.186–190.

## f014 (Clinica Sarafoleanu): montat NE-inline

| Script | Ce face |
|---|---|
| `f014_state.sh` / `f014_bootcheck.sh` / `f014_bc2.sh` | Read-only: interfețe, netplan generat, wait-online, wg1, firewall persistat, blocări pe IP-urile critice |
| `f014_mgmt_persist.sh` + `f014_mgmt_run.sh` | Management permanent pe `enp0s25` (br0 cu un singur membru, DHCP); `eno1` scos din punte, ca port de captură; dead-man 120 s cu revert |

`enp2s0` arată NO-CARRIER la clinică: placa e suspectă. Persistența a fost verificată la reboot.

## Verificări de flotă (read-only)

| Script | Ce face |
|---|---|
| `persist_check.sh` | `drop.conf`, reguli DROP în fișier, HOME_NET, `CYBER3_BLOCK` live == `rules.v4` |
| `health_atomic.sh` | Suricata, reguli, erori, cozi, qdrop, trafic pe fiecare port al punții, % blocat, allowlist neblocat, IP de test eliminat, agent, wg. Verdict OK sau listă de probleme. |
| `audit/` | Auditul empiric din 15–16.10: blocări reale, rezolvere, nivelul alertelor, testul de detecție f014 |
