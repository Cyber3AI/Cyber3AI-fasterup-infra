# CYBER3 Scan — Generare rapoarte per client

Pipeline de raportare după modelul f003/f002, cu **MATCH cauzal pe gazdă**.

## Componente
- `c3report_gen.py` — generatorul (rulează **pe portal**: OpenSearch :9200 + SSH la senzor + reportlab).
  Produce `*.md` (raport complet + MATCH cauzal) + `discovery.json`/`findings.json`.
- `c3report_md2pdf.py` — randare MD → PDF (temă navy, DejaVu pt diacritice). Rulează pe portal.
- DOCX: `../brand/mkdocx.py in.md out.docx` (rulează local în WSL).

## Flux (per senzor, după ce scanul `c3-engage.sh` s-a terminat)
```bash
# 1) pe portal — generează MD + JSON
python3 c3report_gen.py <sensor> <agent_id> <wg_host> <scan_id> "Organizație client (confidențial)" <bd:0/1> "<nota>" /tmp/out/<sensor>
# 2) pe portal — randează PDF
/opt/fasterup-portal/venv/bin/python c3report_md2pdf.py /tmp/out/<sensor>/CYBER3_Scan_Raport_<sensor>_<data>.md  ...pdf
# 3) local — DOCX din MD
python3 ../brand/mkdocx.py raport.md raport.docx
# 4) asamblează în  CYBER3 Scan REPORT/<sensor>/
```

## REGULĂ STRICTĂ
Parametrul `<ORG>` = **întotdeauna generic** (`"Organizație client (confidențial)"`).
**Numele real al clientului NU apare NICIODATĂ în raport.** Maparea senzor→client se ține separat, intern.

## MATCH cauzal (5.2) — ce decide verdictul
Leagă **tipul expunerii** (SMB/RDP/WEB/DB/SNMP/CLEARTEXT din scan) de **tipul activității** (signatura reală)
ȘI **direcția** (extern vs intern) pe aceeași gazdă:
- expunere ⟷ atac de același tip **din EXTERIOR** → ⚠️ **CAUZAL** (prioritate)
- expunere ⟷ activitate de același tip **din INTERIOR** → administrare legitimă probabilă (FP), **NU atac**
- atac extern fără potrivire de expunere → vizat din exterior, asigurați patch-uri
- doar trafic informațional → expus fără atac corelat (proactiv)

Plus interpretarea onestă a alertelor nivel≥10 (real vs FP) + verificarea „**nu e generat de scan**" (fereastra 4h).
Capcane Suricata cunoscute: „PowerShell over SMB" intern = administrare (nu C2); „Web App Attack/PrivEsc" din exterior = probing automat de internet (nu compromitere); „failed sudo" = eveniment de gazdă.
