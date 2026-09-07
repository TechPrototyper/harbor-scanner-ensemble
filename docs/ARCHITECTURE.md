# Multi-Engine-Adapter: Architektur

Ziel: **ein** Harbor-Scanner, der intern **n** Engines fährt (heute Trivy und Grype),
die Befunde deterministisch zu einem Bericht verschmilzt und die Herkunft jedes Fundes
sichtbar macht. Harbor sieht einen Scanner, blockt auf der Vereinigungsmenge, und die
CVE-Allowlist greift für beide Engines gleichzeitig.

Das ersetzt den geplanten Harbor-Fork mit n Scannern pro Projekt: kein Eingriff in
Harbors Kern, kein CNCF-Proposal, kein Carry-Patch, läuft auf 2.15.1 wie es ist.

## 1. Grundentscheidungen

| Entscheidung | Wahl | Begründung |
|---|---|---|
| Ein Repo oder zwei | ein Repo, ein Binary, n Treiber | Der Merge braucht beide Report-Modelle; zwei Repos hieße ein geteiltes Modul und doppelte Releases. |
| Engine-Auswahl | `SCANNER_ENGINES=grype,trivy` (Default `grype`) | Der reine Grype-Adapter bleibt als Ein-Engine-Fall erhalten, das ist der veröffentlichte Nutzen. |
| Merge | deterministisch, kein Modell | Der Bericht entscheidet über Auslieferung. Gleiche Eingabe muss gleiche Ausgabe geben und begründbar sein. Gemessene Varianz ist mechanisch (s. § 7). |
| Ausführung | alle Engines parallel | Laufzeit ist max(t_i), nicht die Summe. |
| Teilausfall | strikt: eine fehlgeschlagene Engine lässt den Scan fehlschlagen | Ein still degradiertes Sicherheitsgate ist schlimmer als ein sichtbarer Fehler. Abschaltbar per `SCANNER_ALLOW_PARTIAL`. |
| Repo-Name | bleibt `harbor-scanner-grype` | Eine Stunde alt, Umbenennen später ist ein GitHub-Feature mit Redirect. Nicht jetzt entscheiden. |

## 2. Paketschnitt

```
pkg/harbor      Report-Modell (vorhanden, unverändert)
pkg/engine      NEU  Treiber-Schnittstelle + Registry + paralleler Lauf
pkg/grype       vorhanden -> implementiert engine.Driver
pkg/trivy       NEU  implementiert engine.Driver
pkg/merge       NEU  Kanonisierung, Dedup, Feldregeln, Provenienz
pkg/api         vorhanden, ruft künftig engine.RunAll + merge.Merge
pkg/job         vorhanden, unverändert
internal/config vorhanden, neue Schlüssel
```

Die Schnittstelle:

```go
package engine

type Target struct {
    Repository string            // wie von Harbor geliefert
    Digest     string
    Registry   string            // URL
    Auth       string            // Authorization-Header von Harbor, nie geloggt
}

type Info struct {
    Name    string  // "grype", "trivy"
    Version string  // Engine-Version
    DB      string  // Version/Datum der Vulnerability-DB
}

type Driver interface {
    Info(ctx context.Context) (Info, error)
    Scan(ctx context.Context, t Target) ([]harbor.VulnerabilityItem, error)
}
```

Jeder Treiber liefert bereits **Harbor-Items**, nicht sein Rohformat. Die engine-spezifische
Übersetzung bleibt beim Treiber; der Merge sieht nur noch ein einziges Modell. Der Treiber
setzt dabei `VendorAttributes["source"] = <name>` und, falls die Engine eine andere Kennung
verwendet als die kanonische, `VendorAttributes["source_id"]`.

`RunAll` startet alle Treiber parallel, mit eigenem Timeout je Treiber, und sammelt
Ergebnis oder Fehler pro Engine.

## 3. Kanonisierung der Kennung

Der Merge-Schlüssel ist `(canonicalID, package, version)`.

`canonicalID`:
1. Beginnt die Kennung mit `CVE-`, ist sie kanonisch.
2. Sonst: erste `CVE-`-Kennung aus den verwandten Einträgen der Engine.
   Grype liefert sie in `relatedVulnerabilities[]`, Trivy in `References` bzw. `VulnerabilityID`.
3. Sonst bleibt die Originalkennung (GHSA, ALAS, …).

Die Originalkennung wandert immer nach `VendorAttributes["ids_by_source"]`, damit nichts verloren geht.

**Gemessen an echten Daten** (unser Adapter-Image, 07.09.2026): Grype meldet 34 Funde unter
einer GHSA-Kennung, davon sind 32 über `relatedVulnerabilities` auf eine CVE auflösbar. Die
Kanonisierung hebt die Schnittmenge der beiden Scanner also messbar an; ohne sie wären es 31
gemeinsame Funde.

**Bekanntes Risiko:** Paketnamen können sich zwischen Engines unterscheiden, bei OS-Paketen
etwa Quell- gegen Binärpaket. Für Go-Binaries stimmen sie überein (`stdlib`,
`golang.org/x/crypto`, beide identisch). Der Merge bekommt deshalb einen Normalisierungs-Hook
für Paketnamen, vorerst mit der Identität als Implementierung.

## 4. Feldregeln beim Verschmelzen

Deterministisch, dokumentiert, jede Regel ein eigener Test.

| Feld | Regel |
|---|---|
| `severity` | höchste gewinnt (Critical > High > Medium > Low > Negligible > Unknown) |
| `fix_version` | Vereinigung der Versionslisten, Leerzeichen entfernt, dedupliziert, sortiert, mit `,` verbunden |
| `description` | längste nicht-leere; danach Provenienz-Präfix (§ 5) |
| `links` | Vereinigung, dedupliziert, stabile Reihenfolge |
| `preferred_cvss` | höchster Base-Score; bei Gleichstand v3.x vor v2 |
| `cwe_ids` | Vereinigung, sortiert |
| `layer` | erster nicht-leerer |
| `vendor_attributes` | flache Vereinigung plus die eigenen Schlüssel aus § 5 |

Report-`severity` ist das Maximum über alle verschmolzenen Items.
Die Ausgabe ist stabil sortiert nach `(severity absteigend, canonicalID, package)`, damit
zwei Läufe über dieselbe Eingabe byte-gleich sind.

## 5. Provenienz

**Sichtbar in Harbors Oberfläche**, weil `vendor_attributes` dort vermutlich nicht gerendert
wird: ein Präfix am Anfang der Beschreibung.

* `(*)` — alle erfolgreich gelaufenen Engines haben den Fund gemeldet
* `(T)` — nur Trivy
* `(G)` — nur Grype
* bei mehr als zwei Engines und Teilmenge: sortierte Initialen, etwa `(GT)`

Die Initiale kommt aus `Driver.Info().Name`, erster Buchstabe groß. Beim Start prüft die
Registry auf Kollisionen und verweigert den Dienst bei doppelten Initialen. Abschaltbar über
`SCANNER_PROVENANCE_PREFIX=false`.

**Maschinenlesbar** in `vendor_attributes`:

```json
{
  "sources": ["grype", "trivy"],
  "severity_by_source": {"grype": "Critical", "trivy": "High"},
  "ids_by_source": {"grype": "GHSA-5cgq-3rg8-m6cv", "trivy": "CVE-2026-56854"},
  "fix_by_source": {"grype": "0.52.0", "trivy": "0.55.0"}
}
```

Damit ist jede Merge-Entscheidung im Nachhinein nachvollziehbar, ohne die Rohberichte zu brauchen.

## 6. Metadata, Betrieb, Ressourcen

* `/api/v1/metadata` meldet `scanner.name` als die verbundene Liste, etwa `grype+trivy`,
  `version` ist die Adapter-Version. Die Engine- und DB-Versionen stehen in den Capabilities.
* Engine-Versionen werden beim Start ermittelt und mit TTL zwischengespeichert; `/metadata`
  darf keine Prozesse starten, Harbor ruft es häufig.
* **Datenbanken:** beide Engines brauchen ihre Vulnerability-DB. Einmal beim Start laden,
  danach per `SCANNER_DB_REFRESH_INTERVAL` auffrischen, Ablage in einem `emptyDir`. Nicht pro
  Scan laden, das war im Skript-Ansatz die Hauptlaufzeit.
* **Ressourcen:** zwei DBs im Speicher sind der Kostenpunkt. Requests klein halten,
  Limits großzügig, Requests klein: auf CPU-knappen Knoten bleibt der Pod
  sonst Pending.
* Ein Replica. Der Job-Store ist im Speicher, das bleibt so.

## 7. Warum kein Modell im Scan-Pfad

Gemessen an den beiden echten Berichten desselben Images:

| Prüfung | Ergebnis |
|---|---|
| gemeinsame Funde (vor Kanonisierung) | 31 |
| davon Severity identisch | 29 |
| davon Severity abweichend | 2 |
| Fix-Version abweichend | 29, ausschließlich Formatierung (`1.25.8, 1.26.1` gegen `1.25.8,1.26.1`) |

Die "große Vielfalt der Berichtselemente" existiert nicht. Es sind zwei stabile, versionierte
JSON-Schemata, und die Abweichungen sind Leerzeichen und eine einzige Severity-Skalendifferenz.
Ein Modell brächte Nichtdeterminismus, Latenz und Halluzinationsrisiko in eine Entscheidung,
die ein Image blockiert oder freigibt.

Sinnvoll ist ein Modell **offline**: Abweichungen zwischen Engines auswerten, um daraus neue
Normalisierungsregeln abzuleiten, oder einen Bericht für Menschen zusammenfassen. Beides
außerhalb des Scan-Pfads, beides ohne Einfluss auf das Gate.

## 8. Konfiguration (neu)

| Variable | Default | Bedeutung |
|---|---|---|
| `SCANNER_ENGINES` | `grype` | Kommaliste der aktiven Engines |
| `SCANNER_ENGINE_TIMEOUT` | `5m` | Timeout je Engine |
| `SCANNER_ALLOW_PARTIAL` | `false` | Scan gilt trotz Engine-Ausfall als erfolgreich |
| `SCANNER_PROVENANCE_PREFIX` | `true` | `(*)`, `(T)`, `(G)` vor der Beschreibung |
| `SCANNER_TRIVY_PATH` | `trivy` | Pfad zum Trivy-Binary |
| `SCANNER_DB_REFRESH_INTERVAL` | `12h` | Auffrischung der Vulnerability-DBs |

Bestehende Schlüssel bleiben unverändert.

## 9. Teststrategie

Die beiden echten Berichte aus dem Lauf vom 07.09.2026 (`trivy.json` 94 Funde, `grype.json`
163 Funde, dasselbe Image) sind die Golden Fixtures. Damit ist der Merge gegen reale Daten
prüfbar, nicht gegen erdachte.

Prüfbare Zusagen:
* Die Schnittmenge nach Kanonisierung ist **größer als 31**, denn 32 GHSA-Funde lösen sich auf CVEs auf.
* Kein Fund geht verloren: die Zahl der Ergebnis-Items ist gleich der Zahl eindeutiger Schlüssel.
* Jedes Item trägt genau ein Provenienz-Präfix, und die Summe über `(*)`, `(T)`, `(G)` ergibt die Gesamtzahl.
* CVE-2026-56858 und CVE-2026-56860 erscheinen als `High`, nicht als `Medium` (höchste gewinnt).
* Zwei Läufe über dieselbe Eingabe erzeugen byte-gleiche Ausgabe.

## 10. Arbeitspakete für coderplus

Jedes Paket ein Harness-Lauf, Tests zuerst, rot vorgegeben.

| # | Inhalt | Abnahme |
|---|---|---|
| M1 | `pkg/engine`: Schnittstelle, Registry, Initialen-Kollisionsprüfung, paralleler Lauf mit Timeout und Fehlersammlung | Registry lehnt doppelte Initialen ab; ein langsamer Treiber blockiert den anderen nicht |
| M2 | `pkg/grype` auf `engine.Driver` umstellen, Verhalten unverändert | bestehende Grype-Tests bleiben grün |
| M3 | `pkg/trivy`: Treiber, `trivy image --format json`, Mapping auf Harbor-Items | Mapping-Test gegen `trivy.json`-Fixture, 94 Items, Severity-Verteilung wie gemessen |
| M4 | `pkg/merge`: Kanonisierung, Merge-Schlüssel, Feldregeln, stabile Sortierung | Golden-Test über beide Fixtures, Zusagen aus § 9 |
| M5 | Provenienz: Präfix und `vendor_attributes` | Präfixverteilung stimmt, abschaltbar |
| M6 | Verdrahtung in `pkg/api` und `internal/config`, `/metadata` mit Engine-Liste und Cache | Ende-zu-Ende-Test über httptest mit zwei Fake-Treibern |
| M7 | Dockerfile mit beiden Binaries, DB-Vorwärmung, Chart-Werte | `helm lint` grün, Image startet ohne Netz mit vorgeladener DB |

M2 vor M3, M4 nach M3, sonst ist die Reihenfolge frei.

## 11. Offene Punkte für Tim

* Repo-Name: bleibt vorerst `harbor-scanner-grype`, Umbenennung später möglich.
* Ob der Merge-Adapter den reinen Grype-Adapter auf GitHub ersetzt oder als zweiter
  Betriebsmodus daneben steht. Vorschlag: derselbe Code, Modus über `SCANNER_ENGINES`.
* Ob Trivy zusätzlich zu Harbors eingebautem Trivy läuft (dann zweimal dieselbe Engine im
  Cluster) oder ob Harbors Trivy nach dem Umstieg abgeschaltet wird.

---

## 12. Nachmessung an den Fixtures (07.09.2026, vor dem Schnitt der Pakete)

Die Zahlen in § 3, § 7 und § 9 stammen aus einer Vorabzählung. Eine Nachmessung
direkt auf `pkg/merge/testdata/{trivy,grype}.json` ergibt abweichende Werte. Die
Architektur bleibt gültig, die **Zusagen in § 9 werden durch die gemessenen
Werte unten ersetzt**, und eine Regel kommt hinzu.

### 12.1 Neue Regel: Versionen normalisieren

Der Merge-Schlüssel braucht neben dem Paketnamen-Hook auch eine
**Versions-Normalisierung**. Dieselbe Go-Standardbibliothek heißt

* bei Trivy `v1.24.13`
* bei Grype `go1.24.13`

Ohne Normalisierung merged kein einziger stdlib-Fund. Regel: führendes `v` bzw.
`go` entfernen, dann vergleichen. Das ist die wirksamste Einzelregel im ganzen
Merge (siehe Tabelle).

### 12.2 Gemessene Werte

| Größe | ohne Kanonisierung | + ID-Kanonisierung | + Versions-Normalisierung |
|---|---|---|---|
| Schnittmenge | 2 | 44 | **94** |
| Vereinigung | 207 | 165 | **115** |
| nur Trivy | 92 | 50 | **0** |
| nur Grype | 113 | 71 | **21** |

Grype meldet 163 Matches, aber nur **115 eindeutige Schlüssel**: 48 Funde
erscheinen doppelt, weil dieselbe Schwachstelle einmal unter der CVE- und
einmal unter einer `GO-…`-Kennung geliefert wird, die auf dieselbe CVE
auflöst. **Der Merge braucht deshalb auch eine Deduplizierung innerhalb einer
Engine**, nicht nur zwischen Engines. Trivy hat keine Dubletten.

Nicht-CVE-Kennungen bei Grype: 101 von 163, davon 97 über
`relatedVulnerabilities` auf eine CVE auflösbar (nicht 34/32).

### 12.3 Severity-Abweichungen

19 der 94 gemeinsamen Funde haben abweichende Severity, nicht 2. Beispiele:

| CVE | Paket | Trivy | Grype | gemerged |
|---|---|---|---|---|
| CVE-2026-39830 | golang.org/x/crypto | High | Critical | Critical |
| CVE-2026-39834 | golang.org/x/crypto | Medium | Critical | Critical |
| CVE-2026-25681 | golang.org/x/net | High | Medium | High |
| CVE-2026-56855 | golang.org/x/crypto | Unknown | High | High |

Das ändert nichts an der Regel „höchste gewinnt", macht sie aber wichtiger:
19 Funde landen höher, als eine einzelne Engine sie meldet. Genau das ist der
Zweck des Multi-Engine-Betriebs.

### 12.4 Ersetzte Zusagen für die Tests (§ 9)

* Schnittmenge nach Kanonisierung **und** Versions-Normalisierung: **exakt 94**
* Vereinigung, also Anzahl Items im Bericht: **exakt 115**
* Präfixverteilung: `(*)` **94**, `(G)` **21**, `(T)` **0**
* Severity-Abweichungen: **19**, alle zugunsten der höheren Stufe
* CVE-2026-56858 und CVE-2026-56860: Trivy High, Grype Medium, gemerged **High**
* Grype-interne Dubletten: 163 Matches → 115 Schlüssel
* Zwei Läufe über dieselbe Eingabe erzeugen byte-gleiche Ausgabe


---

## 13. Cluster-Test 07.09.2026, echtes Image, echte Engines

Image `<registry>/platform/harbor-scanner-ensemble:v2026.09.07-2` (im Cluster
per Kaniko gebaut), Pod in ns `harbor`, Scan des Adapter-Images selbst
ueber `http://harbor-core:80`.

| | Wert |
|---|---|
| Items | 99 |
| Dauer | 35 s, beide Engines parallel |
| Severity | 6 Critical, 61 High, 28 Medium, 2 Low, 2 Unknown |
| Herkunft | `(*)` 58, `(T)` 40, `(G)` 1 |
| Metadata | `grype+trivy`, Grype 0.118.0, Trivy 0.74.0 |

**Die Abdeckung der Engines ist nicht stabil.** In den Fixtures vom
selben Tag (Grype 0.112, aeltere DB) fand Trivy *nichts*, was Grype nicht
auch fand: `(*)` 94, `(G)` 21, `(T)` 0. Mit aktuellen Engines und
frischen Datenbanken kehrt sich das fast um: `(T)` 40 gegen `(G)` 1.
Welcher Scanner mehr findet, haengt also vom Datenbankstand ab, nicht vom
Scanner. Das ist das staerkste Argument fuer den Ensemble-Betrieb, und es
war vor dem Test nicht bekannt.

## 14. Voraussetzungen fuer den Betrieb als Gate

Ein Scanner allein blockiert nichts. Pro Projekt braucht es:

| Einstellung | Wirkung |
|---|---|
| Scan bei Push | sonst entsteht nie ein Bericht |
| Pull blockieren | die eigentliche Sperre |
| Schwelle, z. B. Critical | ab wann gesperrt wird |
| Scanner zugewiesen | Harbor fuehrt genau einen pro Projekt |

Die CVE-Allowlist ist der Ausnahmemechanismus dazu. Ein Eintrag mit
Ablaufdatum gilt fuer den gesamten Bericht, also fuer alle Engines
gleichzeitig. Genau das macht den Ensemble-Ansatz betrieblich tragfaehig:
eine Ausnahmeliste statt einer pro Scanner.

Die Pull-Sperre sollte projektweise scharf geschaltet werden, nicht
ueberall auf einmal. Sie verhindert auch das Ziehen bereits laufender
Images, ein Pod-Neustart kann dadurch fehlschlagen, bevor jemand die
Befunde gesehen hat.
