# Cross-platform system/ship pass — 2026-08-02

Snapshot id: `20260802_205333` (see `out/progress_data.json`)
Cumulative: 315 renamed functions, 152 renamed globals, 68 renamed types (1900 total functions).

## Context

- **PC target:** `GOF2.exe` (PE x86, MSVC, base 0x401000) — the live IDB.
- **iOS reference:** `Galaxy on Fire 2 HD` (Mach-O ARM64, gof2hd_1.1.19) — mesh peer `f42700d501a5`, full mangled C++ symbols (8101 fns).
- **Sources:** KaamoClubModApi (`resources/KaamoClubModApi`, validated PC ground truth — every `Offset::` anchor checked so far resolves onto the live IDB), gof2hd-decomp (Android 2.0.16 byte-matching port), DeepOpen (J2ME v1.0.4 logic oracle).

## Subsystem: star-system data + status (this session)

### FileRead (13 functions)
`loadStation`, `loadStationsBinaryFromId`, `loadStationCollision`, `loadWreckCollision`, `loadStationsBinary(SolarSystem*)`, `loadAgents`, `loadSystemsBinary` (27 systems), `loadItemsBinary` (196 items), `loadShipsBinary` (44 ships, 120B ShipInfo), `loadNamesBinary`, `loadTicker` (54 entries), `loadWeaponPositions`, `loadDocks` (`data/bin/docks.bin`, PC-era, no Android/iOS witness).

### Galaxy (4)
`getSystem`, `distancePercent`, `distance`, `getAsteroidProbabilities`.

### SolarSystem
`SolarSystem::SolarSystem` (0x4C38C6), `SolarSystem::SolarSystem_Dtor` (0x40A4F7). Struct created (68B) and applied; layout cross-checked against mod-api `SingleSystem` (+0x0C name, +0x14 id, +0x18 risk, +0x1C faction, +0x20 pos, +0x2C warpGate, +0x30 texture, +0x34 stationIds, +0x3C linked, +0x40 startsUnlocked).

### StarMap (13)
`StarMap`, `StarMap_Dtor`, `init`, `initStarSystem`, `depart`, `drawOnScreenInfo`, `draw`, `update`, `OnTouchBegin`, `OnTouchMove`, `OnTouchEnd`.

### StarSystem (2)
`StarSystem::StarSystem` (0x4D3B98), `StarSystem::render` (0x4D4CFD, mod-api `STARSYSTEM_RENDER`).

### Status / StatusWindow (22)
`Status::Status`, `inAlienOrbit`, `departStation`, `addStationToStack`, `getFreelanceMission`, `getCampaignMission`, `setCampaignMission`, `setCurrentCampaignMission`, `nextCampaignMission`, `removeMission`, `setStation`, `setWingmen`, `replaceHash`, `replaceHash_3Arg`, `stringHasToken`, `calcCargoPrices`, `updateRating`, `hardCoreMode`, `resetGame`, `StatusWindow::StatusWindow`, `Mission::Mission_Dtor`, plus AEArray release helpers.

### Types
- `SolarSystem` (68B) — created + applied to ctor.
- `Globals_status` (504B) — created from KaamoClubModApi `Globals_status` and applied to `g_Status` (0x60AD6C). Verified offsets: +16 wingmen, +340 ShipInfo, +344 Mission, +348 mission array, +356 station stack, +360 SystemInfo, +432 currentCampaignMission.

### Cross-platform findings (recorded as `[GOF2 XPLAT]` comments)
- **PC is an earlier source revision than iOS 1.1.19:** Level::init builds 8 ParticleSystemManagers vs iOS 10 (missing 27321/27311); StarSystem ctor simpler (3007B vs 3700B).
- **Gas clouds / plasma removed on PC:** no `gas/cloud/nebula` strings, no `Level::createGasClouds`, so `Galaxy::getPlasmaProbabilities` has no PC equivalent (plasma items exist, generator gone).
- **PC file layout:** all binaries under `data/bin/<file>.bin` (Android/iOS use bare names).
- `FileRead::loadDocks` (`docks.bin`, 40B dock records) is PC-era only.

## Next targets

- Ship/Player cluster: `PlayerEgo::*`, `Ship::*`, `Gun::*`, `KIPlayer::*`, `PlayerFighter::*` (mod-api anchors ready).
- Apply `Globals_status` as `this` type on Status member prototypes.
- Engine core (`AbyssEngine`) TU mapping (per `gof2hd-decomp/_work/original_layout/tu_mapping.md`).
