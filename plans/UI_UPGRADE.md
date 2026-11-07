# U01: 21st-based workspace redesign and strict product review

Authorized by the owner on 2026-11-05 after completion of C01-C40. This new work does not reopen, overwrite or recertify historical C evidence. The original plan validator returns no dependency-ready C task.

## Deliverables

- Evidence-grounded comparison of the shipped local product and public browser workspace against mature security products. Separate implemented local capability, limited exposure, missing feature and unvalidated demand.
- Rebuild every existing screen around the MIT shadcn/ui components listed on 21st.dev. Adapt them to the existing semantic CSS stack, with pinned provenance and shipped license notices. No mandatory online dependency.
- Accessible sidebar navigation, compact application toolbar, local theme preference, searchable keyboard navigation, honest loading/error/empty/stale states and consistent forms/tables.
- A useful public read-only synthetic tour with explicit sample labels, plus a real local overview over existing validated read endpoints. Public mode must never contact an operational API or imply live security monitoring.
- Preserve all sensor, replay, triage, certificate, update, JSON-preview and roadmap capabilities and the protected-file restriction.
- Prioritized future product roadmap with acceptance gates; no unimplemented backend control masquerades as a working feature.

## Validation

Run plan validation, typecheck and Pages build; the existing Node suite; public and operational browser checks on CI; targeted keyboard, theme, navigation, sample isolation and narrow-screen checks. Record actual results and verification limits. Keep v0.0.1 release artifacts and historical proof unchanged. Publish the authorized UI update through the existing Pages workflow after passing checks.
