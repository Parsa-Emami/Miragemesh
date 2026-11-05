# MirageMesh workspace design system

U01, 2026-11-05. Scope: every existing workspace route in the local application and public Pages build. See `plans/UI_UPGRADE.md` and `docs/product/GLOBAL_READINESS_REVIEW.md`.

## 21st source and adaptation

21st.dev is a registry of work by multiple authors, not a single UI theme or runtime dependency. This implementation selects the shadcn/ui family listed on 21st:

- https://21st.dev/@shadcn/components/sidebar
- https://21st.dev/@shadcn/components/button
- https://21st.dev/@shadcn/components/card
- https://21st.dev/@shadcn/components/table
- https://21st.dev/blog/react-sidebar-component-examples

Button, card, badge and table slot/variant composition is adapted from the corresponding MIT upstream sources at shadcn-ui/ui commit `8a3536678a528cc012b9e62484290e79d0be410f`. Utility classes are translated to the repository's existing semantic CSS. Native button/link/table semantics and semantic heading titles are retained. Radix Slot polymorphism is deliberately absent; actions use real buttons and navigation uses real anchors. The sidebar uses the selected composition, with route state and privacy context specific to MirageMesh. It is not an unmodified installation of the complete shadcn Sidebar package.

`UI_PROVENANCE.json` records immutable upstream source URLs, downloaded source hashes, copied icon paths and licenses. Adapted code lives in `apps/web/src/components/ui/primitives.tsx`. License notices ship in `licenses/`, `THIRD_PARTY_NOTICES.md` and the generated SBOM. No source gated by a 21st account was bypassed or copied; the selected upstream is publicly MIT-licensed.

## Tokens and visual direction

Neutral graphite surfaces, restrained cobalt actions and separate semantic success/warning/error colors suit a dense security workspace. Colors are scoped semantic variables, following https://ui.shadcn.com/docs/theming. The exact values are in `apps/web/src/tokens.css`.

| Role | Dark | Light |
|---|---|---|
| Background | `#0e1014` | `#f7f8fb` |
| Surface | `#15181e` | `#ffffff` |
| Text | `#eef0f6` | `#202530` |
| Muted text | `#a6adbd` | `#566176` |
| Primary action | `#4263eb` | `#3c50cf` |
| Link/accent | `#a9b9ff` | `#394fc4` |
| Border | `#2c313c` | `#d8dde7` |

Use the operating system's sans-serif font stack and local monospace for exact identifiers. No external font or asset request is required. Layout: 236px desktop sidebar, compact toolbar, bounded content area, clear section hierarchy and scrollable semantic tables. On narrow screens the single navigation remains visible as a horizontally scrollable row, rather than hiding tasks behind an inaccessible hover control.

## Component boundaries

- `AppShell`: shared navigation, toolbar, theme and search dialog. It does not fetch operational data or own domain permissions.
- `primitives`: source-adapted button/card/badge/table and locally vendored Lucide icon presentation.
- `OperationalOverview`: validates existing local sensor/incident responses; displays unknown when unavailable. Counts come only from accepted snapshots; no inferred clean state.
- `SampleTour`: bounded, fictional read-only records with a persistent synthetic-data explanation. It never reads operational APIs or writes triage.
- Existing feature pages: retain their real validators, stale snapshots, cancellation, source trace, idempotency and write recovery semantics. Shared CSS gives each view the same tables/forms/panels.
- `PublicWorkspace`: distribution, supported-profile facts, sample exploration and copyable installation commands; never changes engine admission.

## Interaction and accessibility

- Keyboard: skip to content, visible focus, labelled Main navigation, real links, native form controls and native modal dialog.
- Search: button or Ctrl/Cmd+K; type a page name; Tab and Enter select; Escape closes. Native dialog traps focus and returns it to the opener. This is page navigation, not full-text security-event search.
- Theme: user-selected light/dark stored under `miragemesh-theme` only; failure to store does not block rendering. No operational data is persisted in the browser.
- State: loading, unavailability, stale data, empty datasets, rejected input and unknown save outcome remain explicit. Color is accompanied by text.
- Motion: no decorative animation; reduced-motion preference is honored.
- Tables: native headers/scope and focusable overflow regions preserve a keyboard/table equivalent at 360px.

Native dialog behavior reference: https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/dialog. Effect cleanup reference: https://react.dev/reference/react/useEffect. Automated tests and manual browser inspection are evidence for their tested scope; no full WCAG or independent accessibility certification is claimed.

## Deployment boundary

Pages ships static assets under `/Miragemesh/`. Icons are bundled under `assets/icons/`, compatible with the existing local server's allowed asset path. Public runtime configuration still has engine integration disabled. The same React source has separate local and public compositions. v0.0.1 binary artifacts retain their original UI until a new signed full release is deliberately published.
