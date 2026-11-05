import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Button, Icon } from './ui/primitives';

export type Route = 'workspace' | 'roadmap' | 'sensors' | 'incidents' | 'certificates' | 'updates';
export const navigation: { id: Route; title: string; icon: string; description: string }[] = [
  { id: 'workspace', title: 'Workspace', icon: 'layout-dashboard', description: 'Overview and getting started' },
  { id: 'sensors', title: 'Sensors', icon: 'radio', description: 'Sensor activity and delivery health' },
  { id: 'incidents', title: 'Incidents', icon: 'activity', description: 'Replay evidence and review findings' },
  { id: 'certificates', title: 'Certificates', icon: 'key-round', description: 'Identity and certificate lifecycle' },
  { id: 'updates', title: 'Updates', icon: 'package-check', description: 'Signed sensor release evidence' },
  { id: 'roadmap', title: 'Roadmap', icon: 'map', description: 'Source-backed delivery history' },
];
const repository = 'https://github.com/Parsa-Emami/Miragemesh';
function initialTheme() {
  try { const saved = localStorage.getItem('miragemesh-theme'); if (saved === 'light' || saved === 'dark') return saved; } catch {}
  return matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

export default function AppShell({ page, publicMode, children }: { page: Route; publicMode: boolean; children: ReactNode }) {
  const [theme, setTheme] = useState(initialTheme);
  const [search, setSearch] = useState('');
  const dialog = useRef<HTMLDialogElement>(null);
  const current = navigation.find(item => item.id === page)!;
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('miragemesh-theme', theme); } catch {}
  }, [theme]);
  function openSearch() { setSearch(''); if (!dialog.current?.open) dialog.current?.showModal(); }
  useEffect(() => {
    const key = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); openSearch(); }
    };
    addEventListener('keydown', key);
    return () => removeEventListener('keydown', key);
  }, []);
  const matches = navigation.filter(item => `${item.title} ${item.description}`.toLowerCase().includes(search.toLowerCase()));
  return <div className="app">
    <a className="skip" href="#content">Skip to content</a>
    <aside className="sidebar">
      <a className="brand" href="#workspace"><span className="brand-mark"><Icon name="shield-check"/></span><span>MirageMesh<small>Security workspace</small></span></a>
      <div className="workspace-switch"><span className="workspace-avatar"><Icon name={publicMode ? 'book-open' : 'terminal'}/></span><div><strong>{publicMode ? 'Public workspace' : 'Local workspace'}</strong><small>{publicMode ? 'Explore the product' : 'On your own host'}</small></div><span className="version">0.0.1</span></div>
      <p className="nav-label">Workspace</p>
      <nav aria-label="Main">{navigation.map(item => <a key={item.id} href={`#${item.id}`} aria-current={page === item.id ? 'page' : undefined}><Icon name={item.icon}/><span>{item.title}</span>{item.id === 'roadmap' && <span className="nav-count">40</span>}</a>)}</nav>
      <div className="sidebar-bottom"><div className="privacy-card"><Icon name="shield-check"/><strong>Your data stays yours.</strong><p>Open source. Local processing. No automatic uploads.</p><a href={repository + '/blob/main/docs/release/SERVICE_POLICY.md'}>Privacy and data policy <Icon name="arrow-up-right"/></a></div><a className="sidebar-help" href={repository + '/blob/main/docs/release/USER_GUIDE.md'}><Icon name="circle-question-mark"/>Documentation<Icon name="arrow-up-right"/></a><div className="sidebar-status"><span className="dot"/>Apache-2.0 <span>v0.0.1</span></div></div>
    </aside>
    <div className="app-body">
      <header className="topbar"><div className="breadcrumb"><span>Workspace</span><Icon name="chevron-right"/><strong>{page === 'workspace' ? 'Overview' : current.title}</strong></div><div className="topbar-actions"><Button variant="outline" className="search-trigger" onClick={openSearch} aria-label="Search workspace"><Icon name="search"/><span>Search workspace</span><kbd>⌘ K</kbd></Button><Button variant="ghost" className="icon-button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label="Toggle color theme" title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}><Icon name={theme === 'dark' ? 'sun' : 'moon'}/></Button><a className="source-link" href={repository} aria-label="MirageMesh source on GitHub"><Icon name="code-2"/><span>GitHub</span></a></div></header>
      <main id="content" tabIndex={-1}>{children}</main>
      <footer><span>MirageMesh <span className="footer-separator">/</span> Evidence before conclusions.</span><span>No telemetry · No automatic file uploads</span></footer>
    </div>
    <dialog ref={dialog} className="command-dialog" aria-labelledby="search-title" onClick={event => { if (event.target === event.currentTarget) dialog.current?.close(); }}>
      <div className="command-heading"><h2 id="search-title">Go to a workspace page</h2><Button variant="ghost" className="icon-button" aria-label="Close workspace search" onClick={() => dialog.current?.close()}><Icon name="x"/></Button></div>
      <label className="command-input"><Icon name="search"/><input autoFocus type="search" aria-label="Find a workspace page" placeholder="Search pages…" value={search} onChange={event => setSearch(event.target.value)}/></label>
      <nav aria-label="Search results">{matches.map(item => <a key={item.id} href={`#${item.id}`} onClick={() => dialog.current?.close()}><Icon name={item.icon}/><div><strong>{item.title}</strong><small>{item.description}</small></div><Icon name="arrow-right"/></a>)}</nav>
      {matches.length === 0 && <p className="command-empty">No pages match. Try “sensors” or “incidents”.</p>}<p className="command-hint">Tab to a result · Enter to open · Escape to close</p>
    </dialog>
  </div>;
}
