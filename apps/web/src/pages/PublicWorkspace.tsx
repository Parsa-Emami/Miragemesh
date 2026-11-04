const repository = 'https://github.com/Parsa-Emami/Miragemesh';
const features = [
  ['Identity you can verify', 'One-time enrollment, mutual TLS, signed configuration, certificate rotation and recovery.'],
  ['Events that survive interruption', 'A bounded offline spool, durable acknowledgements, duplicate protection and explicit loss accounting.'],
  ['Evidence you can trace', 'Immutable event segments, rebuildable indexes, incident replay and durable triage rationale.'],
  ['Operations with measured limits', 'Local readiness, redacted diagnostics, retention coverage and tested backup and restore.'],
];

export default function PublicWorkspace({ section }: { section: string }) {
  return <>
    <section className="notice" aria-label="Public deployment"><span className="dot"/>Public browser workspace · Engine and sensor processing run on your Linux host.</section>
    {section !== 'workspace' && <section className="panel"><h2>Use {section} in your local workspace</h2><p>This public site has no access to your sensors, incidents, certificates or credentials. Install the complete Linux release to open the operational views against your own engine.</p><a className="text-link" href={repository + '/releases/latest'}>Get the local release →</a></section>}
    <section className="panel public-release"><div><div className="eyebrow">Apache-2.0 · Local first</div><h2>Keep your observations close.<br/>Make every incident explainable.</h2><p>MirageMesh connects sensor identity, offline delivery and source-backed incident review in one open-source workflow.</p><div className="public-actions"><a className="file-button" href={repository + '/releases/latest'}>Download the Linux release</a><a className="text-link" href={repository}>Explore the source →</a></div></div><div className="public-terminal"><span>START ON YOUR OWN HOST</span><pre><code>{'git clone ' + repository + '.git\ncd Miragemesh\nnpm run setup\nnpm start'}</code></pre><a href={repository + '/blob/main/docs/engineering/CLONE_TO_RUN.md'}>Prerequisites and installation guide →</a></div></section>
    <div className="grid">{features.map(([title, text]) => <section className="panel" key={title}><h2>{title}</h2><p>{text}</p></section>)}</div>
    <section className="panel"><div className="eyebrow">Verified local profile</div><h2>Clear boundaries. Repeatable checks.</h2><p>Ubuntu 24.04 · Linux amd64 · rootless Podman. The recorded capacity test sustained 8 events per second with 5 sensors for 30 seconds under a 2 vCPU / 2 GiB limit.</p><p>Check the release evidence for the exact source, supported environment, test results and installation proof. Additional operating systems and hosted multi-user deployments require separate validation.</p><div className="public-actions"><a className="text-link" href={repository + '/blob/main/docs/release/PUBLICATION.md'}>Verify and install →</a><a className="text-link" href="#roadmap">Inspect the roadmap →</a><a className="text-link" href={repository + '/blob/main/SECURITY.md'}>Security policy →</a></div></section>
  </>;
}
