export function validatePublication(plan, source) {
  if (plan?.schema_version !== 1 || plan.repository !== 'Parsa-Emami/Miragemesh' || source.repository !== plan.repository || plan.publication_authorized !== true || !plan.authorization?.trim()) throw new Error('Publication is not authorized for this repository.');
  if (!source.clean || !/^[a-f0-9]{40}$/.test(source.commit)) throw new Error('Publication requires an exact clean source commit.');
  if (!/^\d+\.\d+\.\d+$/.test(plan.version) || source.version !== plan.version || plan.tag !== `v${plan.version}` || plan.platform !== 'linux-amd64' || !Number.isSafeInteger(plan.revision) || plan.revision < 1) throw new Error('Publication version, tag or platform does not match the approved plan.');
  return Object.freeze({ ...plan });
}
