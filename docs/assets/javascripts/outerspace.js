(() => {
  const menu = document.querySelector('.menu-toggle');
  const nav = document.getElementById('nav');
  const closeMenu = () => { menu.setAttribute('aria-expanded', 'false'); nav.classList.remove('open'); };
  menu.addEventListener('click', () => {
    const open = menu.getAttribute('aria-expanded') !== 'true';
    menu.setAttribute('aria-expanded', String(open)); nav.classList.toggle('open', open);
  });
  nav.querySelectorAll('a').forEach(a => a.addEventListener('click', closeMenu));
  document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeMenu(); menu.focus(); } });
  const content = {
    cold: ['COLD CACHE', 'The first node fetches from origin.', 'The configured Dragonfly peer retrieves image blobs from the registry. Containerd keeps origin resolution over HTTPS and verifies OCI content digests.'],
    peers: ['PEER DELIVERY', 'The next node can reuse available pieces.', 'Dragonfly coordinates transfers from available peers. Every node still needs the image layers it uses; P2P reduces repeated origin traffic, rather than eliminating local storage.'],
    gc: ['SEPARATE LIFECYCLES', 'Keep what runs. Retire what waits.', 'Kubelet collects unused images with a 24-hour maximum age and disk-pressure thresholds. Dragonfly expires its separate peer cache after six hours. Kubelet age tracking resets on restart.']
  };
  const tabs = [...document.querySelectorAll('[data-flow]')];
  function select(tab) {
    tabs.forEach(t => { const on = t === tab; t.setAttribute('aria-selected', String(on)); t.tabIndex = on ? 0 : -1; });
    const [label, title, description] = content[tab.dataset.flow];
    const panel = document.getElementById('flow-panel'); panel.dataset.stage = tab.dataset.flow; panel.setAttribute('aria-labelledby', tab.id);
    document.getElementById('flow-label').textContent = label;
    document.getElementById('flow-title').textContent = title;
    document.getElementById('flow-description').textContent = description;
  }
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => select(tab));
    tab.addEventListener('keydown', e => {
      const indexes = { ArrowRight: (i + 1) % tabs.length, ArrowLeft: (i + tabs.length - 1) % tabs.length, Home: 0, End: tabs.length - 1 };
      if (e.key in indexes) { e.preventDefault(); const next = tabs[indexes[e.key]]; select(next); next.focus(); }
    });
  });
  document.getElementById('copy-commands').addEventListener('click', async e => {
    try { await navigator.clipboard.writeText(document.getElementById('build-commands').textContent); e.target.textContent = 'Copied'; }
    catch { e.target.textContent = 'Select code'; const selection = window.getSelection(); const range = document.createRange(); range.selectNodeContents(document.getElementById('build-commands')); selection.removeAllRanges(); selection.addRange(range); }
    setTimeout(() => { e.target.textContent = 'Copy'; }, 2500);
  });
})();
