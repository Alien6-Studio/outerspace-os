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
  document.getElementById('copy-commands').addEventListener('click', async e => {
    try { await navigator.clipboard.writeText(document.getElementById('build-commands').textContent); e.target.textContent = 'Copied'; }
    catch { e.target.textContent = 'Select code'; const selection = window.getSelection(); const range = document.createRange(); range.selectNodeContents(document.getElementById('build-commands')); selection.removeAllRanges(); selection.addRange(range); }
    setTimeout(() => { e.target.textContent = 'Copy'; }, 2500);
  });
})();
