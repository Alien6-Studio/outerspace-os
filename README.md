# OuterSpace OS website

This branch owns the website sources (`site/`) and the published HTML (`docs/`).
The Linux distribution is developed on `main`. GitHub Pages can continue serving
`gh-pages:/docs`; the existing custom domain `os.outerspace.sh` is preserved.

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r site/requirements.txt
mkdocs serve -f site/mkdocs.yml
```

Create a topic branch from `gh-pages`. To publish, rebuild the tracked HTML and
commit it with the source changes:

```sh
mkdocs build --strict -f site/mkdocs.yml --site-dir "$PWD/docs"
git add site docs
git commit -m "Update website"
git push -u origin HEAD
```

Open a pull request targeting `gh-pages`. The required `site-quality` check builds
MkDocs in strict mode; merge after it passes and review threads are resolved.
GitHub Pages serves the committed `docs/` directory after merge.

The distribution's [contribution guide](https://github.com/Alien6-Studio/outerspace-os/blob/main/CONTRIBUTING.md),
[security policy](https://github.com/Alien6-Studio/outerspace-os/blob/main/SECURITY.md)
and [Code of Conduct](https://github.com/Alien6-Studio/outerspace-os/blob/main/CODE_OF_CONDUCT.md)
also apply to this branch. Repository settings and rulesets are tracked on `main`
under `.github/repository/`.
