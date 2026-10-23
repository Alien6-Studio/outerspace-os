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

To publish, rebuild the tracked HTML, commit it with the source changes, and push:

```sh
mkdocs build --strict -f site/mkdocs.yml --site-dir "$PWD/docs"
git add site docs
git commit -m "Update website"
git push origin gh-pages
```

CI checks the source build. It does not change the repository Pages configuration.
