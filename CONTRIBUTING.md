# Contributing to OwlScan

Thanks for wanting to improve OwlScan. Here's how to get from zero to a merged PR.

Before you start: read the [Code of Conduct](CODE_OF_CONDUCT.md). It is short, direct, and non-negotiable. If you are contributing a security-relevant change or have found a vulnerability, read the [Security Policy](SECURITY.md) first.

---

## Dev Setup

```bash
git clone https://github.com/owlscan/owlscan
cd owlscan
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
owlscan init          # creates ~/.owlscan/config.yaml
owlscan web           # http://localhost:5000
```

---

## What to Contribute

| Area | Where to look |
|---|---|
| New intelligence API | `owlscan/intel/apis/` — copy `shodan_api.py` as a template |
| New tech fingerprint | `owlscan/scrapers/tech_detector.py` |
| New export format | `owlscan/exporters/manager.py` |
| Bug fix | File an issue first if the root cause is unclear |
| Web UI / templates | `owlscan/web/templates/`, `owlscan/web/static/` |

---

## Adding a New API (the fast path)

The plugin system auto-registers anything decorated with `@register_api`:

```python
# owlscan/intel/apis/myapi.py
from owlscan.intel.apis.base import BaseIntelAPI, register_api, APICategory, APITier

@register_api
class MyAPI(BaseIntelAPI):
    NAME = "myapi"
    DESCRIPTION = "My source"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.NETWORK]
    BASE_URL = "https://api.example.com/v1"
    SIGN_UP_URL = "https://example.com/signup"

    async def search(self, query: str, **kwargs):
        data = await self._get(f"{self.BASE_URL}/search", params={"q": query, "key": self._api_key})
        return [self._wrap_result("result", data)]
```

Then add one import line to `owlscan/intel/orchestrator.py`.

---

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Match the existing code style (no new linting warnings)
- If you add a new API, include the `SIGN_UP_URL` so users can get a key
- Don't commit `config/owlscan.yaml` or any file containing API keys
- Reference any related issue in the PR description (`Fixes #123`)

---

## Reporting Bugs

Use the [bug report template](https://github.com/owlscan/owlscan/issues/new?template=bug_report.md).

For security vulnerabilities, **do not open a public issue.** Follow the process in [`SECURITY.md`](SECURITY.md) — private email first, coordinated disclosure before anything goes public.

---

## License

By contributing you agree your code will be released under the [MIT License](LICENSE).
