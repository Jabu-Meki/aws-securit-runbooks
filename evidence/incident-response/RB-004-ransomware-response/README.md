# Evidence — RB-004-ransomware-response

**Naming:** `YYYY-MM-DD_INC-XXXX_<description>.<ext>`

## Required
- `*_guardduty-finding.json`
- `*_cloudtrail-export.json`
- `*_config-before.json`
- `*_config-after.json`
- `*_timeline.md`
- `*_post-incident-review.md`

```bash
sha256sum * > evidence-hashes-$(date +%Y%m%d).txt
```

See [evidence package template](../../templates/incident-evidence-package.md).
