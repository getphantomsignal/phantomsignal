# Vendored data

## wmn-data.json — WhatsMyName site rules

Username-enumeration detection rules used by `scrapers/username_enum.py`.

- **Source:** [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) by Micah Hoffman.
- **License:** Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0).
  The `license` field is preserved inside the JSON. This data file is licensed
  separately from PhantomSignal's MIT code.
- **Update:** replace with the latest `wmn-data.json` from the upstream repo to
  refresh the site list; the schema (`name`, `uri_check`, `e_code`, `e_string`,
  `m_string`, `cat`) is consumed as-is.
