# AstroTalk Inventory Portal

Unified inventory dashboard combining Products, Packaging, and Certificate inventory.

## Structure

```
public/
  index.html        ← Portal shell (tab switcher)
  packaging.html    ← Packaging DRR dashboard
  certificates.html ← Certificate inventory dashboard
```

The Products dashboard is loaded from its existing Vercel deployment via iframe.

## Deploy to Vercel

1. Push this repo to GitHub
2. Go to [vercel.com](https://vercel.com) → New Project → Import your repo
3. Framework: **Other** (static site)
4. Root directory: leave blank (or set to `/`)
5. Build command: leave blank
6. Output directory: `public`
7. Deploy

That's it — all three dashboards will be live under one URL.

## Update data

- **Packaging**: click "Upload CSV" inside the Packaging tab
- **Certificates**: upload both CSVs using the dropzones inside the Certificates tab
- **Products**: already live at weekly-dashboard-yxe7.vercel.app
