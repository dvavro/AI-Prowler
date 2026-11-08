# Upload plans and check the scale
<!-- screen: plans; words: upload, plans, pdf, sheets, scale, calibrate, viewport, read, blueprint -->
The plan engine reads a PDF plan set: it splits it into sheets, reads each title block (sheet number, title, revision) and finds each view's scale. Check the scales before anything is measured.

1. Open the project and, under **Plans**, choose the PDF (or a scan or photo) and click **Upload and check**, then **Attach**.
2. Click the file name to open the plan set, then click **📖 Read the plans…** and **Yes**. The page updates by itself while it reads.
3. Look down the sheet list. Each sheet shows its number, title, discipline and the scales found. A yellow **needs a scale** means a view has no scale yet.
4. Click a sheet. The views are outlined on the drawing: blue has a scale, dashed yellow has none, dotted grey is not to scale (NTS).
5. To fix a scale, type it as written on the drawing (for example 1/4" = 1'-0") next to the view and click **Set…**, then **Yes**.
6. No scale written? Click **📏 Calibrate…**, click both ends of something you know the length of (a dimension line or a door), type the real length (for example 12'-6") and click **Set the scale…**, then **Yes**.

## Good to know
- Changing a scale re-measures everything in that view.
- Scans and photos have no text the engine can read yet, so calibrate them.
- DXF and DWG drawings are read from a later plan-engine release; print them to PDF for now.
- Owners and estimators can read plans and set scales; reviewers and field staff can look at them.
