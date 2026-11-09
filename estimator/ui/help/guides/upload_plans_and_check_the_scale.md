# Upload plans and check the scale
<!-- screen: plans; words: upload, plans, pdf, sheets, scale, calibrate, viewport, read, blueprint, scan, photo, dwg, needs review -->
The plan engine reads a PDF plan set: it splits it into sheets, reads each title block (sheet number, title, revision) and finds each view's scale. Check the scales before anything is measured.

1. Open the project and, under **Plans**, choose the PDF (or a scan or photo) and click **Upload and check**, then **Attach**.
2. Click the file name to open the plan set, then click **📖 Read the plans…** and **Yes**. The page updates by itself while it reads.
3. Look down the sheet list. Each sheet shows its number, title, discipline and the scales found. A yellow **needs a scale** means a view has no scale yet.
4. Click a sheet. The views are outlined on the drawing: blue has a scale, dashed yellow has none, dotted grey is not to scale (NTS).
5. To fix a scale, type it as written on the drawing (for example 1/4" = 1'-0") next to the view and click **Set…**, then **Yes**.
6. No scale written? Click **📏 Calibrate…**, click both ends of something you know the length of (a dimension line or a door), type the real length (for example 12'-6") and click **Set the scale…**, then **Yes**.

## Good to know
- Changing a scale re-measures everything in that view.
- Scans and photos: a tilted scan is straightened, a blueprint (light lines on a dark sheet) is turned the right way round, and a phone photo of a sheet on a table is squared up to its page edges. Walls and straight lines are traced, and with OCR (Tesseract) installed the words are read too. Everything found on a scan or photo says **needs review**: check each quantity on the plan before approving it.
- A photo has no true size: always **📏 Calibrate…** it from something you know the length of. A tilted or curled page measures less well than a scan; for bidding, ask for the PDF.
- **Found on this sheet** lists the walls and rooms the engine found (and, for DXF drawings, symbols, notes and dimensions), with their measured totals once the view has a scale.
- DXF drawings are read at real size, so they never need a scale. DWG files are converted to DXF when the free **ODA File Converter** (opendesign.com, Guest Files) or LibreDWG is installed on this PC; the Estimator tab's **CAD and tools** section shows whether one was found. Without one, save the drawing as DXF from your CAD program, or print to PDF.
- Owners and estimators can read plans and set scales; reviewers and field staff can look at them.
