# GillNet AI pixel-accurate dashboard redesign

## Build
- Rework the desktop canvas to the specified 1440×960 composition with a 226px ivory sidebar, 740px main column, and 368px right column.
- Match every supplied panel size, radius, border, spacing, font size, icon treatment, status color, and row position.
- Use Fraunces for the brand and sidebar, Habibi for section headings, and Poppins for interface copy.
- Place the supplied globe image in the exact 204×124 right-side crop inside the welcome panel.
- Preserve the existing scan and password interactions and maintain a practical stacked layout on smaller screens.

## Technical details
- Update semantic color and typography tokens in the global stylesheet.
- Update the dashboard markup and dimensions in the home page only.
- Add Fraunces to the existing font stylesheet link.
- Verify the finished result at desktop and mobile widths, including interactions and browser errors.
