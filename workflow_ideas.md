## Workflow ideas

- Fetching KB for platform 25h2/24h2 x64
- Only take the KB number -- KB5077181 , only take 5077181
- From https://support.microsoft.com/help/{KB_NUM} --> https://support.microsoft.com/help/5077181
- Download .csv from the  "File information" section . the link to download the .csv will be in the href of an <a> element of class "ocpExternalLink" containing the text "download the file information for cumulative update {KB Number}"
`<a href="https://go.microsoft.com/fwlink/?linkid=2350331" target="_blank" class="ocpExternalLink" data-bi-type="anchor">download the file information for cumulative update 5077181</a>`
- filter only for .exe , .dll and .sys files.
- compare version with previous month to get only actual updated files , not repackaged ones.
