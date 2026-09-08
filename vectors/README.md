# Conformance vectors

One directory per case:

```
<case-name>/
  input.<ext>       the file as a verifier receives it
  proof.json        the proof, where it is not inside the file
  expected.json     the expected verdict and the reason for each check
  NOTES.md          how the case was produced, and what it is testing
```

Written **before** the code that produces them. Expected verdicts are decided in
review; never edited to make an implementation pass.

Cases to cover at minimum: valid photo, valid video, broken signature, truncated
file, corrupted trailer, missing timestamp, missing anchor, unknown minor
version, watermark-only match, cropped photo beyond the correction budget,
re-encoded video per platform, cut clip with contiguous segments.
