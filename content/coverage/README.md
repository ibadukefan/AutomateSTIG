# Coverage Manifests

This directory contains rule-by-rule coverage manifests for STIGs that AutomateSTIG claims to support.

A supported manifest answers three questions for every DISA rule:

1. Does AutomateSTIG automate it, import it from a scanner, or require manual review?
2. Where is the implementation or evidence mapping?
3. What tests prove the behavior?

Check packs without matching manifests are experimental/community content.

`*.example.json` manifests exercise sanitized fixture workflows. `*.full.json` manifests enumerate every rule currently represented in the corresponding AutomateSTIG check pack for flagship targets, but remain `experimental` until cross-checked against authorized real DISA benchmark releases and scanner/checklist fixture corpora.
