# Updating controlled tools

Open a pull request with the tool ID, upstream commit, observed CLI identity, license changes and reason for updating. Resolve tags to full commits and update the corresponding source lock and build recipe together. Preserve the source pin used by an existing artifact.

Run the contract validator and tests. Build candidates use the central workflow, with inherited fork workflows disabled. Review changes to build scripts and Cargo.lock before dispatching a new build. Do not add secrets to source, artifacts, reports or logs.

Attach measured evidence with exact package, adapter, app, platform and model identities. Upstream release labels, clean compilation and model prose do not substitute for the application's acceptance gates. Candidate artifacts are not approved installer catalogues. Follow the promotion contract before creating a managed release.
