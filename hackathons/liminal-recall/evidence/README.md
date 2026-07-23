# Live evidence staging area

`live_deploy.py` writes deployment and runtime proof here. Generated files are ignored by Git by default because even sanitized cloud output must receive a human review before publication.

Before adding any artifact to the final submission commit:

1. inspect it for database URLs, usernames, tokens, passwords, certificates, AWS account details that are not needed, and private endpoints;
2. confirm every claim refers to the final commit and live deployment;
3. add only the bounded evidence required by the judging scorecard;
4. use `git add -f evidence/<reviewed-file>` for a deliberately reviewed artifact.

Never force-add an entire evidence directory.
