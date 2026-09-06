.PHONY: build-LiminalRecallFunction

# SAM may stage the CodeUri before this target runs. The builder clears that
# staging directory and repopulates it from an explicit runtime allowlist.
build-LiminalRecallFunction:
	python3 build_lambda.py "$(ARTIFACTS_DIR)"
