.PHONY: test test-core test-crypto test-encoding test-protocol lint clean

BASH        := bash
TEST_RUNNER := tests/run_tests.sh
SHELL_FILES := $(shell find . -name '*.sh' -not -path '*/tmp/*')

# ── Tests ────────────────────────────────────────────────────────────────────

test:
	@$(BASH) $(TEST_RUNNER)

test-core:
	@$(BASH) $(TEST_RUNNER) core

test-crypto:
	@$(BASH) $(TEST_RUNNER) crypto

test-encoding:
	@$(BASH) $(TEST_RUNNER) encoding

test-protocol:
	@$(BASH) $(TEST_RUNNER) protocol

# ── Qualité ──────────────────────────────────────────────────────────────────

lint:
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck requis : apt install shellcheck"; exit 1; }
	@shellcheck $(SHELL_FILES)

# ── Nettoyage ────────────────────────────────────────────────────────────────

clean:
	@rm -rf tests/tmp
	@echo "Nettoyé."
