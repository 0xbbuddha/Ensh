#!/usr/bin/env bash
#
# tests/run_tests.sh — Lanceur de tests Ensh
#
# Usage :
#   ./tests/run_tests.sh           # Tous les tests
#   ./tests/run_tests.sh core      # Seulement les tests du module "core"
#   ./tests/run_tests.sh crypto    # Seulement "crypto"
#
# Convention de fichiers de tests :
#   tests/<module>/test_<nom>.sh
#
# Convention des fonctions de test dans chaque fichier :
#   Chaque fonction dont le nom commence par "test::" est automatiquement
#   découverte et exécutée.
#
# ─────────────────────────────────────────────────────────────────────────────

set -uo pipefail

readonly TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ENSH_ROOT="$(dirname "${TESTS_DIR}")"

source "${ENSH_ROOT}/ensh.sh"

# ── Compteurs ─────────────────────────────────────────────────────────────────
declare -gi _TEST_TOTAL=0
declare -gi _TEST_PASSED=0
declare -gi _TEST_FAILED=0
declare -gi _TEST_SKIPPED=0
declare -ga _TEST_FAILURES=()

# ── Assertions ────────────────────────────────────────────────────────────────

# assert::equal <actual> <expected> [message]
assert::equal() {
    local actual="$1"
    local expected="$2"
    local msg="${3:-}"
    (( _TEST_TOTAL++ ))
    if [[ "${actual}" == "${expected}" ]]; then
        (( _TEST_PASSED++ ))
        return 0
    else
        (( _TEST_FAILED++ ))
        local context="${msg:+${msg} — }"
        _TEST_FAILURES+=( "  ÉCHEC : ${context}obtenu='${actual}' attendu='${expected}'" )
        return 1
    fi
}

# assert::not_equal <actual> <unexpected> [message]
assert::not_equal() {
    local actual="$1"
    local unexpected="$2"
    local msg="${3:-}"
    (( _TEST_TOTAL++ ))
    if [[ "${actual}" != "${unexpected}" ]]; then
        (( _TEST_PASSED++ ))
        return 0
    else
        (( _TEST_FAILED++ ))
        _TEST_FAILURES+=( "  ÉCHEC : ${msg:+${msg} — }valeur inattendue='${actual}'" )
        return 1
    fi
}

# assert::empty <value> [message]
assert::empty() {
    assert::equal "$1" "" "${2:-valeur devrait être vide}"
}

# assert::not_empty <value> [message]
assert::not_empty() {
    assert::not_equal "$1" "" "${2:-valeur ne devrait pas être vide}"
}

# assert::length_equal <hex_string> <expected_bytes> [message]
# Vérifie que la longueur en octets d'une chaîne hex est correcte.
assert::length_equal() {
    local actual_bytes=$(( ${#1} / 2 ))
    assert::equal "${actual_bytes}" "$2" "${3:-longueur en octets}"
}

# assert::returns_zero <command...>
assert::returns_zero() {
    (( _TEST_TOTAL++ ))
    if "$@" 2>/dev/null; then
        (( _TEST_PASSED++ ))
        return 0
    else
        (( _TEST_FAILED++ ))
        _TEST_FAILURES+=( "  ÉCHEC : '$*' n'a pas retourné 0" )
        return 1
    fi
}

# skip <reason>
skip() {
    (( _TEST_SKIPPED++ ))
    log::debug "SKIP : $1"
}

# ── Exécution d'un fichier de tests ───────────────────────────────────────────

_run_test_file() {
    local file="$1"
    local file_rel="${file#${TESTS_DIR}/}"

    # Capturer les fonctions test:: existantes AVANT le source
    local -A _before_fns=()
    local fn
    while IFS= read -r fn; do
        [[ "${fn}" == test::* ]] && _before_fns["${fn}"]=1
    done < <(declare -F | awk '{print $3}')

    # Sourcer le fichier pour charger ses fonctions test::*
    # shellcheck source=/dev/null
    source "${file}" || {
        log::warn "Impossible de charger le fichier de tests : ${file_rel}"
        return
    }

    # Découvrir uniquement les NOUVELLES fonctions test::*
    local -a test_fns=()
    while IFS= read -r fn; do
        [[ "${fn}" == test::* ]] && [[ -z "${_before_fns[${fn}]:-}" ]] && test_fns+=( "${fn}" )
    done < <(declare -F | awk '{print $3}')

    if (( ${#test_fns[@]} == 0 )); then
        log::debug "Aucun test dans ${file_rel}"
        return
    fi

    printf '\n  \033[1m%s\033[0m\n' "${file_rel}"

    for fn in "${test_fns[@]}"; do
        local before_failed="${_TEST_FAILED}"
        local before_total="${_TEST_TOTAL}"

        # Exécuter dans un sous-shell pour isoler les erreurs fatales,
        # puis re-synchroniser les compteurs depuis un fichier temporaire.
        "${fn}" 2>/dev/null || true

        local after_failed="${_TEST_FAILED}"
        local after_total="${_TEST_TOTAL}"
        local fn_asserts=$(( after_total - before_total ))
        local fn_failed=$(( after_failed - before_failed ))

        if (( fn_failed == 0 )); then
            printf '    \033[0;32m✓\033[0m %s (%d assertion(s))\n' \
                "${fn#test::}" "${fn_asserts}"
        else
            printf '    \033[0;31m✗\033[0m %s (%d/%d assertion(s) échouée(s))\n' \
                "${fn#test::}" "${fn_failed}" "${fn_asserts}"
        fi
    done
}

# ── Point d'entrée ────────────────────────────────────────────────────────────

main() {
    local filter="${1:-}"
    local -a test_files=()

    if [[ -n "${filter}" ]]; then
        while IFS= read -r f; do
            test_files+=( "${f}" )
        done < <(find "${TESTS_DIR}/${filter}" -name 'test_*.sh' -type f 2>/dev/null | sort)
    else
        while IFS= read -r f; do
            test_files+=( "${f}" )
        done < <(find "${TESTS_DIR}" -name 'test_*.sh' -type f 2>/dev/null | sort)
    fi

    if (( ${#test_files[@]} == 0 )); then
        printf '\033[0;33mAucun fichier de tests trouvé%s\033[0m\n' \
            "${filter:+ dans '${filter}'}"
        exit 0
    fi

    printf '\033[1mEnsh — Suite de tests\033[0m\n'
    printf '════════════════════════════════════\n'

    for f in "${test_files[@]}"; do
        _run_test_file "${f}"
    done

    printf '\n════════════════════════════════════\n'
    printf 'Total   : %d\n' "${_TEST_TOTAL}"
    printf '\033[0;32mPassés  : %d\033[0m\n' "${_TEST_PASSED}"

    if (( _TEST_FAILED > 0 )); then
        printf '\033[0;31mÉchecs  : %d\033[0m\n' "${_TEST_FAILED}"
        printf '\nDétail des échecs :\n'
        local failure
        for failure in "${_TEST_FAILURES[@]}"; do
            printf '%s\n' "${failure}"
        done
    fi

    if (( _TEST_SKIPPED > 0 )); then
        printf 'Ignorés : %d\n' "${_TEST_SKIPPED}"
    fi

    printf '\n'
    (( _TEST_FAILED == 0 ))
}

main "$@"
