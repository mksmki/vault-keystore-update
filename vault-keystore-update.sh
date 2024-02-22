#!/usr/bin/env bash

# Requires curl and jq to be installed

set -euo pipefail

declare -r JQ=$(which jq)
declare ROLE_ID=${ROLE_ID:-}
declare SECRET_ID=${SECRET_ID:-}

function log_error() {
  local -r ERROR_TEXT="\033[0;31m"
  local -r NO_COLOR="\033[0m"
  echo -e "$(date --utc +%FT%T.%3NZ) ${ERROR_TEXT}$1${NO_COLOR}"
}

function log_warn() {
  local -r WARN_TEXT="\033[0;33m"
  local -r NO_COLOR="\033[0m"
  echo -e "$(date --utc +%FT%T.%3NZ) ${WARN_TEXT}$1${NO_COLOR}"
}

function log_success() {
  local -r GREEN_TEXT="\033[0;32m"
  local -r NO_COLOR="\033[0m"
  echo -e "$(date --utc +%FT%T.%3NZ) ${GREEN_TEXT}$1${NO_COLOR}"
}

function catch_signal() {
    local -ir EXIT_CODE=$?
    if (( $EXIT_CODE != 0 ))
    then
        log_error "Error code: ${EXIT_CODE}" >&2
    else
        log_success "Completed!"
        exit 0
    fi
    exit 1
}

function import_variables() {
    local -r SCRIPT_VARS="$(dirname $0)/env.rc"
    [[ -r "${SCRIPT_VARS}" ]] || {
        log_error "Error: env.rc not exists or not readable"
        exit 1
    }
    source ${SCRIPT_VARS}

    log_success "Variables imported"
}

function read_secret_prompt() {
    local secret=""
    local prompt="$1"

    while IFS= read -p "$prompt" -r -s -n 1 char; do
        if [[ "$char" == $'\0' ]]; then
            break
        fi

        secret="${secret}${char}"
        prompt="*"
    done
    echo -n "${secret}"
}

function run_checks() {
    [[ -x ${JQ} ]] || {
        log_error "Error: jq is not found or not executable"
        exit 1
    }

    [[ -x ${LS_KEYSTORE} ]] || {
        log_error "Error: ${LS_KEYSTORE} script not found or not executable"
        exit 1
    }

    if [[ -z "${ROLE_ID}" ]]; then
        log_warn "Application role_id for Vault authorization is not defined"
        ROLE_ID=$(read_secret_prompt "Enter ROLE_ID: ")
        echo ""

        [[ -n "${ROLE_ID}" ]] || {
            log_error "Error: ROLE_ID is not set or empty!"
            exit 1
        }
    fi

    if [[ -z "${SECRET_ID}" ]]; then
        log_warn "Application secret_id for Vault authorization is not defined"
        SECRET_ID=$(read_secret_prompt "Enter SECRET_ID: ")
        echo ""

        [[ -n "${SECRET_ID}" ]] || {
            log_error "Error: SECRET_ID is not set or empty!"
            exit 1
        }
    fi

    log_success "Parameters verified"
}

function get_vault_token() {
    VAULT_TOKEN=$(curl ${CURL_INSECURE:-} \
        --silent \
        --request PUT \
        --header "X-Vault-Request: true" \
        --data "{\"role_id\": \"${ROLE_ID}\",\"secret_id\": \"${SECRET_ID}\"}" \
        ${VAULT_LOGIN_URL} \
        | ${JQ} .auth.client_token \
        | sed 's/"//g')

    [[ -n "${VAULT_TOKEN}" ]] || {
        log_error "Error: Vault login failed"
        exit 1
    }

    log_success "Vault login successful"
}

function get_secret_data() {
    VAULT_DATA=$(curl ${CURL_INSECURE:-} \
        --silent \
        --request GET \
        --header "X-Vault-Request: true" \
        --header "X-Vault-Token: ${VAULT_TOKEN}" \
        ${VAULT_SECRETS_URL} \
        | ${JQ} -c .data)

    [[ -n "${VAULT_DATA}" ]] || {
        log_error "Error: Secret data is empty"
        exit 1
    }

    log_success "Vault secret data fetched"
}

function backup_keystore() {
    local keystore_name="${LS_DB_PATH}/logstash.keystore"
    local backup_name="${LS_DB_PATH}/logstash.keystore-$(date --utc +%Y%m%d%H%M%S)"

    if [[ -r "${backup_name}" ]]; then
        log_warn "Keystore DB with name ${backup_name} already exists. Exiting"
        exit 0
    fi

    cp "${keystore_name}" "${backup_name}"
    log_success "Keystore DB backup created with name ${backup_name}"
}

function prepare_keystore_db() {
    local keystore_name="${LS_DB_PATH}/logstash.keystore"

    if [[ -f "${keystore_name}" ]]; then
        backup_keystore
    else
        local ls_result=$(echo 'y' | ${LS_KEYSTORE} --path.settings ${LS_DB_PATH} create)
        if [[ "x$(echo -n ${ls_result} | grep -oc 'Created')" != "x0" ]]; then
            log_success "New Keystore DB created ${keystore_name}"
        else
            log_error "Error: Cannot create new Keystore DB at ${keystore_name}"
            exit 1
        fi
    fi

    if [[ ! -r ${keystore_name} ]]; then
        log_error "Error: Logstash keystore DB (${keystore_name}) does not exists or not readable"
        exit 1
    fi

    if [[ ! -w ${keystore_name} ]]; then
        log_error "Error: Logstash keystore DB (${keystore_name}) does not exists or not writable"
        exit 1
    fi
}

function keystore_secret_data() {
    local key
    local value

    for key in $(echo -n "${VAULT_DATA}" | ${JQ} 'keys[]' | sed 's/"//g'); do
        local value=$(echo -n "${VAULT_DATA}" | ${JQ} .${key} | sed 's/"//g')
        local value_hash=$(echo -n "${value}" | sha256sum | cut -f1 -d' ')

        #! DEBUG
        # echo "Key name: ${key} -> ${value}"
        local ls_result=$(${LS_KEYSTORE} --path.settings ${LS_DB_PATH} remove ${key})
        if [[ "$(echo -n ${ls_result} | grep -o 'does not exist')" == "does not exist" ]]; then
            log_warn "Key ${key} not found in Keystore DB"
        else
            log_success "Key ${key} removed from Keystore DB"
        fi

        if [[ "${value}x" != "x" ]]; then
            local ls_update_result=$(echo -n "${value}" | ${LS_KEYSTORE} --path.settings ${LS_DB_PATH} add ${key})
            if [[ "$(echo -n ${ls_update_result} | grep -o 'Added')" == "Added" ]]; then
                log_success "Key ${key} added to Keystore DB with hashed value SHA256 ${value_hash}"
            else
                log_error "Error: key ${key} not added to Keystore DB"
            fi
        else
            log_warn "Skipping empty value for key ${key}"
        fi

    done
}

function banner() {
    cat << EOF
 __      __         _ _     _  __              _                   _    _           _       _
 \\ \\    / /        | | |   | |/ /             | |                 | |  | |         | |     | |
  \\ \\  / __ _ _   _| | |_  | ' / ___ _   _ ___| |_ ___  _ __ ___  | |  | |_ __   __| | __ _| |_ ___
   \\ \\/ / _\` | | | | | __| |  < / _ | | | / __| __/ _ \\| '__/ _ \\ | |  | | '_ \\ / _\` |/ _\` | __/ _ \\
    \\  | (_| | |_| | | |_  | . |  __| |_| \\__ | || (_) | | |  __/ | |__| | |_) | (_| | (_| | ||  __/
     \\/ \\__,_|\\__,_|_|\\__| |_|\\_\\___|\\__, |___/\\__\\___/|_|  \\___|  \\____/| .__/ \\__,_|\\__,_|\\__\\___|
                                      __/ |                              | |
                                     |___/                               |_|

EOF
}

function main() {
    trap catch_signal EXIT

    banner
    import_variables
    run_checks
    prepare_keystore_db

    get_vault_token
    #! DEBUG
    # echo "${VAULT_TOKEN}"
    get_secret_data
    # echo "${VAULT_DATA}"
    keystore_secret_data
}

main "$@"
