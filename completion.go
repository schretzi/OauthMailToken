package main

import "fmt"

// runCompletionCommand implements the "completion" subcommand: print a
// shell completion script for args.Shell ("bash" or "zsh") to stdout. Both
// scripts complete subcommands/flags and, for the commands that take an
// account argument, shell out to "omt list-accounts" to offer the
// configured account names - so account completion always reflects the
// current config.yaml without needing to be regenerated.
func runCompletionCommand(args *Args) error {
	switch args.Shell {
	case "bash":
		fmt.Print(bashCompletionScript)
	case "zsh":
		fmt.Print(zshCompletionScript)
	default:
		// parseArgs already validates this; unreachable in practice.
		return fmt.Errorf("unsupported shell %q (want \"bash\" or \"zsh\")", args.Shell)
	}
	return nil
}

// bashCompletionScript is self-contained (doesn't depend on the
// bash-completion package's _init_completion helper being installed).
// Install with: source <(omt completion bash)   # e.g. in ~/.bashrc
const bashCompletionScript = `# bash completion for omt - source <(omt completion bash)
_omt_completion() {
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local commands="authorize refresh list-accounts status token completion daemon"
    local flags="-h --help -v --verbose -d --debug -a --authorize --authflow -t --test"

    if [[ "$prev" == "--authflow" ]]; then
        COMPREPLY=( $(compgen -W "authcode localhostauthcode devicecode" -- "$cur") )
        return 0
    fi
    if [[ "$prev" == "completion" ]]; then
        COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") )
        return 0
    fi

    local subcommand=""
    if [[ ${COMP_CWORD} -ge 1 ]]; then
        case "${COMP_WORDS[1]}" in
            authorize|refresh|list-accounts|status|token|completion|daemon)
                subcommand="${COMP_WORDS[1]}"
                ;;
        esac
    fi

    if [[ "$subcommand" == "list-accounts" || "$subcommand" == "completion" || "$subcommand" == "daemon" ]]; then
        COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
        return 0
    fi

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
        return 0
    fi

    local accounts
    accounts=$(omt list-accounts 2>/dev/null)

    if [[ -z "$subcommand" && ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$commands $accounts" -- "$cur") )
        return 0
    fi

    COMPREPLY=( $(compgen -W "$accounts" -- "$cur") )
}
complete -F _omt_completion omt
`

// zshCompletionScript registers itself with compsys via "compdef" when
// sourced directly (requires "autoload -Uz compinit && compinit" to have
// already run, e.g. earlier in ~/.zshrc).
// Install with: source <(omt completion zsh)   # e.g. in ~/.zshrc
const zshCompletionScript = `#compdef omt
# zsh completion for omt - source <(omt completion zsh)

_omt() {
    local -a commands
    commands=(
        'authorize:re-run the interactive authorization flow for an account'
        'refresh:force a refresh-token exchange (all accounts if none given)'
        'list-accounts:print the configured account names'
        'status:show authorization status for all (or one) account'
        'token:print the stored access token for one account'
        'completion:print a shell completion script (bash or zsh)'
        'daemon:run in the foreground, periodically refreshing tokens due to expire'
    )

    local -a accounts
    accounts=(${(f)"$(omt list-accounts 2>/dev/null)"})

    if (( CURRENT == 2 )); then
        _describe -t commands 'omt command' commands
        _describe -t accounts 'account' accounts
        return
    fi

    case ${words[2]} in
        list-accounts|daemon)
            ;;
        completion)
            if (( CURRENT == 3 )); then
                compadd bash zsh
            fi
            ;;
        authorize|refresh|status|token)
            if (( CURRENT == 3 )); then
                _describe -t accounts 'account' accounts
            fi
            ;;
        *)
            # default "get" invocation: the first word is an account (or a flag).
            _describe -t accounts 'account' accounts
            ;;
    esac

    if [[ ${words[CURRENT]} == -* ]]; then
        _values 'flag' \
            '-h[show help]' \
            '-v[increase verbosity]' \
            '-d[enable debug output]' \
            '-a[force re-authorization]' \
            '--authflow[oauth2 flow]:flow:(authcode localhostauthcode devicecode)' \
            '-t[test endpoints]'
    fi
}

compdef _omt omt
`
