_kls_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    opts="-h -v -q -a -r -d -l --help --version --no-color --quiet --verbose --all --recursive --depth --filter --modified-before --modified-after --dirs-only --file-only --ext --sort --reverse --dirs-first --long --no-header --stats --health --no-health --only-alerts --attack-surface --alerts-first --security-report --immutable --setuid-tree --timeline --min-severity --only-anomalies"

    case "${prev}" in
        --sort)
            COMPREPLY=( $(compgen -W "name size type modified ext extension severity" -- "${cur}") )
            return 0
            ;;
        --min-severity)
            COMPREPLY=( $(compgen -W "info medium high" -- "${cur}") )
            return 0
            ;;
        --depth)
            # Expects a number
            return 0
            ;;
        --modified-before|--modified-after)
            # Expects a date YYYY-MM-DD
            return 0
            ;;
        --ext|--filter)
            return 0
            ;;
    esac

    if [[ ${cur} == -* ]] ; then
        COMPREPLY=( $(compgen -W "low medlow med high crit" -- "${cur}") )
        return 0
    fi

    # Default file/directory completion
    COMPREPLY=( $(compgen -f -- "${cur}") )
}
complete -F _kls_completions kls
