# Disable file completions by default for arguments that require specific values
complete -c kls -f

# Global / basic options
complete -c kls -s h -l help -d 'Display help message and exit'
complete -c kls -s v -l version -d 'Display version information and exit'
complete -c kls -l no-color -d 'Disable colored output'
complete -c kls -s q -l quiet -d 'Run in quiet mode'
complete -c kls -l verbose -d 'Enable verbose output'

# Collection & Filtering options
complete -c kls -s a -l all -d 'Include hidden files and directories'
complete -c kls -s r -l recursive -d 'Recursively list subdirectories'
complete -c kls -s d -l depth -r -d 'Limit recursion depth'
complete -c kls -l filter -r -d 'Only display files and directories matching glob PATTERN'
complete -c kls -l modified-before -r -d 'Only display entries modified before specified DATE (YYYY-MM-DD)'
complete -c kls -l modified-after -r -d 'Only display entries modified after specified DATE (YYYY-MM-DD)'
complete -c kls -l dirs-only -d 'Only show directories'
complete -c kls -l file-only -d 'Only show regular files'
complete -c kls -l ext -r -d 'Only display files with specific extensions (comma-separated)'

# Sorting options
complete -c kls -l sort -r -f -a "name size type modified ext extension severity" -d 'Sort the listing by criteria'
complete -c kls -l reverse -d 'Reverse the order of the sort'
complete -c kls -l dirs-first -d 'List directories before other files'

# Presentation options
complete -c kls -s l -l long -d 'Use a long listing format'
complete -c kls -l no-header -d 'Suppress column headers'
complete -c kls -l stats -d 'Display execution statistics'

# Security & Health options
complete -c kls -l health -d 'Enable security health analysis'
complete -c kls -l no-health -d 'Disable security health analysis'
complete -c kls -l only-alerts -d 'Only display filesystem entries with security alerts'
complete -c kls -l attack-surface -d 'Enable attack surface presentation'
complete -c kls -l alerts-first -d 'Sort listing with security alerts first'
complete -c kls -l security-report -d 'Generate detailed security report'
complete -c kls -l immutable -d 'Display files with immutable attribute'
complete -c kls -l setuid-tree -d 'Recursively scan SetUID/SetGID tree'
complete -c kls -l timeline -d 'Present file history or timeline'
complete -c kls -l min-severity -r -f -a "low medlow med high crit" -d 'Filter alerts to specified severity'
complete -c kls -l only-anomalies -d 'Only show anomalous filesystem entries'

# Enable file completion for positional arguments
complete -c kls -a '(__fish_complete_path)'
