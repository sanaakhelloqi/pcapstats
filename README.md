# pcapstats

## Install
`pip install pcapstats`

## CLI
### pcapstats stats
```
Usage: pcapstats stats [OPTIONS] [FILES]...

  Calculate statistics for one or more pcap files.

Options:
  -o, --output TEXT
  -p, --processes INTEGER  Maximum amount of concurrent processes.
  --help                   Show this message and exit.
```

### pcapstats compare
```
Usage: pcapstats compare [OPTIONS] ORIGINAL [TARGETS]...

  Calculate similarity metrics and statistics for one or more pcap file.

Options:
  -o, --output TEXT
  -v, --visualize
  -vo, --visualize-output TEXT
  -p, --processes INTEGER       Maximum amount of concurrent processes.
  --help                        Show this message and exit.
```

### pcapstats filter
```
Usage: pcapstats filter [OPTIONS] ORIGINAL [TARGETS]...

  Filter pcap files based on similarity metrics.

Options:
  -o, --output TEXT        File where filter output gets saved.
  -j, --json-file TEXT     JSON containing custom thresholds for the available
                           metrics.

  -p, --processes INTEGER  Maximum amount of concurrent processes.
  --help                   Show this message and exit.
```