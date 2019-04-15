#!/bin/sh

set -e

CLInoMOREhack=' | grep ^'	# Choose if some of your units are configured config-system-console; set-output-more (FGT default)
#CLInoMOREhack=''		# Choose if ALL your units are configured "set output normal". This may reduce latency.

default_vdom="Prod"		# Will be tab-completed, first few letters are sufficient

#################################

host=""
vdom="$default_vdom"
interface="any"
userfilter=""
mode=6
count=0

usage() {
	echo "Usage: $0 [-n count] [-d vdom] [-i interface|any] host [filter]"
	exit $1
}

while getopts "hn:d:i:" opt; do
	case "$opt" in
		h)	usage 0 ;;
		n)	count="$OPTARG" ;;
		d)	vdom="$OPTARG" ;;
		i)	interface="$OPTARG" ;;
		*)	usage 1 ;;
	esac
done
shift `expr $OPTIND - 1`

case "$#" in
	2)	host="$1"; userfilter="$2" ;;
	1)	host="$1";;
	0)	echo "Missing mandatory argument: Host" >&2
		usage 1
		;;
	*)	echo "Too many arguments" >&2
		usage 1
		;;
esac

case "$host" in
	# Fortigate 1-HA cluster
	1a|fw1a)	hostIP=10.0.0.8  ;;
	1b|fw1b)	hostIP=10.0.0.9  ;;
	1|fw1)		hostIP=10.0.0.10 ;;
	# Fortigate 2
	2|fw2)		hostIP=10.1.0.10 ;;
	# Fortigate 3
	3|fw3)		hostIP=10.2.0.10 ;;
	*)	cat <<END
Unsupported host \"$host\", try one of:
	UNCONFIGURED, edit the script
	1	fw1	fw1a	fw1b
	2	fw2
	3	fw3
END
		exit 1 ;;
esac

fgcommand_vdom='
config vdom
edit '"$vdom"'	 '

fgcommand_sniff="$fgcommand_vdom"'
diag sniffer packet %s "%s" %s %s a'"$CLInoMOREhack"

if ! [ 0 -le "$count" ]; then
	echo "ERROR: count \"$count\" is not a number"
	exit 1
fi

# Prevent us from capturing OUR OWN ssh connection
sshfilter="(not (host $hostIP and port 22))"
if [ -n "$userfilter" ]; then
	filter="($userfilter) and ($sshfilter)"
else
	filter="$sshfilter"
fi

printf "$fgcommand_sniff" "$interface" "$filter" "$mode" "$count" | ssh "$hostIP" | sed 's/^[^#]\+ # *//' | fgsniffer-converter
