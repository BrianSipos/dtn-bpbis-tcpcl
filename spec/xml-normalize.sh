#!/bin/sh
set -e

USAGE="Usage: $0 [filename]"
if [ "$#" -eq "1" ]; then
    FILEPATH=$1
    shift 1
else
    echo "$USAGE"
    exit 1
fi

XSLTPROC="xsltproc --nonet --nowrite"
XMLLINT="xmllint --nonet --nowarning"
XMLLINT_CANON="${XMLLINT} --c14n"
XMLLINT_NORM="${XMLLINT} --format --encode UTF-8"
SELFDIR=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))

# Normalize a single XML file
# Arguments:
#  1: The file path to normalize
#
function normalize {
    FILEPATH=$1
    shift

    if [ ! -f "${FILEPATH}" ]; then
        echo "File is missing: ${FILEPATH}"
        exit 1
    fi

    # Canonicalize and normalize XML into ".out" file
    EXT="${FILEPATH##*.}"
    if [ "${EXT}" == "xml" ]; then
        ${XMLLINT_CANON} "${FILEPATH}" | \
            ${XMLLINT_NORM} - >"${FILEPATH}.out"
    else
        echo "Cannot handle file with extension: ${EXT}"
        exit 1
    fi

    if ! diff -q "${FILEPATH}.out" "${FILEPATH}" >/dev/null; then
        mv "${FILEPATH}.out" "${FILEPATH}"
        echo "Normalized ${FILEPATH}"
    else
        rm "${FILEPATH}.out"
    fi
}

if [ ! -z "$FILEPATH" ]; then
    normalize "${FILEPATH}"
fi
