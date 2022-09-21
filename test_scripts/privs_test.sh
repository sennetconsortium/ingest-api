#!/bin/bash
set -e
set -u

SCHEME_HOST_PORT=http://0.0.0.0:8484
BEARER_TOKEN=
VERBOSE=

usage()
{
  echo "Usage: $0 [-H SCHEME_HOST_PORT] [-t BEARER_TOKEN] [-v] [-h]"
  echo " -H Scheme, host, and port (default $SCHEME_HOST_PORT)"
  echo " -t BEARER_TOKEN (no default)"
  echo " -v Verbose"
  echo " -h Help"
  exit 2
}
# NOTE: To retrieve the token for the build_json_token:
# In Firefox open 'Tools > Browser Tools > Web Developer Tools'.
# Login through the UI
# HuBMAP: https://portal.hubmapconsortium.org/
# SenNet: https://portal.dev.sennetconsortium.org/
# In the Web Developer Tools, click on 'Network', and then one of the search endpoints.
# Copy the 'Request Header', 'Authoriation : Bearer' token.
#
# $ ./test_scripts/privs_test.sh -H https://ingest-api.dev.hubmapconsortium.org -t TOKEN

while getopts 'H:t:vh' arg; do
  case $arg in
    H) SCHEME_HOST_PORT=$OPTARG ;;
    t) BEARER_TOKEN=$OPTARG ;;
    v) VERBOSE='--verbose' ;;
    h|?) usage ;;
  esac
done

shift $((OPTIND-1))

if [ -z "$BEARER_TOKEN" ] ; then
  echo "Need to specify a BEARER_TOKEN"
  exit
fi

echo "Scheme, host, and port: ${SCHEME_HOST_PORT}"
echo "Bearer Token: ${BEARER_TOKEN}"
echo "NOTE: Bearer Token should be from SenNet: https://portal.dev.sennetconsortium.org/"
echo

echo "*** This call has no Bearer token and so should return a 401 and no data"
curl $VERBOSE -X GET -si "${SCHEME_HOST_PORT}/privs" \
 -H "Authorization: Bearer "
echo

echo "*** This call has a bearer token and so should return a json object for read_privs and write_privs"
curl $VERBOSE -X GET -si "${SCHEME_HOST_PORT}/privs" \
 -H "Authorization: Bearer $BEARER_TOKEN"
echo

GROUP_UUID='some_group_UUID'
echo
curl $VERBOSE -X GET -si "${SCHEME_HOST_PORT}/privs/${GROUP_UUID}/has-write" \
 -H "Authorization: Bearer $BEARER_TOKEN"
echo

curl $VERBOSE -X GET -si "${SCHEME_HOST_PORT}/privs/user-write-groups" \
 -H "Authorization: Bearer $BEARER_TOKEN"
echo
