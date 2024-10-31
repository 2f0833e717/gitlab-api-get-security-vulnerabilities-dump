$!/bin/bash

DOMAIN="gitlab.xxxx.com"

PROJECT_PATH_WITH_NAMESPACE_LIST=(
  xxxx/projectA
  xxxx/projectB
  xxxx/projectC
)

REST_ROOT="https://${DOMAIN}/api/v4"
GRAPHQL_ROOT="https://${DOMAIN}/api/graphql"

USER=$(awk '$1=="machine"&&$2=="'"${DOMAIN}"'"{getline;print $2}' "${HOME}/.netrc")
PSWD=$(awk '$1=="machine"&&$2=="'"${DOMAIN}"'"{getline;getline;print $2}' "${HOME}/.netrc")

function CURL(){
  curl --header "Authorization: Bearer ${PSWD}" -sSL "${@}"
}

function RESTJQ(){
  CURL "${REST_ROOT}/${1}" | jq -r "${2-.}"
}

function GRAPHQL(){
  CURL \
    -X POST \
    -H "Content-Type: application/json" \
    -d "${1}" \
    "${GRAPHQL_ROOT}"
}

QUERY='
query {
  project(fullPath: "__PROJECT_PATH_WITH_NAMESPACE__") {
    id
    name
    vulnerabilities__VULNERABILITIES_PARAM__{
      pageInfo {
        endCursor
        hasNextPage
      }
      nodes{
        id
        reportType
        title
        severity
        datectedAt
        updatedAt
        vulnerabilityPath
        description
        falsePositive
        state
        hasSolutions
        scanner{
          reportType
          externalId
          name
          vendor
        }
        identifiers{
          externalId
          externalType
          name
          url
        }
        project{
          id
          name
          fullPath
        }
        links{
          name
          url
        }
        location{
          ... on
          VulnerabilityLocationSecretDetection{
            file
            startLine
            endLine
            vulnerableClass
            vulnerableMethod
            blobPath
          }
          ... on
          VulnerabilityLocationSast{
            file
            startLine
            endLine
            vulnerableClass
            vulnerableMethod
            blobPath
          }
          ... on
          VulnerabilityLocationDependencyScanning{
            file
            dependency{
              package{
                name
              }
              version
            }
            blobPath
          }
        }
        details{
          ... on
          VulnerabilityDetailCode{
            description
            fieldName
            lang
            name
            value
          }
        }
      }
    }
  }
}
'
QUERY=$(perl -pe 's/^ +//;s/\n/\\n/;s/"/\\"/g' <<< "${QUERY}")

echo '"URL","Tool Genre","Tool Engine","Severity","State","HasSolution",HasResolution","Title","Project","File","BLOB","Start","End"'

GROUP_ID=$(RESTJQ "/groups" '.[]|selec(.full_path=="'"${GROUP_NAME}"'")|.id')
for PROJECT_PATH_WITH_NAMESPACE in "${PROJECT_PATH_WITH_NAMESPACE_LIST[@]}";do
  for HAS_RESOLUTION in "false" "true";do
    END_CURSOR=
    echo "${PROJECT_PATH_WITH_NAMESPACE}:${HAS_RESOLUTION}:start" 1>&2
    while :;do
      JSON_QUERY='{"query":"'"${QUERY}"'"}'
      JSON_QUERY="${JSON_QUERY/__PROJECT_PATH_WITH_NAMESPACE__/${PROJECT_PATH_WITH_NAMESPACE}}"
      if [ -n "${END_CURSOR}" -a "${END_CURSOR}" != "null" ];then
        JSON_QUERY="${JSON_QUERY/__VULNERABILITIES_PARAM__/(hasResolution: ${HAS_RESOLUTION}, after: \\\"${END_CURSOR}\\\")}"
      else
        JSON_QUERY="${JSON_QUERY/__VULNERABILITIES_PARAM__/(hasResolution: ${HAS_RESOLUTION})}"
      fi
      # echo "${JSON_QUERY}"
      VULS_JSON=$(GRAPHQL "${JSON_QUERY}")
      # echo "${VULS_JSON}"
      if [ "$(jq -r '.data.project.vulnerabilities.nodes[]|length' <<< "${VULS_JSON}")" == 0 ];then
        break;
      fi
      END_CURSOR=$(jq -r '.data.project.vulnerabilities.pageInfo.endCursor' <<< "${VULS_JSON}")
      HAS_NEXT_PAGE=$(jq -r '.data.project.vulnerabilities.pageInfo.hasNextPage' <<< "${VULS_JSON}")
      jq -r '.data.project.vulnerabilities.pageInfo.nodes[]|[.vulnerabilityPath,.reportType,.scanner.name,.severity,.state,.hasSolution,'"${HAS_RESOLUTION}"',.title,.project.fullPath,.location.file,.location.blobPath,.location.startLine,.location.endLine]|@csv' <<< "${VULS_JSON}"
      if [ "${HAS_NEXT_PAGE}" == "false" ];then
        break;
      fi
    done
    echo "${PROJECT_PATH_WITH_NAMESPACE}:${HAS_RESOLUTION}:end" 1>&2
  done
done
