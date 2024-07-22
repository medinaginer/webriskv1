# [START webrisk_search_uri]

from google.cloud import webrisk_v1
from google.cloud.webrisk_v1 import SearchUrisResponse,ThreatType


def search_uri(
    uri: str, threat_type: webrisk_v1.ThreatType.SOCIAL_ENGINEERING
) -> SearchUrisResponse:
    """Checks whether a URI is on a given threatList.

    Multiple threatLists may be searched in a single query. The response will list all
    requested threatLists the URI was found to match. If the URI is not
    found on any of the requested ThreatList an empty response will be returned.

    Args:
        uri: The URI to be checked for matches
            Example: "http://testsafebrowsing.appspot.com/s/malware.html"
        threat_type: The ThreatLists to search in. Multiple ThreatLists may be specified.
            Example: threat_type = webrisk_v1.ThreatType.MALWARE

    Returns:
        SearchUrisResponse that contains a threat_type if the URI is present in the threatList.
    """
    webrisk_client = webrisk_v1.WebRiskServiceClient()

    request = webrisk_v1.SearchUrisRequest()
    request.threat_types = [threat_type]
    request.uri = uri

    response = webrisk_client.search_uris(request)
    if response.threat.threat_types:
        print(f"The URI has the following threat: {response}")
    else:
        print("The URL is safe!")
    return response


# [END webrisk_search_uri]

search_uri("http://testsafebrowsing.appspot.com/s/malware.html",  webrisk_v1.ThreatType.SOCIAL_ENGINEERING)