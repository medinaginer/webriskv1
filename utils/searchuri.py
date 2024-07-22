from google.cloud import webrisk_v1
from google.cloud.webrisk_v1 import SearchUrisResponse, ThreatType
from typing import List, Optional

def search_uri_for_threats(uri: str) -> Optional[SearchUrisResponse]:
    """
    Checks whether a URI is associated with malware or social engineering threats.

    Args:
        uri (str): The URI to be checked for threats.
            Example: "http://testsafebrowsing.appspot.com/s/malware.html"

    Returns:
        Optional[SearchUrisResponse]: Contains threat types if the URI is present in any threatList.
                                      Returns None if an error occurs.
    """
    try:
        webrisk_client = webrisk_v1.WebRiskServiceClient()

        threat_types = [ThreatType.MALWARE, ThreatType.SOCIAL_ENGINEERING]
        
        request = webrisk_v1.SearchUrisRequest(
            uri=uri,
            threat_types=threat_types
        )

        response = webrisk_client.search_uris(request)
        
        return response
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def interpret_response(response: Optional[SearchUrisResponse], uri: str) -> None:
    """
    Interprets and prints the threat response for a given URI.

    Args:
        response (Optional[SearchUrisResponse]): The response from the Web Risk API.
        uri (str): The URI that was checked.
    """
    if response is None:
        print(f"Failed to get a response from the Web Risk API for {uri}")
    elif response.threat.threat_types:
        print(f"Threats detected for {uri}:")
        for threat in response.threat.threat_types:
            print(f"- {ThreatType(threat).name}")
    else:
        print(f"No threats detected. The URL {uri} appears to be safe.")

def main():
    urls_to_check = [
        "https://testsafebrowsing.appspot.com/s/malware.html",
        "https://testsafebrowsing.appspot.com/s/phishing.html",
        "https://www.google.com"
    ]

    for url in urls_to_check:
        print(f"\nChecking URL: {url}")
        response = search_uri_for_threats(url)
        interpret_response(response, url)

if __name__ == "__main__":
    main()