from google.cloud import webrisk_v1
from google.cloud.webrisk_v1 import Submission

def submit_uri(project_id: str, uri: str) -> Submission:
    webrisk_client = webrisk_v1.WebRiskServiceClient()

    # Set the URI to be submitted.
    submission = webrisk_v1.Submission()
    submission.uri = uri

    # Confidence that a URI is unsafe.
    threat_confidence = webrisk_v1.ThreatInfo.Confidence(
        level=webrisk_v1.ThreatInfo.Confidence.ConfidenceLevel.MEDIUM
    )

    # Context about why the URI is unsafe.
    threat_justification = webrisk_v1.ThreatInfo.ThreatJustification(
        # Labels that explain how the URI was classified.
        labels=[
            webrisk_v1.ThreatInfo.ThreatJustification.JustificationLabel.AUTOMATED_REPORT
        ],
        # Free-form context on why this URI is unsafe.
        comments=["Testing submission"],
    )

    # Set the context about the submission including the type of abuse found on the URI and
    # supporting details.
    threat_info = webrisk_v1.ThreatInfo(
        # The abuse type found on the URI.
        abuse_type=webrisk_v1.types.ThreatType.SOCIAL_ENGINEERING,
        threat_confidence=threat_confidence,
        threat_justification=threat_justification,
    )

    # Set the details about how the threat was discovered.
    threat_discovery = webrisk_v1.ThreatDiscovery(
        # Platform on which the threat was discovered.
        platform=webrisk_v1.ThreatDiscovery.Platform.MACOS,
        # CLDR region code of the countries/regions the URI poses a threat ordered
        # from most impact to least impact. Example: "US" for United States.
        region_codes=["US"],
    )

    request = webrisk_v1.SubmitUriRequest(
        parent=f"projects/{project_id}",
        submission=submission,
        threat_info=threat_info,
        threat_discovery=threat_discovery,
    )

    response = webrisk_client.submit_uri(request).result(timeout=30)
    return response
