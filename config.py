"""Runtime-configurable institution reporting destinations."""
import os


REPORTING_CONTACTS = {
    "institution_name": os.environ.get("INSTITUTION_NAME", "[Your institution]"),
    "security_team": os.environ.get(
        "SECURITY_TEAM_CONTACT", "[Configure an official IT/security reporting channel]"
    ),
    "reporting_url": os.environ.get(
        "SECURITY_REPORTING_URL", "[Configure a trusted reporting URL]"
    ),
}
