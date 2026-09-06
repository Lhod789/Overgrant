import unittest

from overgrant.inputs import parse_consent_url, parse_scope_list, parse_slack_manifest

BOTH_SETS = """
{"oauth_config": {"scopes": {
    "bot": ["channels:join", "channels:history"],
    "user": ["channels:history"]
}}}
"""

BOT_ONLY = """
{"oauth_config": {"scopes": {"bot": ["files:read"]}}}
"""

MALFORMED = """
{"oauth_config": {"scopes": ["channels:join"]}}
"""

SLACK_URL = (
    "https://slack.com/oauth/v2/authorize?client_id=1"
    "&scope=channels:join,channels:history"
    "&user_scope=channels:history"
)

GOOGLE_URL = (
    "https://accounts.google.com/o/oauth2/v2/auth?client_id=1"
    "&scope=https://www.googleapis.com/auth/gmail.readonly"
    "%20https://www.googleapis.com/auth/drive.readonly"
)


class TestSlackManifest(unittest.TestCase):
    def test_both_grant_sets_are_parsed(self):
        self.assertEqual(
            parse_slack_manifest(BOTH_SETS),
            {
                "bot": ["channels:join", "channels:history"],
                "user": ["channels:history"],
            },
        )

    def test_absent_grant_set_is_omitted_not_empty(self):
        self.assertEqual(parse_slack_manifest(BOT_ONLY), {"bot": ["files:read"]})

    def test_malformed_scopes_value_raises(self):
        with self.assertRaises(ValueError):
            parse_slack_manifest(MALFORMED)


class TestConsentUrl(unittest.TestCase):
    def test_slack_comma_form_gives_bot_and_user(self):
        self.assertEqual(
            parse_consent_url(SLACK_URL),
            {
                "bot": ["channels:join", "channels:history"],
                "user": ["channels:history"],
            },
        )

    def test_google_space_form_gives_one_set_of_decoded_urls(self):
        self.assertEqual(
            parse_consent_url(GOOGLE_URL),
            {
                "granted": [
                    "https://www.googleapis.com/auth/gmail.readonly",
                    "https://www.googleapis.com/auth/drive.readonly",
                ]
            },
        )

    def test_trailing_delimiter_produces_no_empty_scope(self):
        parsed = parse_consent_url("https://slack.com/x?scope=files:read,")
        self.assertEqual(parsed, {"granted": ["files:read"]})


class TestScopeList(unittest.TestCase):
    def test_newline_separated(self):
        self.assertEqual(
            parse_scope_list("channels:join\nchannels:history\n"),
            {"granted": ["channels:join", "channels:history"]},
        )

    def test_comma_separated(self):
        self.assertEqual(
            parse_scope_list("channels:join, channels:history"),
            {"granted": ["channels:join", "channels:history"]},
        )


if __name__ == "__main__":
    unittest.main()
