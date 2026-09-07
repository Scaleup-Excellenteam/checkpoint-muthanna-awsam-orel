import copy
import unittest

from chat.config import CONFIG, validate_config


class ConfigurationTests(unittest.TestCase):
    def test_current_configuration_is_valid(self):
        self.assertIs(validate_config(copy.deepcopy(CONFIG)), copy.deepcopy(CONFIG))

    def test_invalid_dlp_configuration_has_a_clear_error(self):
        invalid = copy.deepcopy(CONFIG)
        invalid["dlp"]["monitored_words"].append(
            invalid["dlp"]["monitored_words"][0]
        )
        with self.assertRaisesRegex(ValueError, "cannot contain duplicates"):
            validate_config(invalid)

    def test_message_templates_require_their_placeholders(self):
        invalid = copy.deepcopy(CONFIG)
        invalid["dlp"]["public_block_message"] = "Account blocked."
        with self.assertRaisesRegex(ValueError, "must contain"):
            validate_config(invalid)

    def test_virustotal_key_is_not_stored_in_configuration(self):
        self.assertNotIn("VIRUSTOTAL_API_KEY", repr(CONFIG))


if __name__ == "__main__":
    unittest.main()
