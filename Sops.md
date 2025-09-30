creation_rules:
  - path_regex: .*secrets\.enc\.yaml$
    pgp: >-
      YOUR_PGP_FINGERPRINT,
      TEAM_MEMBER_1_FINGERPRINT,
      TEAM_MEMBER_2_FINGERPRINT
    encrypted_regex: "^(password|password_hash|user|username|secret|token)$"
