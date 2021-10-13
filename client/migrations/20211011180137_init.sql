CREATE TABLE servers(
  -- the full api endpoint e.g. ``https://example.com/graphql``
  api_endpoint TEXT NOT NULL PRIMARY KEY,
  -- an user-defined name to easier identify a service
  nickname TEXT
)