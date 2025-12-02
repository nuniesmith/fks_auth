-- Initialize fks_auth database
-- This script runs automatically when the database container is first created

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create schema for auth data
CREATE SCHEMA IF NOT EXISTS auth;

-- Note: fks_auth (Rust) will create tables via migrations or application code
-- This script is for any pre-migration setup

-- Set default privileges
ALTER DEFAULT PRIVILEGES IN SCHEMA auth GRANT ALL ON TABLES TO fks_auth_user;

-- Log initialization
DO $$
BEGIN
    RAISE NOTICE 'fks_auth database initialized successfully';
END $$;
