IF schema_id('OAuth2Login') IS NULL
BEGIN
    EXECUTE('CREATE SCHEMA [OAuth2Login]');
END
GO
