/*
 * ARX Data Anonymization Tool
 * Copyright 2012 - 2025 Fabian Prasser and contributors
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.deidentifier.arx.io;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.regex.Pattern;

/**
 * Utility for I/O
 * @author Fabian Prasser, Florian Kohlmayer
 */
public class IOUtil {

    /** Pattern for valid SQL identifiers (alphanumeric, underscore, and dot for schema.table) */
    private static final Pattern VALID_SQL_IDENTIFIER = Pattern.compile("^[a-zA-Z_][a-zA-Z0-9_]*(\\.[a-zA-Z_][a-zA-Z0-9_]*)?$");

    /**
     * Trims a given string. Can handle <code>null</code>.
     * @param input
     * @return
     */
    public static String trim(String input) {
        return input == null ? null : input.trim();
    }

    /**
     * Validates a SQL table name to prevent SQL injection.
     * Only allows alphanumeric characters, underscores, and dots (for schema.table format).
     *
     * @param tableName The table name to validate
     * @return true if the table name is valid, false otherwise
     */
    public static boolean isValidSqlIdentifier(String tableName) {
        if (tableName == null || tableName.isEmpty()) {
            return false;
        }
        return VALID_SQL_IDENTIFIER.matcher(tableName).matches();
    }

    /**
     * Validates a table name against the database metadata to ensure it exists.
     * This provides strong protection against SQL injection by verifying the table
     * exists in the database before constructing any query.
     *
     * @param connection The database connection
     * @param tableName The table name to validate (can include schema prefix like "schema.table")
     * @return true if the table exists and is valid, false otherwise
     * @throws SQLException if a database access error occurs
     */
    public static boolean validateTableExists(Connection connection, String tableName) throws SQLException {
        if (tableName == null || tableName.isEmpty()) {
            return false;
        }

        // First check pattern validity
        if (!isValidSqlIdentifier(tableName)) {
            return false;
        }

        // Parse schema and table name
        String schema = null;
        String table = tableName;
        if (tableName.contains(".")) {
            String[] parts = tableName.split("\\.", 2);
            schema = parts[0];
            table = parts[1];
        }

        // Check if table exists using database metadata
        DatabaseMetaData metaData = connection.getMetaData();

        // Normalize schema and table names according to database identifier case rules
        schema = normalizeIdentifierCase(metaData, schema);
        table = normalizeIdentifierCase(metaData, table);

        try (ResultSet tables = metaData.getTables(null, schema, table, new String[]{"TABLE", "VIEW"})) {
            return tables.next();
        }
    }

    /**
     * Normalizes an identifier according to the database's case handling rules.
     *
     * @param metaData The database metadata
     * @param identifier The identifier to normalize (may be null)
     * @return The normalized identifier, or null if input was null
     * @throws SQLException if a database access error occurs
     */
    private static String normalizeIdentifierCase(DatabaseMetaData metaData, String identifier) throws SQLException {
        if (identifier == null) {
            return null;
        }
        if (metaData.storesUpperCaseIdentifiers()) {
            return identifier.toUpperCase();
        } else if (metaData.storesLowerCaseIdentifiers()) {
            return identifier.toLowerCase();
        }
        // If mixed case, leave as is
        return identifier;
    }

    /**
     * Quotes a SQL identifier to make it safe for use in queries.
     * Uses the database-specific quote character when a connection is provided.
     *
     * @param connection The database connection (used to determine quote character)
     * @param identifier The identifier to quote
     * @return The quoted identifier
     * @throws IllegalArgumentException if the identifier is invalid
     * @throws SQLException if a database access error occurs
     */
    public static String quoteSqlIdentifier(Connection connection, String identifier) throws SQLException {
        if (!isValidSqlIdentifier(identifier)) {
            throw new IllegalArgumentException("Invalid SQL identifier: " + identifier);
        }

        // Get the database-specific quote string
        String quote = connection.getMetaData().getIdentifierQuoteString();
        if (quote == null || quote.trim().isEmpty() || " ".equals(quote)) {
            // Fallback to double quotes (ANSI SQL) if quote string is not provided
            quote = "\"";
        }

        // Handle schema.table format
        if (identifier.contains(".")) {
            String[] parts = identifier.split("\\.", 2);
            return quote + parts[0] + quote + "." + quote + parts[1] + quote;
        }

        return quote + identifier + quote;
    }

    /**
     * Quotes a SQL identifier to make it safe for use in queries.
     * Uses double quotes which is ANSI SQL standard.
     *
     * @deprecated Use {@link #quoteSqlIdentifier(Connection, String)} for database-specific quoting
     * @param identifier The identifier to quote
     * @return The quoted identifier
     * @throws IllegalArgumentException if the identifier is invalid
     */
    @Deprecated
    public static String quoteSqlIdentifier(String identifier) {
        if (!isValidSqlIdentifier(identifier)) {
            throw new IllegalArgumentException("Invalid SQL identifier: " + identifier);
        }

        // Handle schema.table format
        if (identifier.contains(".")) {
            String[] parts = identifier.split("\\.", 2);
            return "\"" + parts[0] + "\".\"" + parts[1] + "\"";
        }

        return "\"" + identifier + "\"";
    }
}
