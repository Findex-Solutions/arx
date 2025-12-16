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
        try (ResultSet tables = metaData.getTables(null, schema, table, new String[]{"TABLE", "VIEW"})) {
            return tables.next();
        }
    }

    /**
     * Quotes a SQL identifier to make it safe for use in queries.
     * Uses double quotes which is ANSI SQL standard.
     *
     * @param identifier The identifier to quote
     * @return The quoted identifier
     * @throws IllegalArgumentException if the identifier is invalid
     */
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
