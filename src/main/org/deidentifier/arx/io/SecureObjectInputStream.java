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

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * A secure ObjectInputStream that implements class whitelisting to prevent
 * deserialization attacks. Only classes from trusted packages are allowed
 * to be deserialized.
 *
 * This class provides protection against CWE-502 (Deserialization of Untrusted Data)
 * and related attacks such as gadget chain exploits.
 *
 * @author Fabian Prasser
 */
public class SecureObjectInputStream extends ObjectInputStream {

    /**
     * Whitelist of allowed package prefixes for deserialization.
     * Only classes from these packages will be allowed to deserialize.
     */
    private static final String[] ALLOWED_PACKAGE_PREFIXES = {
        "org.deidentifier.arx.",
        "de.linearbits.",          // ARX ecosystem libraries (newtonraphson, etc.)
        "org.eclipse.",            // SWT GUI components (Point, Rectangle, etc.)
        "java.lang.",
        "java.util.",
        "java.io.",
        "java.math.",
        "java.time."
    };

    /**
     * Allowed primitive array type descriptors.
     * These are single-character codes used in Java serialization for primitive arrays.
     */
    private static final Set<String> ALLOWED_PRIMITIVE_ARRAYS = new HashSet<String>(Arrays.asList(
        "[I",  // int[]
        "[D",  // double[]
        "[B",  // byte[]
        "[Z",  // boolean[]
        "[C",  // char[]
        "[S",  // short[]
        "[J",  // long[]
        "[F"   // float[]
    ));

    /**
     * Set of explicitly allowed classes that don't match package prefixes
     */
    private static final Set<String> ALLOWED_CLASSES = new HashSet<String>(Arrays.asList(
        "java.lang.String",
        "java.lang.Integer",
        "java.lang.Long",
        "java.lang.Double",
        "java.lang.Float",
        "java.lang.Boolean",
        "java.lang.Character",
        "java.lang.Byte",
        "java.lang.Short",
        "java.lang.Number",
        "java.lang.Enum",
        "java.util.HashMap",
        "java.util.ArrayList",
        "java.util.LinkedList",
        "java.util.HashSet",
        "java.util.TreeSet",
        "java.util.TreeMap",
        "java.util.LinkedHashMap",
        "java.util.LinkedHashSet",
        "java.util.Date",
        "java.util.Locale",
        "java.math.BigDecimal",
        "java.math.BigInteger"
    ));

    /**
     * Creates a new instance
     * @param in The input stream to read from
     * @throws IOException if an I/O error occurs
     */
    public SecureObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        String className = desc.getName();

        // Check if class is allowed
        if (!isClassAllowed(className)) {
            throw new InvalidClassException("Unauthorized deserialization attempt for class: " + className);
        }

        return super.resolveClass(desc);
    }

    /**
     * Checks if a class is allowed to be deserialized based on the whitelist.
     *
     * @param className The fully qualified class name
     * @return true if the class is allowed, false otherwise
     */
    protected boolean isClassAllowed(String className) {
        // Check explicit allowed classes
        if (ALLOWED_CLASSES.contains(className)) {
            return true;
        }

        // Handle array types
        if (className.startsWith("[")) {
            return isArrayTypeAllowed(className);
        }

        // Check package prefixes for regular classes
        for (String prefix : ALLOWED_PACKAGE_PREFIXES) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks if an array type is allowed to be deserialized.
     * Handles primitive arrays, object arrays, and multi-dimensional arrays.
     *
     * @param className The array type descriptor (e.g., "[I", "[Ljava.lang.String;", "[[D")
     * @return true if the array type is allowed, false otherwise
     */
    private boolean isArrayTypeAllowed(String className) {
        // Primitive arrays (e.g., "[I" for int[], "[D" for double[])
        if (ALLOWED_PRIMITIVE_ARRAYS.contains(className)) {
            return true;
        }

        // Multi-dimensional arrays - recursively check the component type
        if (className.startsWith("[[")) {
            return isArrayTypeAllowed(className.substring(1));
        }

        // Object arrays (e.g., "[Ljava.lang.String;" for String[])
        if (className.startsWith("[L") && className.endsWith(";")) {
            // Extract the element class name (between "[L" and ";")
            String elementClass = className.substring(2, className.length() - 1);
            // Recursively check if the element type is allowed
            return isClassAllowed(elementClass);
        }

        return false;
    }
}
