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
package org.deidentifier.arx.gui.worker.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * This class handles compatibility issues with object deserialization
 * and provides security against deserialization attacks by whitelisting
 * allowed classes.
 *
 * @author Fabian Prasser
 */
public class BackwardsCompatibleObjectInputStream extends ObjectInputStream {

    /**
     * Whitelist of allowed package prefixes for deserialization.
     * Only classes from these packages will be allowed to deserialize.
     */
    private static final String[] ALLOWED_PACKAGE_PREFIXES = {
        "org.deidentifier.arx.",
        "java.lang.",
        "java.util.",
        "java.io.",
        "java.math.",
        "java.time.",
        "[L",  // Array types
        "[I",  // int arrays
        "[D",  // double arrays
        "[B",  // byte arrays
        "[Z",  // boolean arrays
        "[C",  // char arrays
        "[S",  // short arrays
        "[J",  // long arrays
        "[F"   // float arrays
    };

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
     * @param in
     * @throws IOException
     */
    public BackwardsCompatibleObjectInputStream(InputStream in) throws IOException {
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

    @Override
    protected ObjectStreamClass readClassDescriptor() throws IOException, ClassNotFoundException {

        // Read from stream
        ObjectStreamClass result = super.readClassDescriptor();

        // Handle movement of ARXLogisticRegressionConfiguration
        if (result.getName().equals("org.deidentifier.arx.ARXLogisticRegressionConfiguration")) {
            result = ObjectStreamClass.lookup(org.deidentifier.arx.aggregates.ClassificationConfigurationLogisticRegression.class);

        // Handle movement of ARXLogisticRegressionConfiguration$PriorFunction
        } else if (result.getName().equals("org.deidentifier.arx.ARXLogisticRegressionConfiguration$PriorFunction")) {
            result = ObjectStreamClass.lookup(org.deidentifier.arx.aggregates.ClassificationConfigurationLogisticRegression.PriorFunction.class);
        }

        // Return potentially mapped descriptor
        return result;
    }

    /**
     * Checks if a class is allowed to be deserialized based on the whitelist.
     *
     * @param className The fully qualified class name
     * @return true if the class is allowed, false otherwise
     */
    private boolean isClassAllowed(String className) {
        // Check explicit allowed classes
        if (ALLOWED_CLASSES.contains(className)) {
            return true;
        }

        // Check package prefixes
        for (String prefix : ALLOWED_PACKAGE_PREFIXES) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }

        return false;
    }
}
