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

import org.deidentifier.arx.gui.resources.Resources;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xml.sax.helpers.XMLReaderFactory;

import com.carrotsearch.hppc.CharArrayList;

/**
 * The default XML handler.
 *
 * @author Fabian Prasser
 * @author Florian Kohlmayer
 */
public abstract class XMLHandler extends DefaultHandler {

    /**
     * Creates a secure XMLReader with XXE (XML External Entity) protection enabled.
     * This method disables external entity processing to prevent XXE attacks.
     *
     * @return A secure XMLReader instance
     * @throws SAXException if the XMLReader cannot be created or configured
     */
    public static XMLReader createSecureXMLReader() throws SAXException {
        XMLReader xmlReader = XMLReaderFactory.createXMLReader();

        // Track if we successfully applied at least one critical protection
        boolean hasProtection = false;

        // Disable DTDs (doctypes) entirely - this is the most important protection
        try {
            xmlReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            hasProtection = true;
        } catch (SAXException e) {
            // Feature may not be supported by all parsers, try alternative protections
        }

        // Disable external general entities
        try {
            xmlReader.setFeature("http://xml.org/sax/features/external-general-entities", false);
            hasProtection = true;
        } catch (SAXException e) {
            // Feature may not be supported
        }

        // Disable external parameter entities
        try {
            xmlReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            hasProtection = true;
        } catch (SAXException e) {
            // Feature may not be supported
        }

        // Disable external DTDs
        try {
            xmlReader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            hasProtection = true;
        } catch (SAXException e) {
            // Feature may not be supported
        }

        // Ensure at least one protection was applied
        if (!hasProtection) {
            throw new SAXException("Unable to configure XMLReader with XXE protection. " +
                "No security features could be set on the parser.");
        }

        return xmlReader;
    }

    /**  The payload */
    public String payload;
    
    /** The arraylist */
    private CharArrayList sb = new CharArrayList();

    @Override
    public void characters(final char[] ch,
                           final int start,
                           final int length) throws SAXException {
        // Add to chararraylist
        sb.add(ch, start, length);
    }

    @Override
    public void endElement(final String uri,
                           final String localName,
                           final String qName) throws SAXException {
        payload =  new String(sb.buffer, 0, sb.size());
        if (!end(uri, localName, qName)) { throw new SAXException(Resources.getMessage("WorkerLoad.0") + localName); } //$NON-NLS-1$
    }

    @Override
    public void
            startElement(final String uri,
                         final String localName,
                         final String qName,
                         final Attributes attributes) throws SAXException {
        sb.clear();
        if (!start(uri, localName, qName, attributes)) { throw new SAXException(Resources.getMessage("WorkerLoad.1") + localName); } //$NON-NLS-1$
    }

    /**
     * 
     *
     * @param uri
     * @param localName
     * @param qName
     * @return
     * @throws SAXException
     */
    protected abstract boolean end(String uri,
                                   String localName,
                                   String qName) throws SAXException;

    /**
     * 
     *
     * @param uri
     * @param localName
     * @param qName
     * @param attributes
     * @return
     * @throws SAXException
     */
    protected abstract boolean
            start(String uri,
                  String localName,
                  String qName,
                  Attributes attributes) throws SAXException;
}
