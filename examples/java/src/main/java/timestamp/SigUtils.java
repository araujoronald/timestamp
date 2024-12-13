/*
 * Copyright 2017 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package timestamp;

import java.io.IOException;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

/**
 * Utility class for the signature / timestamp examples.
 * 
 * @author Tilman Hausherr
 */
public class SigUtils {

	private SigUtils() {
	}

	/**
	 * Get the access permissions granted for this document in the DocMDP transform
	 * parameters dictionary. Details are described in the table "Entries in the
	 * DocMDP transform parameters dictionary" in the PDF specification.
	 *
	 * @param doc document.
	 * @return the permission value. 0 means no DocMDP transform parameters
	 *         dictionary exists. Other return values are 1, 2 or 3. 2 is also
	 *         returned if the DocMDP transform parameters dictionary is found but
	 *         did not contain a /P entry, or if the value is outside the valid
	 *         range.
	 */
	public static int getMDPPermission(PDDocument doc) {
		COSDictionary permsDict = doc.getDocumentCatalog().getCOSObject().getCOSDictionary(COSName.PERMS);
		if (permsDict != null) {
			COSDictionary signatureDict = permsDict.getCOSDictionary(COSName.DOCMDP);
			if (signatureDict != null) {
				COSArray refArray = signatureDict.getCOSArray(COSName.REFERENCE);
				if (refArray != null) {
					for (int i = 0; i < refArray.size(); ++i) {
						COSBase base = refArray.getObject(i);
						if (base instanceof COSDictionary) {
							COSDictionary sigRefDict = (COSDictionary) base;
							if (COSName.DOCMDP.equals(sigRefDict.getDictionaryObject(COSName.TRANSFORM_METHOD))) {
								base = sigRefDict.getDictionaryObject(COSName.TRANSFORM_PARAMS);
								if (base instanceof COSDictionary) {
									COSDictionary transformDict = (COSDictionary) base;
									int accessPermissions = transformDict.getInt(COSName.P, 2);
									if (accessPermissions < 1 || accessPermissions > 3) {
										accessPermissions = 2;
									}
									return accessPermissions;
								}
							}
						}
					}
				}
			}
		}
		return 0;
	}

	/**
	 * Set the "modification detection and prevention" permissions granted for this
	 * document in the DocMDP transform parameters dictionary. Details are described
	 * in the table "Entries in the DocMDP transform parameters dictionary" in the
	 * PDF specification.
	 *
	 * @param doc               The document.
	 * @param signature         The signature object.
	 * @param accessPermissions The permission value (1, 2 or 3).
	 *
	 * @throws IOException if a signature exists.
	 */
	public static void setMDPPermission(PDDocument doc, PDSignature signature, int accessPermissions)
			throws IOException {
		for (PDSignature sig : doc.getSignatureDictionaries()) {
			// "Approval signatures shall follow the certification signature if one is
			// present"
			// thus we don't care about timestamp signatures
			if (COSName.DOC_TIME_STAMP.equals(sig.getCOSObject().getItem(COSName.TYPE))) {
				continue;
			}
			if (sig.getCOSObject().containsKey(COSName.CONTENTS)) {
				throw new IOException("DocMDP transform method not allowed if an approval signature exists");
			}
		}

		COSDictionary sigDict = signature.getCOSObject();

		// DocMDP specific stuff
		// all values in the signature dictionary shall be direct objects
		COSDictionary transformParameters = new COSDictionary();
		transformParameters.setItem(COSName.TYPE, COSName.TRANSFORM_PARAMS);
		transformParameters.setInt(COSName.P, accessPermissions);
		transformParameters.setName(COSName.V, "1.2");
		transformParameters.setNeedToBeUpdated(true);
		transformParameters.setDirect(true);

		COSDictionary referenceDict = new COSDictionary();
		referenceDict.setItem(COSName.TYPE, COSName.SIG_REF);
		referenceDict.setItem(COSName.TRANSFORM_METHOD, COSName.DOCMDP);
		referenceDict.setItem(COSName.DIGEST_METHOD, COSName.getPDFName("SHA1"));
		referenceDict.setItem(COSName.TRANSFORM_PARAMS, transformParameters);
		referenceDict.setNeedToBeUpdated(true);
		referenceDict.setDirect(true);

		COSArray referenceArray = new COSArray();
		referenceArray.add(referenceDict);
		sigDict.setItem(COSName.REFERENCE, referenceArray);
		referenceArray.setNeedToBeUpdated(true);
		referenceArray.setDirect(true);

		// Catalog
		COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
		COSDictionary permsDict = new COSDictionary();
		catalogDict.setItem(COSName.PERMS, permsDict);
		permsDict.setItem(COSName.DOCMDP, signature);
		catalogDict.setNeedToBeUpdated(true);
		permsDict.setNeedToBeUpdated(true);
	}
}