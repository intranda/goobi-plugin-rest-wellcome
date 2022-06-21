package org.goobi.api.rest;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.Namespace;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.XMLOutputter;
import org.jdom2.xpath.XPath;

import ugh.dl.DocStruct;
import ugh.dl.Metadata;
import ugh.dl.MetadataType;
import ugh.dl.Person;
import ugh.dl.Prefs;
import ugh.exceptions.DocStructHasNoTypeException;
import ugh.exceptions.MetadataTypeNotAllowedException;

public class WellcomeUtils {

	private static final Logger logger = Logger.getLogger(WellcomeUtils.class);
	private static final Namespace NS_MODS = Namespace.getNamespace("mods", "http://www.loc.gov/mods/v3");

	public static List<String> getKeys(XMLConfiguration config) {
		List<String> keyList = new ArrayList<String>();
		int count = config.getMaxIndex("mapping");
		for (int i = 0; i <= count; i++) {
			String key = config.getString("mapping(" + i + ")[@field]");
			keyList.add(key);
		}
		return keyList;
	}

	public static String getValue(XMLConfiguration config, String inField) {
		int count = config.getMaxIndex("mapping");
		for (int i = 0; i <= count; i++) {
			String field = config.getString("mapping(" + i + ")[@field]");
			if (field.equals(inField)) {
				return config.getString("mapping(" + i + ")[@value]");
			}
		}
		return inField;
	}

	public static void writeXmlToFile(String folderName, String fileName, Document doc) {
		try {
			File folder = new File(folderName);
			if (!folder.exists()) {
				folder.mkdirs();
			}
			new XMLOutputter().output(doc, new FileOutputStream(folder.getAbsolutePath() + File.separator + fileName));
		} catch (FileNotFoundException e) {
			logger.error(e.getMessage());
		} catch (IOException e) {
			logger.error(e.getMessage());
		}
	}

	/**
	 * Returns the document's identifier, or a timestamp if the record has none
	 * 
	 * @param prefs
	 * @param ds
	 * @return
	 * @throws MetadataTypeNotAllowedException
	 * @throws DocStructHasNoTypeException
	 */
	public static String getIdentifier(Prefs prefs, DocStruct ds) throws MetadataTypeNotAllowedException, DocStructHasNoTypeException {
		String answer = getMetadataValue(prefs, ds, "CatalogIDDigital");
		if (answer==null){
			answer = String.valueOf(System.currentTimeMillis());
			addMetadataValue(prefs, ds, "CatalogIDDigital", answer);
		}
		return answer;
	}

	/**
	 * Returns the document's wellcome identifier
	 * 
	 * @param prefs
	 * @param ds
	 * @return
	 * @throws MetadataTypeNotAllowedException
	 * @throws DocStructHasNoTypeException
	 */
	public static String getWellcomeIdentifier(Prefs prefs, DocStruct ds) throws MetadataTypeNotAllowedException, DocStructHasNoTypeException {
		return getMetadataValue(prefs, ds, "wellcomeidentifier");
	}

	/**
	 * Returns the document's leader 6 value
	 * 
	 * @param prefs
	 * @param ds
	 * @return
	 * @throws MetadataTypeNotAllowedException
	 * @throws DocStructHasNoTypeException
	 */
	public static String getLeader6(Prefs prefs, DocStruct ds) throws MetadataTypeNotAllowedException, DocStructHasNoTypeException {
		return getMetadataValue(prefs, ds, "leader6");
	}

	/**
	 * Returns given value
	 * 
	 * @param prefs
	 * @param ds
	 * @return
	 * @throws MetadataTypeNotAllowedException
	 * @throws DocStructHasNoTypeException
	 */
	private static String getMetadataValue(Prefs prefs, DocStruct ds, String metadataType) throws MetadataTypeNotAllowedException,
			DocStructHasNoTypeException {
		String ret = null;
		MetadataType mdTypeId = prefs.getMetadataTypeByName(metadataType);
		if (ds.getAllMetadataByType(mdTypeId) != null && !ds.getAllMetadataByType(mdTypeId).isEmpty()) {
			Metadata mdId = ds.getAllMetadataByType(mdTypeId).get(0);
			ret = mdId.getValue();
		}
		return ret;
	}

	private static void addMetadataValue(Prefs prefs, DocStruct ds, String metadataType, String value) throws MetadataTypeNotAllowedException,
			DocStructHasNoTypeException {
		MetadataType mdTypeId = prefs.getMetadataTypeByName(metadataType);
		Metadata mdId = new Metadata(mdTypeId);
		ds.addMetadata(mdId);
		mdId.setValue(value);
	}

	/**
	 * Returns the document's title.
	 * 
	 * @param prefs
	 * @param ds
	 * @return
	 * @throws MetadataTypeNotAllowedException
	 * @throws DocStructHasNoTypeException
	 */
	public static String getTitle(Prefs prefs, DocStruct ds) throws MetadataTypeNotAllowedException, DocStructHasNoTypeException {
		return getMetadataValue(prefs, ds, "TitleDocMain");
	}

	/**
	 * Returns the document's author.
	 * 
	 * @param prefs
	 * @param ds
	 * @return
	 * @throws MetadataTypeNotAllowedException
	 * @throws DocStructHasNoTypeException
	 */
	public static String getAuthor(Prefs prefs, DocStruct ds) throws MetadataTypeNotAllowedException, DocStructHasNoTypeException {
		String ret = null;

		MetadataType mdTypePerson = prefs.getMetadataTypeByName("Author");
		if (ds.getAllPersonsByType(mdTypePerson) != null && !ds.getAllPersonsByType(mdTypePerson).isEmpty()) {
			Person personAuthor = ds.getAllPersonsByType(mdTypePerson).get(0);
			ret = personAuthor.getLastname();
			if (StringUtils.isNotEmpty(personAuthor.getFirstname())) {
				ret += ", " + personAuthor.getFirstname();
			}
		}

		return ret;
	}

	/**
	 * 
	 * @param pres
	 * @param dsLogical
	 * @param dsPhysical
	 * @param eleMods
	 * @param mappingFile
	 * @throws IOException
	 * @throws JDOMException
	 */
	@SuppressWarnings("unchecked")
	public static void parseModsSection(String mappingFileName, Prefs prefs, DocStruct dsLogical, DocStruct dsPhysical, Element eleMods)
			throws JDOMException, IOException {
		// logger.debug(new XMLOutputter().outputString(eleMods));
		Document doc = new Document();
		Element eleNewMods = (Element) eleMods.clone();
		doc.setRootElement(eleNewMods);
		File file = new File(mappingFileName);
		Document mapDoc = new SAXBuilder().build(file);
		for (Object obj : mapDoc.getRootElement().getChildren("metadata", null)) {
			Element eleMetadata = (Element) obj;
			String mdName = eleMetadata.getChildTextTrim("name", null);
			MetadataType mdType = prefs.getMetadataTypeByName(mdName);
			if (mdType != null) {
				try {
					List<Element> eleXpathList = eleMetadata.getChildren("xpath", null);
					if (mdType.getIsPerson()) {
						// Persons
						for (Element eleXpath : eleXpathList) {
							String query = eleXpath.getTextTrim();
							// logger.debug("XPath: " + query);
							XPath xpath = XPath.newInstance(query);
							xpath.addNamespace(NS_MODS);
							// Element eleValue = (Element) xpath.selectSingleNode(doc);
							List<?> eleValueList = xpath.selectNodes(doc);
							if (eleValueList != null) {
								for (Object ele : eleValueList) {
								    Element eleValue = (Element)ele;
									String name = "";
									String firstName = "";
									String lastName = "";

									if (eleXpath.getAttribute("family") != null) {
										lastName = eleValue.getTextTrim();
									} else if (eleXpath.getAttribute("given") != null) {
										firstName = eleValue.getTextTrim();
									} else {
										name = eleValue.getTextTrim();
									}

									if (name.contains(",")) {
										String[] nameSplit = name.split("[,]");
										if (nameSplit.length > 0 && StringUtils.isEmpty(lastName)) {
											lastName = nameSplit[0].trim();
										}
										if (nameSplit.length > 1 && StringUtils.isEmpty(firstName)) {
											firstName = nameSplit[1].trim();
										}
									} else {
										lastName = name;
									}

									if (StringUtils.isNotEmpty(lastName)) {
										Person person = new Person(mdType);
										person.setFirstname(firstName);
										person.setLastname(lastName);
										person.setRole(mdType.getName());
										if (eleMetadata.getAttribute("logical") != null
												&& eleMetadata.getAttributeValue("logical").equalsIgnoreCase("true")) {
											dsLogical.addPerson(person);
										}
									}
								}
							}
						}

					} else {
						// Regular metadata
						for (Element eleXpath : eleXpathList) {
							String query = eleXpath.getTextTrim();
							// logger.debug("XPath: " + query);
							XPath xpath = XPath.newInstance(query);
							xpath.addNamespace(NS_MODS);
							List<?> eleValueList = xpath.selectNodes(doc);
							if (eleValueList != null) {
							    for (Object ele : eleValueList) {
                                    Element eleValue = (Element)ele;
									List<String> values = new ArrayList<String>();
									// logger.debug("value: " + eleValue.getTextTrim());
									// System.out.println("value: " + eleValue.getTextTrim());

									values.add(eleValue.getTextTrim());

									String value = "";
									for (String s : values) {
										if (StringUtils.isNotEmpty(s)) {
											value += " " + s;
										}
									}
									value = value.trim();

									if (value.length() > 0) {
										Metadata metadata = new Metadata(mdType);
										metadata.setValue(value);
										if (eleMetadata.getAttribute("logical") != null
												&& eleMetadata.getAttributeValue("logical").equalsIgnoreCase("true")) {
											dsLogical.addMetadata(metadata);
										}
										if (eleMetadata.getAttribute("physical") != null
												&& eleMetadata.getAttributeValue("physical").equalsIgnoreCase("true")) {
											dsPhysical.addMetadata(metadata);
										}
									}
								}
							}
						}

					}
				} catch (MetadataTypeNotAllowedException e) {
					logger.warn(e.getMessage());
				}
			} else {
				logger.warn("Metadata '" + mdName + "' is not defined in the ruleset.");
			}
		}
	}
	
	
	public static void parseModsSectionForMultivolumes(String mappingFileName, Prefs prefs, DocStruct rootElement, DocStruct firstChild, DocStruct dsPhysical, Element eleMods)
			throws JDOMException, IOException {
		// logger.debug(new XMLOutputter().outputString(eleMods));
		Document doc = new Document();
		Element eleNewMods = (Element) eleMods.clone();
		doc.setRootElement(eleNewMods);
		File file = new File(mappingFileName);
		Document mapDoc = new SAXBuilder().build(file);
		for (Object obj : mapDoc.getRootElement().getChildren("metadata", null)) {
			Element eleMetadata = (Element) obj;
			String mdName = eleMetadata.getChildTextTrim("name", null);
			MetadataType mdType = prefs.getMetadataTypeByName(mdName);
			if (mdType != null) {
				try {
					@SuppressWarnings("unchecked")
                    List<Element> eleXpathList = eleMetadata.getChildren("xpath", null);
					if (mdType.getIsPerson()) {
						// Persons
						for (Element eleXpath : eleXpathList) {
							String query = eleXpath.getTextTrim();
							// logger.debug("XPath: " + query);
							XPath xpath = XPath.newInstance(query);
							xpath.addNamespace(NS_MODS);
							// Element eleValue = (Element) xpath.selectSingleNode(doc);
							@SuppressWarnings("unchecked")
                            List<?> eleValueList = xpath.selectNodes(doc);
							if (eleValueList != null) {
							    for (Object ele : eleValueList) {
                                    Element eleValue = (Element)ele;
									String name = "";
									String firstName = "";
									String lastName = "";

									if (eleXpath.getAttribute("family") != null) {
										lastName = eleValue.getTextTrim();
									} else if (eleXpath.getAttribute("given") != null) {
										firstName = eleValue.getTextTrim();
									} else {
										name = eleValue.getTextTrim();
									}

									if (name.contains(",")) {
										String[] nameSplit = name.split("[,]");
										if (nameSplit.length > 0 && StringUtils.isEmpty(lastName)) {
											lastName = nameSplit[0].trim();
										}
										if (nameSplit.length > 1 && StringUtils.isEmpty(firstName)) {
											firstName = nameSplit[1].trim();
										}
									} else {
										lastName = name;
									}

									if (StringUtils.isNotEmpty(lastName)) {
										Person person = new Person(mdType);
										person.setFirstname(firstName);
										person.setLastname(lastName);
										person.setRole(mdType.getName());
										if (eleMetadata.getAttribute("logical") != null
												&& eleMetadata.getAttributeValue("logical").equalsIgnoreCase("true")) {
											if (eleMetadata.getAttribute("depth") != null && eleMetadata.getAttributeValue("depth").equals("child")) {
												firstChild.addPerson(person);
											} else {
												rootElement.addPerson(person);												
											}
										}
									}
								}
							}
						}

					} else {
						// Regular metadata
						for (Element eleXpath : eleXpathList) {
							String query = eleXpath.getTextTrim();
							// logger.debug("XPath: " + query);
							XPath xpath = XPath.newInstance(query);
							xpath.addNamespace(NS_MODS);
							@SuppressWarnings("unchecked")
                            List<?> eleValueList = xpath.selectNodes(doc);
							if (eleValueList != null) {
							    for (Object ele : eleValueList) {
                                    Element eleValue = (Element)ele;
									List<String> values = new ArrayList<String>();
									// logger.debug("value: " + eleValue.getTextTrim());
									// System.out.println("value: " + eleValue.getTextTrim());

									values.add(eleValue.getTextTrim());

									String value = "";
									for (String s : values) {
										if (StringUtils.isNotEmpty(s)) {
											value += " " + s;
										}
									}
									value = value.trim();

									if (value.length() > 0) {
										Metadata metadata = new Metadata(mdType);
										metadata.setValue(value);
										if (eleMetadata.getAttribute("logical") != null
												&& eleMetadata.getAttributeValue("logical").equalsIgnoreCase("true")) {
											if (eleMetadata.getAttribute("depth") != null && eleMetadata.getAttributeValue("depth").equals("child")) {
												firstChild.addMetadata(metadata);
											} else {
												rootElement.addMetadata(metadata);
											}
										}
										if (eleMetadata.getAttribute("physical") != null
												&& eleMetadata.getAttributeValue("physical").equalsIgnoreCase("true")) {
											dsPhysical.addMetadata(metadata);
										}
									}
								}
							}
						}

					}
				} catch (MetadataTypeNotAllowedException e) {
					logger.warn(e.getMessage());
				}
			} else {
				logger.warn("Metadata '" + mdName + "' is not defined in the ruleset.");
			}
		}
	}

	public static void main(String[] args) {
		// WellcomeCalmImport wic = new WellcomeCalmImport();
		// List<String> keyList = WellcomeUtils.getKeys(ConfigPlugins.getPluginConfig(wic));
		// for (String key : keyList) {
		// System.out.println(key + ": " + WellcomeUtils.getValue(ConfigPlugins.getPluginConfig(wic), key));
		// }

	}

    public static String getAIDownloadIdentifier(Prefs prefs, DocStruct ds) throws MetadataTypeNotAllowedException, DocStructHasNoTypeException {
        return getMetadataValue(prefs, ds, "IADownloadIdentifier");
    }
	
}
