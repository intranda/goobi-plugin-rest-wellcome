package org.goobi.api.rest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.SystemUtils;
import org.goobi.api.rest.model.ArchiveCallbackRequest;
import org.goobi.api.rest.response.WellcomeCreationResponse;
import org.goobi.beans.Process;
import org.goobi.beans.Processproperty;
import org.goobi.beans.Step;
import org.goobi.managedbeans.LoginBean;
import org.goobi.production.flow.jobs.HistoryAnalyserJob;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.Namespace;
import org.jdom2.input.SAXBuilder;
import org.jdom2.transform.XSLTransformer;

import de.sub.goobi.config.ConfigurationHelper;
import de.sub.goobi.helper.BeanHelper;
import de.sub.goobi.helper.Helper;
import de.sub.goobi.helper.ScriptThreadWithoutHibernate;
import de.sub.goobi.helper.enums.PropertyType;
import de.sub.goobi.helper.enums.StepEditType;
import de.sub.goobi.helper.enums.StepStatus;
import de.sub.goobi.helper.exceptions.DAOException;
import de.sub.goobi.helper.exceptions.SwapException;
import de.sub.goobi.persistence.managers.ProcessManager;
import de.sub.goobi.persistence.managers.PropertyManager;
import de.sub.goobi.persistence.managers.StepManager;
import lombok.extern.log4j.Log4j;
import ugh.dl.DigitalDocument;
import ugh.dl.DocStruct;
import ugh.dl.Fileformat;
import ugh.dl.Metadata;
import ugh.dl.MetadataType;
import ugh.dl.Prefs;
import ugh.exceptions.DocStructHasNoTypeException;
import ugh.exceptions.MetadataTypeNotAllowedException;
import ugh.exceptions.PreferencesException;
import ugh.exceptions.TypeNotAllowedAsChildException;
import ugh.exceptions.TypeNotAllowedForParentException;
import ugh.fileformats.mets.MetsMods;

@Path("/wellcome")
@Log4j
public class WellcomeEndpoints {

    private static final String XSLT = ConfigurationHelper.getInstance().getXsltFolder() + "MARC21slim2MODS3.xsl";
    private static final String MODS_MAPPING_FILE = ConfigurationHelper.getInstance().getXsltFolder() + "mods_map.xml";
    private static final Namespace MARC = Namespace.getNamespace("marc", "http://www.loc.gov/MARC21/slim");

    private Map<String, String> map = new HashMap<String, String>();

    private String currentIdentifier;
    private String currentWellcomeIdentifier;

    public WellcomeEndpoints() {
        map.put("?Monographic", "Monograph");
        map.put("?continuing", "Periodical"); // not mapped
        map.put("?Notated music", "Monograph");
        map.put("?Manuscript notated music", "Monograph");
        map.put("?Cartographic material", "SingleMap");
        map.put("?Manuscript cartographic material", "SingleMap");
        map.put("?Projected medium", "Video");
        map.put("?Nonmusical sound recording", "Audio");
        map.put("?Musical sound recording", "Audio");
        map.put("?Two-dimensional nonprojectable graphic", "Artwork");
        map.put("?Computer file", "Monograph");
        map.put("?Kit", "Monograph");
        map.put("?Mixed materials", "Monograph");
        map.put("?Three-dimensional artefact or naturally occurring object", "3DObject");
        map.put("?Manuscript language material", "Archive");
        map.put("?BoundManuscript", "BoundManuscript");
    }

    @Path("/steps/{stepid}/archivecallback")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response archiveCallback(@PathParam("stepid") int stepId, ArchiveCallbackRequest acr) {
        if ("completed-callback-succeeded".equals(acr.getStatus().get("id"))) {
            Step so = StepManager.getStepById(stepId);
            if (so == null) {
                return Response.status(404).entity("step not found").build();
            } else {
                so.setBearbeitungsstatusEnum(StepStatus.DONE);
                try {
                    StepManager.saveStep(so);
                } catch (DAOException e) {
                    log.error(e);
                    return Response.status(500).build();
                }
                return Response.noContent().build();
            }
        }
        return Response.noContent().build();
    }

    @Path("/create")
    @POST
    @Produces("text/xml")
    public Response createNewProcess(@HeaderParam("templateid") int templateId, @HeaderParam("marcfile") String marcfile,
            @HeaderParam("collection") String collectionName) {

        if (StringUtils.isBlank(marcfile)) {
            Response resp = Response.status(Response.Status.BAD_REQUEST).entity(createErrorResponse("Parameter marc file is missing or empty."))
                    .build();
            return resp;
        }
        java.nio.file.Path path = Paths.get(marcfile);
        if (!Files.exists(path)) {
            Response resp = Response.status(Response.Status.BAD_REQUEST).entity(createErrorResponse("Marc file does not exist: " + marcfile)).build();
            return resp;
        }

        String filename = path.getFileName().toString();
        // remove ending _marc.xml and _mrc.xml
        filename = filename.replaceAll("_(marc|mrc)\\.xml", "");
        currentIdentifier = filename;

        if (ProcessManager.countProcesses("titel LIKE '%" + filename + "\\_%'") > 0) {
            // file already exists            
            Response resp = Response.status(Response.Status.EXPECTATION_FAILED).entity(createErrorResponse("Process with b-number " + filename
                    + " already exists, as MMO.")).build();
            return resp;

        }

        if (ProcessManager.countProcesses("titel LIKE '%" + filename + "%'") > 0) {
            // file already exists            
            Response resp = Response.status(Response.Status.CONFLICT).entity(createErrorResponse("Process with b-number " + filename
                    + " already exists, you should remove it.")).build();
            return resp;

        }
        String order = null;
        String anchorId = null;
        if (filename.matches("\\w+_\\d{4}")) {
            // multivolume
            anchorId = filename.split("_")[0];
            order = filename.split("_")[1];
            if (ProcessManager.countProcesses("titel LIKE '%" + anchorId + "'") > 0) {
                Response resp = Response.status(Response.Status.EXPECTATION_FAILED).entity(createErrorResponse("b-number " + anchorId
                        + " already exists, you should move it to suspicious folder.")).build();
                return resp;
            }
        }

        Process template = ProcessManager.getProcessById(templateId);
        if (template == null) {
            Response resp = Response.status(Response.Status.BAD_REQUEST).entity(createErrorResponse("Cannot find process template with id "
                    + templateId)).build();
            return resp;
        }

        Prefs prefs = template.getRegelsatz().getPreferences();

        SAXBuilder builder = new SAXBuilder();
        Document doc = null;
        try {
            doc = builder.build(marcfile);
        } catch (JDOMException | IOException e) {
            log.error(e);
            Response resp = Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(createErrorResponse("Cannot read marc record " + marcfile))
                    .build();
            return resp;
        }
        Fileformat ff = null;
        if (order == null) {
            ff = convertData(doc, prefs, collectionName);
        } else {
            ff = convertMMO(doc, prefs, collectionName, order, anchorId, filename);
        }
        if (ff == null) {
            Response resp = Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(createErrorResponse("Cannot convert marc record "
                    + marcfile)).build();
            return resp;

        }

        Process process = cloneTemplate(template);
        // set title
        process.setTitel(getProcessTitle());

        try {
            NeuenProzessAnlegen(process, template, ff, prefs);

            saveProperty(process, "b-number", currentIdentifier);
            saveProperty(process, "CollectionName1", "Digitised");
            saveProperty(process, "CollectionName2", collectionName);
            saveProperty(process, "securityTag", "open");
            saveProperty(process, "schemaName", "Millennium");

        } catch (Exception e) {
            log.error(e);
            Response resp = Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(createErrorResponse("Cannot create process with title "
                    + getProcessTitle())).build();
            return resp;
        }
        try {
            String destination = process.getImportDirectory();
            WellcomeUtils.writeXmlToFile(destination, getProcessTitle() + "_mrc.xml", doc);
        } catch (SwapException | DAOException | IOException | InterruptedException e) {
            log.error(e);
            Response resp = Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(createErrorResponse("Cannot save import file.")).build();
            return resp;
        }

        WellcomeCreationResponse resp = new WellcomeCreationResponse();
        resp.setProcessId(process.getId());
        resp.setProcessName(getProcessTitle());
        resp.setResult("success");
        return Response.status(Response.Status.OK).entity(resp).build();
    }

    private Fileformat convertMMO(Document doc, Prefs prefs, String collectionName, String order, String anchorIdentifier, String volumeIdentifier) {

        Fileformat ff = null;
        try {
            Element root = doc.getRootElement();
            Element record = null;
            if (root.getName().equalsIgnoreCase("record")) {
                record = root;
            } else {
                record = doc.getRootElement().getChild("record", MARC);
            }
            List<Element> controlfields = record.getChildren("controlfield", MARC);
            List<Element> datafields = record.getChildren("datafield", MARC);
            String value907a = "";

            for (Element e907 : datafields) {
                if (e907.getAttributeValue("tag").equals("907")) {
                    List<Element> subfields = e907.getChildren("subfield", MARC);
                    for (Element subfield : subfields) {
                        if (subfield.getAttributeValue("code").equals("a")) {
                            value907a = subfield.getText().replace(".", "");
                        }
                    }
                }
            }
            boolean control001 = false;
            for (Element e : controlfields) {
                if (e.getAttributeValue("tag").equals("001")) {
                    e.setText(value907a);
                    control001 = true;
                    break;
                }
            }
            if (!control001) {
                Element controlfield001 = new Element("controlfield", MARC);
                controlfield001.setAttribute("tag", "001");
                controlfield001.setText(value907a);
                record.addContent(controlfield001);
            }

            XSLTransformer transformer = new XSLTransformer(XSLT);

            Document docMods = transformer.transform(doc);

            ff = new MetsMods(prefs);
            DigitalDocument dd = new DigitalDocument();
            ff.setDigitalDocument(dd);

            Element eleMods = docMods.getRootElement();
            if (eleMods.getName().equals("modsCollection")) {
                eleMods = eleMods.getChild("mods", null);
            }

            // Determine the root docstruct type
            String dsType = "MultipleManifestation";
            String volumeStructType = "MonographManifestation";

            DocStruct dsRoot = dd.createDocStruct(prefs.getDocStrctTypeByName(dsType));
            dd.setLogicalDocStruct(dsRoot);

            DocStruct dsBoundBook = dd.createDocStruct(prefs.getDocStrctTypeByName("BoundBook"));
            dd.setPhysicalDocStruct(dsBoundBook);
            DocStruct dsVolume = dd.createDocStruct(prefs.getDocStrctTypeByName(volumeStructType));
            dsRoot.addChild(dsVolume);

            // Collect MODS metadata
            WellcomeUtils.parseModsSectionForMultivolumes(MODS_MAPPING_FILE, prefs, dsRoot, dsVolume, dsBoundBook, eleMods);

            Metadata volumeType = new Metadata(prefs.getMetadataTypeByName("_volume"));
            volumeType.setValue(order);

            // order zweistellig
            int orderNo = Integer.parseInt(order);
            if (orderNo < 10) {
                order = "0" + orderNo;
            } else {
                order = "" + orderNo;
            }
            // add publication year to order
            MetadataType yearType = prefs.getMetadataTypeByName("PublicationYear");
            if (dsRoot.getAllMetadataByType(yearType) != null && !dsRoot.getAllMetadataByType(yearType).isEmpty()) {
                Metadata md = dsRoot.getAllMetadataByType(yearType).get(0);
                if (md.getValue().matches("\\d\\d\\d\\d")) {
                    order = md.getValue() + order;
                }
            } else if (dsVolume.getAllMetadataByType(yearType) != null && !dsVolume.getAllMetadataByType(yearType).isEmpty()) {
                Metadata md = dsVolume.getAllMetadataByType(yearType).get(0);
                if (md.getValue().matches("\\d\\d\\d\\d")) {
                    order = md.getValue() + order;
                }
            }

            currentWellcomeIdentifier = WellcomeUtils.getWellcomeIdentifier(prefs, dsRoot);

            MetadataType mdt = prefs.getMetadataTypeByName("CatalogIDDigital");

            if (dsRoot.getAllMetadataByType(mdt) != null && !dsRoot.getAllMetadataByType(mdt).isEmpty()) {
                Metadata md = dsRoot.getAllMetadataByType(mdt).get(0);
                md.setValue(anchorIdentifier);
            } else {
                Metadata mdId = new Metadata(mdt);
                mdId.setValue(anchorIdentifier);
                dsRoot.addMetadata(mdId);
            }

            Metadata mdId = new Metadata(mdt);
            mdId.setValue(volumeIdentifier);
            dsVolume.addMetadata(mdId);
            Metadata currentNo = new Metadata(prefs.getMetadataTypeByName("CurrentNo"));
            currentNo.setValue(order);
            dsVolume.addMetadata(currentNo);
            Metadata CurrentNoSorting = new Metadata(prefs.getMetadataTypeByName("CurrentNoSorting"));
            CurrentNoSorting.setValue(order);
            dsVolume.addMetadata(CurrentNoSorting);

            Metadata manifestationType = new Metadata(prefs.getMetadataTypeByName("_ManifestationType"));

            manifestationType.setValue("General");

            dsVolume.addMetadata(volumeType);

            dsRoot.addMetadata(manifestationType);

            generateDefaultValues(prefs, collectionName, dsRoot, dsBoundBook);
        } catch (JDOMException | IOException | PreferencesException | TypeNotAllowedForParentException | MetadataTypeNotAllowedException
                | TypeNotAllowedAsChildException e) {
            log.error(e);
        }
        return ff;
    }

    private void generateDefaultValues(Prefs prefs, String collectionName, DocStruct dsRoot, DocStruct dsBoundBook)
            throws MetadataTypeNotAllowedException {

        // Add 'pathimagefiles'
        try {
            Metadata mdForPath = new Metadata(prefs.getMetadataTypeByName("pathimagefiles"));
            mdForPath.setValue("./" + currentIdentifier);
            dsBoundBook.addMetadata(mdForPath);
        } catch (MetadataTypeNotAllowedException e1) {
            log.error("MetadataTypeNotAllowedException while reading images", e1);
        } catch (DocStructHasNoTypeException e1) {
            log.error("DocStructHasNoTypeException while reading images", e1);
        }

        MetadataType mdTypeCollection = prefs.getMetadataTypeByName("singleDigCollection");

        Metadata mdCollection = new Metadata(mdTypeCollection);
        mdCollection.setValue(collectionName);
        dsRoot.addMetadata(mdCollection);

        Metadata dateDigitization = new Metadata(prefs.getMetadataTypeByName("_dateDigitization"));
        dateDigitization.setValue("2012");
        Metadata placeOfElectronicOrigin = new Metadata(prefs.getMetadataTypeByName("_placeOfElectronicOrigin"));
        placeOfElectronicOrigin.setValue("Wellcome Trust");
        Metadata _electronicEdition = new Metadata(prefs.getMetadataTypeByName("_electronicEdition"));
        _electronicEdition.setValue("[Electronic ed.]");
        Metadata _electronicPublisher = new Metadata(prefs.getMetadataTypeByName("_electronicPublisher"));
        _electronicPublisher.setValue("Wellcome Trust");
        Metadata _digitalOrigin = new Metadata(prefs.getMetadataTypeByName("_digitalOrigin"));
        _digitalOrigin.setValue("reformatted digital");
        if (dsRoot.getType().isAnchor()) {
            DocStruct ds = dsRoot.getAllChildren().get(0);
            ds.addMetadata(dateDigitization);
            ds.addMetadata(_electronicEdition);

        } else {
            dsRoot.addMetadata(dateDigitization);
            dsRoot.addMetadata(_electronicEdition);
        }
        dsRoot.addMetadata(placeOfElectronicOrigin);
        dsRoot.addMetadata(_electronicPublisher);
        dsRoot.addMetadata(_digitalOrigin);

        Metadata physicalLocation = new Metadata(prefs.getMetadataTypeByName("_digitalOrigin"));
        physicalLocation.setValue("Wellcome Trust");
        dsBoundBook.addMetadata(physicalLocation);
    }

    private Fileformat convertData(Document doc, Prefs prefs, String collectionName) {
        Fileformat ff = null;
        try {

            Element record = null;
            Element root = doc.getRootElement();
            if (root.getName().equals("record")) {
                record = root;
            } else {
                doc.getRootElement().getChild("record", MARC);
            }
            List<Element> controlfields = record.getChildren("controlfield", MARC);
            List<Element> datafields = record.getChildren("datafield", MARC);
            String value907a = "";

            for (Element e907 : datafields) {
                if (e907.getAttributeValue("tag").equals("907")) {
                    List<Element> subfields = e907.getChildren("subfield", MARC);
                    for (Element subfield : subfields) {
                        if (subfield.getAttributeValue("code").equals("a")) {
                            value907a = subfield.getText().replace(".", "");
                        }
                    }
                }
            }
            boolean control001 = false;
            for (Element e : controlfields) {
                if (e.getAttributeValue("tag").equals("001")) {
                    e.setText(value907a);
                    control001 = true;
                    break;
                }
            }
            if (!control001) {
                Element controlfield001 = new Element("controlfield", MARC);
                controlfield001.setAttribute("tag", "001");
                controlfield001.setText(value907a);
                record.addContent(controlfield001);
            }

            XSLTransformer transformer = new XSLTransformer(XSLT);

            Document docMods = transformer.transform(doc);
            ff = new MetsMods(prefs);
            DigitalDocument dd = new DigitalDocument();
            ff.setDigitalDocument(dd);

            Element eleMods = docMods.getRootElement();
            if (eleMods.getName().equals("modsCollection")) {
                eleMods = eleMods.getChild("mods", null);
            }

            // Determine the root docstruct type
            String dsType = "Monograph";
            if (eleMods.getChild("originInfo", null) != null) {
                Element eleIssuance = eleMods.getChild("originInfo", null).getChild("issuance", null);
                if (eleIssuance != null && map.get("?" + eleIssuance.getTextTrim()) != null) {
                    dsType = map.get("?" + eleIssuance.getTextTrim());
                }
            }
            Element eleTypeOfResource = eleMods.getChild("typeOfResource", null);
            if (eleTypeOfResource != null && map.get("?" + eleTypeOfResource.getTextTrim()) != null) {
                dsType = map.get("?" + eleTypeOfResource.getTextTrim());
            }

            DocStruct dsRoot = dd.createDocStruct(prefs.getDocStrctTypeByName(dsType));
            dd.setLogicalDocStruct(dsRoot);

            DocStruct dsBoundBook = dd.createDocStruct(prefs.getDocStrctTypeByName("BoundBook"));
            dd.setPhysicalDocStruct(dsBoundBook);

            // Collect MODS metadata
            WellcomeUtils.parseModsSection(MODS_MAPPING_FILE, prefs, dsRoot, dsBoundBook, eleMods);
            currentWellcomeIdentifier = WellcomeUtils.getWellcomeIdentifier(prefs, dsRoot);

            // Add dummy volume to anchors
            if (dsRoot.getType().getName().equals("Periodical") || dsRoot.getType().getName().equals("MultiVolumeWork")) {
                DocStruct dsVolume = null;
                if (dsRoot.getType().getName().equals("Periodical")) {
                    dsVolume = dd.createDocStruct(prefs.getDocStrctTypeByName("PeriodicalVolume"));
                } else if (dsRoot.getType().getName().equals("MultiVolumeWork")) {
                    dsVolume = dd.createDocStruct(prefs.getDocStrctTypeByName("Volume"));
                }
                dsRoot.addChild(dsVolume);
                Metadata mdId = new Metadata(prefs.getMetadataTypeByName("CatalogIDDigital"));
                mdId.setValue(currentIdentifier + "_0001");
                dsVolume.addMetadata(mdId);
            }
            generateDefaultValues(prefs, collectionName, dsRoot, dsBoundBook);

        } catch (JDOMException | IOException | PreferencesException | TypeNotAllowedForParentException | MetadataTypeNotAllowedException
                | TypeNotAllowedAsChildException e) {
            log.error(e);
        }
        return ff;
    }

    private WellcomeCreationResponse createErrorResponse(String errorText) {
        WellcomeCreationResponse resp = new WellcomeCreationResponse();
        resp.setResult("error");
        resp.setErrorText(errorText);
        return resp;
    }

    private Process cloneTemplate(Process template) {
        Process process = new Process();

        process.setIstTemplate(false);
        process.setInAuswahllisteAnzeigen(false);
        process.setProjekt(template.getProjekt());
        process.setRegelsatz(template.getRegelsatz());
        process.setDocket(template.getDocket());

        BeanHelper bHelper = new BeanHelper();
        bHelper.SchritteKopieren(template, process);
        bHelper.ScanvorlagenKopieren(template, process);
        bHelper.WerkstueckeKopieren(template, process);
        bHelper.EigenschaftenKopieren(template, process);

        return process;
    }

    public void NeuenProzessAnlegen(Process process, Process template, Fileformat ff, Prefs prefs) throws Exception {

        for (Step step : process.getSchritteList()) {

            step.setBearbeitungszeitpunkt(process.getErstellungsdatum());
            step.setEditTypeEnum(StepEditType.AUTOMATIC);
            LoginBean loginForm = (LoginBean) Helper.getManagedBeanValue("#{LoginForm}");
            if (loginForm != null) {
                step.setBearbeitungsbenutzer(loginForm.getMyBenutzer());
            }

            if (step.getBearbeitungsstatusEnum() == StepStatus.DONE) {
                step.setBearbeitungsbeginn(process.getErstellungsdatum());

                Date myDate = new Date();
                step.setBearbeitungszeitpunkt(myDate);
                step.setBearbeitungsende(myDate);
            }

        }

        ProcessManager.saveProcess(process);

        /*
         * -------------------------------- Imagepfad hinzufügen (evtl. vorhandene zunächst löschen) --------------------------------
         */
        try {
            MetadataType mdt = prefs.getMetadataTypeByName("pathimagefiles");
            List<? extends Metadata> alleImagepfade = ff.getDigitalDocument().getPhysicalDocStruct().getAllMetadataByType(mdt);
            if (alleImagepfade != null && alleImagepfade.size() > 0) {
                for (Metadata md : alleImagepfade) {
                    ff.getDigitalDocument().getPhysicalDocStruct().getAllMetadata().remove(md);
                }
            }
            Metadata newmd = new Metadata(mdt);
            if (SystemUtils.IS_OS_WINDOWS) {
                newmd.setValue("file:/" + process.getImagesDirectory() + process.getTitel().trim() + "_tif");
            } else {
                newmd.setValue("file://" + process.getImagesDirectory() + process.getTitel().trim() + "_tif");
            }
            ff.getDigitalDocument().getPhysicalDocStruct().addMetadata(newmd);

            /* Rdf-File schreiben */
            process.writeMetadataFile(ff);

        } catch (ugh.exceptions.DocStructHasNoTypeException | MetadataTypeNotAllowedException e) {
            log.error(e);
        }

        // Adding process to history
        HistoryAnalyserJob.updateHistoryForProzess(process);

        ProcessManager.saveProcess(process);

        process.readMetadataFile();

        List<Step> steps = StepManager.getStepsForProcess(process.getId());
        for (Step s : steps) {
            if (s.getBearbeitungsstatusEnum().equals(StepStatus.OPEN) && s.isTypAutomatisch()) {
                ScriptThreadWithoutHibernate myThread = new ScriptThreadWithoutHibernate(s);
                myThread.start();
            }
        }
    }

    private void saveProperty(Process process, String name, String value) {
        Processproperty pe = new Processproperty();
        pe.setTitel(name);
        pe.setType(PropertyType.String);
        pe.setWert(value);
        pe.setProzess(process);
        PropertyManager.saveProcessProperty(pe);
    }

    public String getProcessTitle() {
        if (currentWellcomeIdentifier != null) {
            String temp = currentWellcomeIdentifier.replaceAll("\\W", "_");
            if (StringUtils.isNotBlank(temp)) {
                return temp.toLowerCase() + "_" + currentIdentifier;
            }
        }
        return currentIdentifier;
    }
}
