package org.goobi.api.rest;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.ConfigurationException;
import javax.ws.rs.Consumes;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.dbutils.QueryRunner;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.SystemUtils;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.goobi.api.rest.model.ArchiveCallbackRequest;
import org.goobi.api.rest.model.FileJson;
import org.goobi.api.rest.model.ResponseJson;
import org.goobi.api.rest.response.WellcomeCreationResponse;
import org.goobi.beans.LogEntry;
import org.goobi.beans.Process;
import org.goobi.beans.Processproperty;
import org.goobi.beans.Step;
import org.goobi.managedbeans.LoginBean;
import org.goobi.production.enums.LogType;
import org.goobi.production.flow.jobs.HistoryAnalyserJob;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.Namespace;
import org.jdom2.input.SAXBuilder;
import org.jdom2.transform.XSLTransformer;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;

import de.sub.goobi.config.ConfigPlugins;
import de.sub.goobi.config.ConfigurationHelper;
import de.sub.goobi.helper.BeanHelper;
import de.sub.goobi.helper.CloseStepHelper;
import de.sub.goobi.helper.Helper;
import de.sub.goobi.helper.JwtHelper;
import de.sub.goobi.helper.ScriptThreadWithoutHibernate;
import de.sub.goobi.helper.StorageProvider;
import de.sub.goobi.helper.enums.PropertyType;
import de.sub.goobi.helper.enums.StepEditType;
import de.sub.goobi.helper.enums.StepStatus;
import de.sub.goobi.helper.exceptions.DAOException;
import de.sub.goobi.helper.exceptions.SwapException;
import de.sub.goobi.persistence.managers.MetadataManager;
import de.sub.goobi.persistence.managers.MySQLHelper;
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
import ugh.exceptions.ReadException;
import ugh.exceptions.TypeNotAllowedAsChildException;
import ugh.exceptions.TypeNotAllowedForParentException;
import ugh.exceptions.WriteException;
import ugh.fileformats.mets.MetsMods;

@Path("/wellcome")
@Log4j
public class WellcomeEndpoints {

    private static final String XSLT = ConfigurationHelper.getInstance().getXsltFolder() + "MARC21slim2MODS3.xsl";
    private static final String MODS_MAPPING_FILE = ConfigurationHelper.getInstance().getXsltFolder() + "mods_map.xml";
    private static final Namespace MARC = Namespace.getNamespace("marc", "http://www.loc.gov/MARC21/slim");
    private static final String PLUGIN_NAME = "intranda_rest_wellcome";

    private Map<String, String> map = new HashMap<>();

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

    @Path("/steps/{stepid}/archivecallback/{token}")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response archiveCallback(@PathParam("stepid") int stepId, @PathParam("token") String token, ArchiveCallbackRequest acr) {
        try {
            if (!JwtHelper.verifyChangeStepToken(token, stepId)) {
                log.error("archive-callback: token not valid or claims not correct");
                return Response.status(401).entity("token not valid or claims not correct").build();
            }
        } catch (ConfigurationException e1) {
            log.error(e1);
            return Response.status(500).entity("Internal server error: Goobi misconfiguration. See logs for details.").build();
        }
        Step so = StepManager.getStepById(stepId);
        if (so == null) {
            log.error("archive-callback: step " + stepId + " not found.");
            return Response.status(404).entity("step not found").build();
        }
        saveProperty(so.getProzess(), "archive ingest id", acr.getId());
        Prefs prefs = so.getProzess().getRegelsatz().getPreferences();
        String catalogID = "";
        String manifestationID = "";
        try {

            DocStruct docstruct = so.getProzess().readMetadataFile().getDigitalDocument().getLogicalDocStruct();
            catalogID = docstruct.getAllMetadataByType(prefs.getMetadataTypeByName("CatalogIDDigital")).get(0).getValue();
            if (docstruct.getType().isAnchor()) {
                docstruct = docstruct.getAllChildren().get(0);
                manifestationID = docstruct.getAllMetadataByType(prefs.getMetadataTypeByName("CatalogIDDigital")).get(0).getValue();
            }
        } catch (PreferencesException | ReadException | WriteException | IOException | InterruptedException | SwapException | DAOException e) {
            log.error("could not find catalogID, not deleting bag", e);
        }
        String bNumber=null;
        if(manifestationID.isEmpty()) {
            bNumber=catalogID;
        }else {
            bNumber=manifestationID;
        }
        
        try {
            String verificationMessage = verifyIngest(bNumber, so.getProzess());
            if (!verificationMessage.isEmpty()) {
                String message = "Unable to verify completeness of ingest, bNumber: " + catalogID + ". " + verificationMessage;
                writeToLog(so, message, "error");
                return Response.noContent().build();
            } else {
                String message = "Verification of ingest successful.";
                writeToLog(so, message, "info");
            }
        } catch (HttpException | IOException | InterruptedException | SwapException | DAOException e) {
            log.error("Failed to verify completeness of ingest", e);
        }
        if ("succeeded".equals(acr.getStatus().get("id"))) {
            String message = "Received callback request from archive service. Status is 'succeeded'.";
            writeToLog(so, message, "info");
            log.debug("archive-callback: archiving succeeded. Closing step.");
            //            so.setBearbeitungsstatusEnum(StepStatus.DONE);
            CloseStepHelper.closeStep(so, null);
            try {
                StepManager.saveStep(so);
            } catch (DAOException e) {
                log.error(e);
                return Response.status(500).build();
            }
            String fileName = acr.getSourceLocation().getPath();
            int dotIndex = fileName.lastIndexOf('.');
            if (dotIndex > 0) {
                fileName = fileName.substring(0, dotIndex);
            }
            //check for other processes waiting to start a bagit export
            startOtherManifestations(so);

            if (fileName.equals(catalogID)) {
                log.debug("archive-service: attempting to delete bag from s3.");
                deleteFileFromS3(acr.getSourceLocation().getBucket(), acr.getSourceLocation().getPath());
            }
            return Response.noContent().build();
        } else if ("failed".equals(acr.getStatus().get("id"))) {
            String message = "Received callback request from archive service. Status is 'failed'.";
            writeToLog(so, message, "error");
            log.debug("archive service notified status 'failed'. Setting step to error.");
            so.setBearbeitungsstatusEnum(StepStatus.ERROR);
            try {
                StepManager.saveStep(so);
            } catch (DAOException e) {
                log.error(e);
                return Response.status(500).build();
            }
            return Response.noContent().build();
        } else {
            String message = "Received callback request from archive service. Status is either not set or unknown to Goobi. See log for details.";
            writeToLog(so, message, "warn");
            log.debug("archive service notified no or unknown status. Deserialized body was:\n" + acr);
        }
        return Response.noContent().build();
    }

    /**
     * Writes message to the Processlog for step so, takes logtype as string
     * 
     * @param so step object
     * @param message
     * @param logType name of the logtype as String
     */
    private void writeToLog(Step so, String message, String logType) {
        LogEntry logEntry = new LogEntry();
        logEntry.setContent(message);
        logEntry.setCreationDate(new Date());
        logEntry.setProcessId(so.getProcessId());
        logEntry.setType(LogType.getByTitle(logType));
        logEntry.setUserName("webapi");
        ProcessManager.saveLogEntry(logEntry);
    }

    /**
     * Checks whether the Bag has been ingested successfully, by getting the manifest from the storage service and comparing the number of files with
     * the local process.
     * 
     * @param bNumber bnumber of the process
     * @param process Process object
     * @return
     * @throws HttpException
     * @throws IOException
     * @throws InterruptedException
     * @throws SwapException
     * @throws DAOException
     */
    private String verifyIngest(String bNumber, Process process)
            throws HttpException, IOException, InterruptedException, SwapException, DAOException {
        int lastIndex = bNumber.lastIndexOf('_');
        String manifestation = null;
        if (lastIndex < 0) {
            lastIndex = bNumber.length();
        } else {
            manifestation = bNumber.substring(lastIndex + 1);
        }
        String bNumberBase = bNumber.substring(0, lastIndex);
        XMLConfiguration xmlConfig = ConfigPlugins.getPluginConfig(PLUGIN_NAME);
        //            xmlConfig = new XMLConfiguration("/opt/digiverso/goobi/config/plugin_auth_config.xml");
        String clientId = xmlConfig.getString("clientID");
        String clientSecret = xmlConfig.getString("clientSecret");
        String authEndpoint = xmlConfig.getString("authEndpoint", "https://auth.wellcomecollection.org/oauth2/token");
        String digitizedEndpoint = xmlConfig.getString("digitizedEndpoint", "https://api.wellcomecollection.org/storage/v1/bags/digitised/");
        digitizedEndpoint += bNumberBase;
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        HttpResponse resp;
        String token;
        try {
            resp = requestToken(clientId, clientSecret, authEndpoint);
            if (resp.getStatusLine().getStatusCode() < 300) {
                String jsonResp = parseResponse(resp);
                JsonElement response = gson.fromJson(jsonResp, JsonElement.class);
                token = response.getAsJsonObject().get("access_token").getAsString();
            } else {
                log.error("unable to obtain authentication token to check if bag already exists");
                throw new HttpException();
            }
        } catch (IOException e) {
            log.error("unable to obtain authentication token to check if bag already exists", e);
            throw new HttpException();
        }
        HttpResponse resp2;
        String digitizedResponse;
        try {
            resp2 = Request.Get(digitizedEndpoint).addHeader("Authorization", "Bearer " + token).execute().returnResponse();
            digitizedResponse = parseResponse(resp2);

        } catch (IOException e) {
            String message = "unable to query if previous instance of this bag already exists on the service";
            log.error(message, e);
            return message;
        }
        if (resp2.getStatusLine().getStatusCode() < 300) {
            ResponseJson json = gson.fromJson(digitizedResponse, ResponseJson.class);
            List<FileJson> files = json.getManifest().getFiles();
            if (manifestation != null) {
                List<FileJson> toDelete = new ArrayList<>();
                for (FileJson file : files) {
                    if (Integer.parseInt(manifestation) != getManifestationNumber(file.getPath())) {
                        toDelete.add(file);
                    }
                }
                files.removeAll(toDelete);
            }
            List<String> imageList = StorageProvider.getInstance().list(process.getImagesOrigDirectory(false));
            List<String> ocrList = StorageProvider.getInstance().list(process.getOcrAltoDirectory());
            int metsfiles = 1;
            if (manifestation != null) {
                metsfiles = 2;
            }
            if (files.size() - imageList.size() - ocrList.size() - metsfiles == 0) {
                return "";
            }
            return String.format(
                    "Did not find expected Number of files in storage manifest. Storage manifest: %s files, Imagefolder: %s, Ocr results: %s, Mets files: %s",
                    files.size(), imageList.size(), ocrList.size(), metsfiles);
        } else {
            return String.format("Could not obtain storage manifest from storage service, response code was %s, response body was: %s",
                    resp.getStatusLine().getStatusCode(), digitizedResponse);
        }
    }

    /**
     * Assumes the file names are structured such that it starts with the bNumber of the anchor which is followed by '_' and the number of the
     * manifestation
     * 
     * @param imageName
     * @return
     */
    private int getManifestationNumber(String imageName) {
        String fileName = Paths.get(imageName).getFileName().toString();
        String[] nameElements = fileName.split("_");
        if (nameElements.length > 2 || !fileName.contains(".")) {
            return Integer.parseInt(nameElements[1]);
        } else {
            String[] lastNameBit = nameElements[1].split("\\.");
            return Integer.parseInt(lastNameBit[0]);
        }
    }

    /**
     * Requests a Token from authEndpoint using grant type client credentials, providing clientId and clientSecret
     * 
     * @param clientId
     * @param clientSecret to authenticate the client id
     * @param authEndpoint url which provides authentication tokens
     * @return
     * @throws IOException
     */
    private HttpResponse requestToken(String clientId, String clientSecret, String authEndpoint) throws IOException {
        HttpResponse resp;
        StringBuilder body = new StringBuilder();
        body.append("client_id=" + clientId);
        body.append("&client_secret=" + clientSecret);
        body.append("&grant_type=client_credentials");
        resp = Request.Post(authEndpoint).bodyString(body.toString(), ContentType.APPLICATION_FORM_URLENCODED).execute().returnResponse();
        return resp;
    }

    /**
     * Takes HttpResponse object and returns its content as String
     * 
     * @param resp
     * @return
     * @throws IOException
     */
    private String parseResponse(HttpResponse resp) throws IOException {
        StringWriter w = new StringWriter();
        try (InputStream is = resp.getEntity().getContent()) {
            IOUtils.copy(is, w, Charset.forName("UTF-8"));
        }
        return w.toString();
    }

    /**
     * Searches for processes from the same multiple manifestation as the step being closed. Checks if they are waiting to start a bagit export
     * themselves, if that is the case starts one of them.
     * 
     * @param step step being closed
     */
    private void startOtherManifestations(Step step) {
        try {
            List<String> stepTitles = new ArrayList<>();
            stepTitles.add("Wait for Bagit");
            Fileformat ff = step.getProzess().readMetadataFile();
            DocStruct ds = ff.getDigitalDocument().getLogicalDocStruct();
            // check if current process is MMO
            if (ds.getType().isAnchor()) {
                String bnumber = getBnumberFromDocstruct(ds);
                if (StringUtils.isBlank(bnumber)) {
                    log.error("Cannot extract bnumber from metadata file.");
                }
                // search for other manifestations
                List<Integer> processIds = MetadataManager.getProcessesWithMetadata("CatalogIDDigital", bnumber);

                StringBuilder processSubQuery = new StringBuilder();
                // check, if they are in export or bagit
                if (processIds.size() > 1) {
                    // check all but the current process
                    for (Integer id : processIds) {
                        if (!step.getProzess().getId().equals(id)) {
                            if (processSubQuery.length() > 0) {
                                processSubQuery.append(", ");
                            }
                            processSubQuery.append(id);
                        }
                    }
                }
                if (processSubQuery.length() == 0) {
                    // no other processes found, continue
                    return;
                }
                // prepares sql expression for list of possible step names
                StringBuilder titleSubQuery = new StringBuilder();
                for (String stepname : stepTitles) {
                    if (titleSubQuery.length() == 0) {
                        titleSubQuery.append("(");
                    } else {
                        titleSubQuery.append(" or ");
                    }
                    titleSubQuery.append("titel = \"");
                    titleSubQuery.append(stepname);
                    titleSubQuery.append("\"");
                }
                titleSubQuery.append(")");
                //get Id of steps waiting to start bagit export
                StringBuilder sqlQuery = new StringBuilder();
                sqlQuery.append("SELECT DISTINCT ");
                sqlQuery.append("    SchritteID ");
                sqlQuery.append("FROM ");
                sqlQuery.append("    schritte ");
                sqlQuery.append("WHERE ");

                sqlQuery.append(titleSubQuery.toString());
                sqlQuery.append("    AND ProzesseID IN (");
                sqlQuery.append(processSubQuery.toString());
                sqlQuery.append(")");
                sqlQuery.append(" AND ");
                sqlQuery.append(" Bearbeitungsstatus =2");
                checkProcessStatus(sqlQuery.toString());
            }
        } catch (ReadException | PreferencesException | WriteException | IOException | InterruptedException | SwapException | DAOException e) {
            log.error(e);
        }
    }

    /**
     * Iterates through metadata in passed Docstruct and returns the value of CatalogIDDigital
     * 
     * @param ds
     * @return value of "CatalogIDDigital
     */
    private String getBnumberFromDocstruct(DocStruct ds) {
        List<? extends Metadata> metadata = ds.getAllMetadata();
        for (Metadata md : metadata) {
            if ("CatalogIDDigital".equals(md.getType().getName())) {
                return md.getValue();
            }
        }
        return null;
    }

    /**
     * Executes passed sql query assumes the returned list of integers are step ids and closes one of them
     * 
     * @param sql
     * @return
     */
    public boolean checkProcessStatus(String sql) {

        Connection connection = null;
        try {
            connection = MySQLHelper.getInstance().getConnection();
            List<Integer> stepIds = new QueryRunner().query(connection, sql, MySQLHelper.resultSetToIntegerListHandler);
            if (!stepIds.isEmpty()) {
                Step nextStep = StepManager.getStepById(stepIds.get(0));
                CloseStepHelper.closeStep(nextStep, null);
            }
        } catch (SQLException e) {
            log.error(e);
        } finally {
            if (connection != null) {
                try {
                    MySQLHelper.closeConnection(connection);
                } catch (SQLException e) {
                }
            }
        }
        return true;
    }

    /**
     * deletes passed file from Amazon s3 (or if configured a custom s3)
     * 
     * @param bucket
     * @param s3Key
     */
    private void deleteFileFromS3(String bucket, String s3Key) {
        AmazonS3 s3 = null;// AmazonS3ClientBuilder.defaultClient();
        ConfigurationHelper conf = ConfigurationHelper.getInstance();
        if (conf.useCustomS3()) {
            AWSCredentials credentials = new BasicAWSCredentials(conf.getS3AccessKeyID(), conf.getS3SecretAccessKey());
            ClientConfiguration clientConfiguration = new ClientConfiguration();
            clientConfiguration.setSignerOverride("AWSS3V4SignerType");

            s3 = AmazonS3ClientBuilder.standard()
                    .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(conf.getS3Endpoint(), Regions.US_EAST_1.name()))
                    .withPathStyleAccessEnabled(true)
                    .withClientConfiguration(clientConfiguration)
                    .withCredentials(new AWSStaticCredentialsProvider(credentials))
                    .build();
        } else {
            s3 = AmazonS3ClientBuilder.defaultClient();
        }
        s3.deleteObject(bucket, s3Key);
    }

    @Path("/create")
    @POST
    @Produces("text/xml")
    public Response createNewProcess(@HeaderParam("templateid") int templateId, @HeaderParam("marcfile") String marcfile,
            @HeaderParam("collection") String collectionName) {

        if (StringUtils.isBlank(marcfile)) {
            Response resp =
                    Response.status(Response.Status.BAD_REQUEST).entity(createErrorResponse("Parameter marc file is missing or empty.")).build();
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
            Response resp = Response.status(Response.Status.EXPECTATION_FAILED)
                    .entity(createErrorResponse("Process with b-number " + filename + " already exists, as MMO."))
                    .build();
            return resp;

        }

        if (ProcessManager.countProcesses("titel LIKE '%" + filename + "%'") > 0) {
            // file already exists
            Response resp = Response.status(Response.Status.CONFLICT)
                    .entity(createErrorResponse("Process with b-number " + filename + " already exists, you should remove it."))
                    .build();
            return resp;

        }
        String order = null;
        String anchorId = null;
        if (filename.matches("\\w+_\\d{4}")) {
            // multivolume
            anchorId = filename.split("_")[0];
            order = filename.split("_")[1];
            if (ProcessManager.countProcesses("titel LIKE '%" + anchorId + "'") > 0) {
                Response resp = Response.status(Response.Status.EXPECTATION_FAILED)
                        .entity(createErrorResponse("b-number " + anchorId + " already exists, you should move it to suspicious folder."))
                        .build();
                return resp;
            }
        }

        Process template = ProcessManager.getProcessById(templateId);
        if (template == null) {
            Response resp = Response.status(Response.Status.BAD_REQUEST)
                    .entity(createErrorResponse("Cannot find process template with id " + templateId))
                    .build();
            return resp;
        }

        Prefs prefs = template.getRegelsatz().getPreferences();

        SAXBuilder builder = new SAXBuilder();
        Document doc = null;
        try {
            doc = builder.build(marcfile);
        } catch (JDOMException | IOException e) {
            log.error(e);
            Response resp =
                    Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(createErrorResponse("Cannot read marc record " + marcfile)).build();
            return resp;
        }
        Fileformat ff = null;
        if (order == null) {
            ff = convertData(doc, prefs, collectionName);
        } else {
            ff = convertMMO(doc, prefs, collectionName, order, anchorId, filename);
        }
        if (ff == null) {
            Response resp = Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(createErrorResponse("Cannot convert marc record " + marcfile))
                    .build();
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
            Response resp = Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(createErrorResponse("Cannot create process with title " + getProcessTitle()))
                    .build();
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
         * -------------------------------- Imagepfad hinzufügen (evtl. vorhandene
         * zunächst löschen) --------------------------------
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
