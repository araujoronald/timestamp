package timestamp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;



public class PDFTimestampSignature implements SignatureInterface {
	
	private static final DigestAlgorithmIdentifierFinder ALGORITHM_OID_FINDER =
            new DefaultDigestAlgorithmIdentifierFinder();
	
	private TimestampClient timestampClient;
	private String hashAlgorithm;
	private String apiType;
	
	public PDFTimestampSignature(String UrlAuthServer, String clientId, String clientSecret, String urlTimeStampApi, String hashAlgorithm) {
		this.hashAlgorithm = hashAlgorithm;
		this.timestampClient = new TimestampClient(UrlAuthServer, clientId, clientSecret, urlTimeStampApi);
	}
	

	public void execute(String fileToSign, String apiType) throws Exception {
		
		byte[] pdfData = Files.readAllBytes(Paths.get(fileToSign));
		this.apiType = apiType;
		
		PDDocument pdDocument = Loader.loadPDF(pdfData);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		int accessPermissions = SigUtils.getMDPPermission(pdDocument);
        if (accessPermissions == 1){
            throw new IllegalStateException(
                    "No changes to the document are permitted due to DocMDP transform parameters dictionary");
        }   
        
		PDSignature signature = new PDSignature();
		SigUtils.setMDPPermission(pdDocument, signature, 2);
		signature.setType(COSName.DOC_TIME_STAMP);
		signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
		signature.setSubFilter(COSName.getPDFName("ETSI.RFC3161"));
	
		pdDocument.addSignature(signature, this);
		pdDocument.saveIncremental(baos);
		
		byte[] result = baos.toByteArray();
		String fileToSave = fileToSign.substring(0, fileToSign.length()-4);
		Files.write(Path.of(fileToSave + "_" + new Date().getTime() + ".pdf"), result);
        
	}
	
	private TimeStampRequest buildTimeStampRequest(MessageDigest digest) throws IOException {
		int nonce = new SecureRandom().nextInt(Integer.MAX_VALUE);

        TimeStampRequestGenerator tsaGenerator = new TimeStampRequestGenerator();
        tsaGenerator.setCertReq(true);
        ASN1ObjectIdentifier oid = ALGORITHM_OID_FINDER.find(digest.getAlgorithm()).getAlgorithm();
        TimeStampRequest request = tsaGenerator.generate(oid, digest.digest(), BigInteger.valueOf(nonce));

        return request;
	}
	
	private MessageDigest getMessageDigest(InputStream content) throws NoSuchAlgorithmException, IOException {
		MessageDigest digest = MessageDigest.getInstance(this.hashAlgorithm);
		DigestInputStream dis = new DigestInputStream(content, digest);
		while (dis.read() != -1) {
		}
		
		return digest;
	}

	@Override
	public byte[] sign(InputStream content) throws IOException {

		try {
			MessageDigest md = this.getMessageDigest(content);
			TimeStampToken timeStampToken;
			
			if(apiType.equalsIgnoreCase("JSON")) {
				timeStampToken = timestampClient.getTimestampToken(md);
				
			} else if(apiType.equalsIgnoreCase("ASN1")) {
				TimeStampRequest timeStampRequest = this.buildTimeStampRequest(md);
				timeStampToken = timestampClient.getTimestampToken(timeStampRequest);
				
			} else {
				throw new RuntimeException("invalid api type");
			}
			
			return timeStampToken.getEncoded();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new byte[] {};
	}
	
	public static void main(String[] args) throws Exception {
		String UrlAuthServer = "https://gateway.apiserpro.serpro.gov.br/token";
		String clientId = "[[CLIENTE_ID]]";
		String clientSecret = "[[CLIENT SECRET]]";
		String urlTimeStampApi = "https://gateway.apiserpro.serpro.gov.br/apitimestamp/v1/";
		String fileToSign = "teste.pdf";
		String apiType = "JSON"; // or ASN1
		String hashAlgorithm = "SHA-512"; // or SHA-512
		
		PDFTimestampSignature timestampWithSignature = new PDFTimestampSignature(UrlAuthServer, clientId, clientSecret, urlTimeStampApi, hashAlgorithm);
		timestampWithSignature.execute(fileToSign, apiType);
	}
}
