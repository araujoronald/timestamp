package timestamp;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class TimestampClient {

	private String urlAuthServer;
	private String clientID;
	private String clientSecret;
	private String urlTimestampAPI;

	public TimestampClient(String urlAuthServer, String clientID, String clientSecret, String urlTimestampAPI) {
		this.urlAuthServer = urlAuthServer;
		this.clientID = clientID;
		this.clientSecret = clientSecret;
		this.urlTimestampAPI = urlTimestampAPI;
	}

	private String getAuthToken() throws IOException, InterruptedException {
		HttpClient httpClient = HttpClient.newHttpClient();

		String authCredential = clientID + ":" + clientSecret;
		String authString = "Basic " + Base64.getEncoder().encodeToString(authCredential.getBytes());
		
		HttpRequest httpRequest = HttpRequest.newBuilder().uri(URI.create(urlAuthServer))
				.header("Authorization", authString).header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials")).build();

		HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
		if (response.statusCode() != 200) {
			throw new RuntimeException("authentication service return code: " + response.statusCode());
		}

		String jsonResponse = response.body();
		JsonObject jsonObject = JsonParser.parseString(jsonResponse).getAsJsonObject();
		return "Bearer " + jsonObject.get("access_token").getAsString();
	}
	
	public TimeStampToken getTimestampToken(TimeStampRequest timeStampRequest)
			throws IOException, InterruptedException, NoSuchAlgorithmException, TSPException {
		
		HttpRequest httpRequest = HttpRequest.newBuilder()
				.uri(URI.create(urlTimestampAPI + "stamps-asn1"))
				.header("Authorization", getAuthToken())
				.header("Content-Type", "application/timestamp-query")
				.POST(HttpRequest.BodyPublishers.ofByteArray(timeStampRequest.getEncoded()))
				.build();

		HttpClient httpClient = HttpClient.newHttpClient();
		HttpResponse<byte[]> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray());
		if (response.statusCode() != 200) {
			throw new RuntimeException("service return code: " + response.statusCode());
		}

		TimeStampResponse timeStampResponse = new TimeStampResponse(response.body());
		return timeStampResponse.getTimeStampToken();
	}

	public TimeStampToken getTimestampToken(MessageDigest md)
			throws IOException, InterruptedException, NoSuchAlgorithmException, TSPException {

		byte[] hash = md.digest();
		String hashBase64 = Base64.getEncoder().encodeToString(hash);	
		
		JsonObject jsonObject = new JsonObject();
		jsonObject.addProperty("hash", hashBase64);

		HttpClient httpClient = HttpClient.newHttpClient();

		HttpRequest httpRequest = HttpRequest.newBuilder()
				.uri(URI.create(urlTimestampAPI + "stamps"))
				.header("Authorization", getAuthToken())
				.header("Content-Type", "application/json")
				.POST(HttpRequest.BodyPublishers.ofString(jsonObject.toString()))
				.build();

		HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
		if (response.statusCode() != 200) {
			throw new RuntimeException("authentication service return code: " + response.statusCode());
		}

		String jsonResponse = response.body();
		JsonObject jsonObjectResponse = JsonParser.parseString(jsonResponse).getAsJsonObject();
		String stamp = jsonObjectResponse.get("stamp").getAsString();
		
		TimeStampResponse timeStampResponse = new TimeStampResponse(Base64.getDecoder().decode(stamp));
		return timeStampResponse.getTimeStampToken();
	}
	
	
}
