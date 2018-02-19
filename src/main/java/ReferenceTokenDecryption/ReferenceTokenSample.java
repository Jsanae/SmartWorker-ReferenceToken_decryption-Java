package ReferenceTokenDecryption;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Base64;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import net.minidev.json.JSONObject;

public class ReferenceTokenSample {


  /**
   *
   * @param idpUrl URL to Smart Ansatt IDP endpoint
   * @param referenceToken token received in header when clients connect to your endpoint
   * @return JWT String
   * @throws MalformedURLException
   * @throws IOException
   * @throws ParseException
   */
  private static String getUserInfo(String idpUrl, String referenceToken) throws MalformedURLException, IOException, ParseException {

    URL issuerURI = new URL(idpUrl);
    HttpURLConnection conn = (HttpURLConnection) issuerURI.openConnection();
    conn.setRequestMethod("GET");
    conn.setRequestProperty("Authorization", referenceToken);

    BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));

    String line;
    StringBuilder result = new StringBuilder();
    while((line = rd.readLine()) != null) {
      result.append(line);
    }
    rd.close();
    System.out.println(result.toString());
    return result.toString();
  }


  /**
   *
   * @param jwtFromUserInfoEndpoint Base64 encoded string received to be decrypted
   * @param privateKey Base64 encoded String of partner certificate
   * @return JSONObject of decrypted payload
   * @throws Exception
   */
  private static JSONObject decryptJWT(String jwtFromUserInfoEndpoint, String privateKey) throws Exception {

    // Decode the partner certificate and create a RSAKey of the JWK
    String decodedKey = new String(Base64.getDecoder().decode(privateKey));
    RSAKey rsaKey = (RSAKey) JWK.parse(decodedKey);

    // Create a JWT object from the JWT string received from Smart Ansatt
    EncryptedJWT jwt = EncryptedJWT.parse(jwtFromUserInfoEndpoint);

    // Create a RSADecrypter using the RSAKey to be used when decrypting the JWT
    RSADecrypter decrypter = new RSADecrypter(rsaKey);

    // Decrypt the JWT
    jwt.decrypt(decrypter);

    // Create a signed JWT object to fetch the payload
    SignedJWT signedJWT = jwt.getPayload().toSignedJWT();


    JSONObject payload = signedJWT.getPayload().toJSONObject();

    // We could now return the payload. but if you wish to verify the signature as well, continue reading.
    // First load the Signature certificate used for validation of sender
    // This can be retrieved from the following endpoints:
    // Production: https://idp.smartansatt.telenor.no/.well-known/openid-configuration, where jwks certificates
    // are defined as "jwks_uri":"https://idp.smartansatt.pimdemo.no/idp/certs"
    // Development: https://smartworker-dev-azure-idp.smartansatt.telenor.no/.well-known/openid-configuration, where jwks certificates
    // are defined as "jwks_uri":"https://smartworker-dev-azure-idp.pimdemo.no/idp/certs"
    // Find the correct one by matching "kid" in the cert-list from the one in the JWT/JWS/JWE header received from userinfo endpoint

    // 'signatureKey' is the base64 encoded string of the signature JWK (this is the public certificate currently being used. You should check this is the correct one following the steps above)
    // The decoded signature is then used to create a new RSAKey which we will use to create a JWSVerifier
    String signatureKey = "ICAgICAgIHsNCiAgICAgICAgICAgICJrdHkiOiAiUlNBIiwNCiAgICAgICAgICAgICJraWQiOiAic2lnLXJzLTAiLA0KICAgICAgICAgICAgInVzZSI6ICJzaWciLA0KICAgICAgICAgICAgImUiOiAiQVFBQiIsDQogICAgICAgICAgICAibiI6ICJoVEViLW9wSk0wQkNCRjBpakFtM1JhVVVCVjNsRFo3ZlFORTZ4dUViQVFqNElwNDN5b1RPOVVjbUhvRGdFMzNGT0I4V01WbHFsNVpIaUExTnppVGUxZC1NRHpTMllRb3ZjOHlxUW80TUtjUkFTQUhMN2lOajdwVllwUDZZWEd4V0V3VTFPWXVRQnBaTkdvTm9VNUp1Rk5oQlRIZi1kMHZRZjNXVGZuaEdjZlg2WnlERWdYVmk5N2tfSlVWZHR2YTJaMU9Tem15aDI2MXRaZlFnMG1TSWxDM1EtTWRJLXBQTVh5cHNFaV9jVDFMWHVtbk4wVUdyQUZSeHYzeHBHY3ZOckNqRF95aXcwQ3BlWGQwZzJOR3BlUE5BY1JlVlREdEg5elEyREZxWDNKdDRLN0ZDaEh3VzN6QjdEdjVJdVlKOVJLdm9nSW1aU2R0Q2x4N3UtcDlQdlEiDQogICAgICAgIH0=";
    String decodedSig = new String(Base64.getDecoder().decode(signatureKey));
    RSAKey rsaSigKey = (RSAKey) JWK.parse(decodedSig);
    JWSVerifier jwsVerifier = new RSASSAVerifier(rsaSigKey);

    // Now we can verify the signature. Returns true if the signature was successfully verified, false if not.
    boolean isValid = signedJWT.verify(jwsVerifier);

    // Implement your own error handling
    if(!isValid) {
      throw new Exception("Signature did not successfully verify");
    }

    return payload;
  }
  public static void main(String[] args){

    // A client will connect to your endpoint with following header -> Authorization: Bearer <referencetoken>
    // This referencetoken is then used to do HTTP GET towards Smart Ansatt IDP url (without the Bearer prefix).
    // Production endpoint: https://idp.smartansatt.telenor.no/idp/me     Development endpoint: https://smartworker-dev-azure-idp.pimdemo.no/idp/me
    //
    // From the 'getUserInfo' method you will receive a Base64 encoded string of the JWT which you will need to decrypt and verify the signature
    // receivedJWTfromUserInfoEndpoint = "someRandomBase64Encodedstring.someRandomBase64Encodedstring.someRandomBase64Encodedstring.someRandomBase64Encodedstring.someRandomBase64Encodedstring"

    try {
      String receivedJWTfromUserInfoEndpoint = ReferenceTokenSample.getUserInfo("https://smartworker-dev-azure-idp.pimdemo.no/idp/me", "<referencetoken>");

      // Load the partner certificate with private key to decrypt the content
      String b64EncodedCert = "someRandomBase64EncodedString";

      // 'decryptJWT' decrypts and verifies the signature of the JWT received
      JSONObject payload = ReferenceTokenSample.decryptJWT(receivedJWTfromUserInfoEndpoint, b64EncodedCert);

      System.out.println(payload.toString());
      /* The payload will typically look something like this
         {
           "sub":"some_guid",
           "aud":"fkowfwkp3-17c5-4324-a2f4-230o23f07aa30",
           "organizationNumber":"1234567",
           "success":true,
           "iss":"https:\/\/smartworker-dev-azure-idp.pimdemo.no",
           "phone_number_verified":true,
           "phone_number":"90807060",
           "telenorSsoToken":"12345678",
           "organizationNumbers":[
              "1234567"
           ],
           "exp":1234567891,
           "iat":1234567891
        }
      */
    } catch (MalformedURLException e1) {
      // TODO Auto-generated catch block
      e1.printStackTrace();
    } catch (IOException e1) {
      // TODO Auto-generated catch block
      e1.printStackTrace();
    } catch (java.text.ParseException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (JOSEException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (ParseException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }

}
