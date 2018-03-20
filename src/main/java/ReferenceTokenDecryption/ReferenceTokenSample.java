package ReferenceTokenDecryption;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.util.Base64;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderConfigurationRequest;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


public class ReferenceTokenSample {

  /**
   *
   * @param idpUrl URL to Smart Ansatt IDP endpoint
   * @param referenceToken token received in header when clients connect to your endpoint
   * @param b64EncodedCert Base64 encoded JWK
   * @param secret Client secret
   * @return JWT String
   * @throws MalformedURLException
   * @throws IOException
   * @throws ParseException
   * @throws java.text.ParseException
   * @throws JOSEException
   * @throws BadJOSEException
   */
  public static String getUserInfo(String idpUrl, String referenceToken, String b64EncodedCert, String secretKey) throws MalformedURLException, IOException, ParseException, java.text.ParseException, BadJOSEException, JOSEException {

    Issuer iss = new Issuer(idpUrl);

    // Will resolve the OpenID provider metadata automatically
    OIDCProviderConfigurationRequest request = new OIDCProviderConfigurationRequest(iss);

    // Make HTTP request
    HTTPRequest httpRequest = request.toHTTPRequest();
    HTTPResponse httpResponse = httpRequest.send();

    // Parse OpenID provider metadata
    OIDCProviderMetadata opMetadata = OIDCProviderMetadata.parse(httpResponse.getContentAsJSONObject());


    // Exchange referencetoken for a JWT
    HttpURLConnection conn = (HttpURLConnection) opMetadata.getUserInfoEndpointURI().toURL().openConnection();
    conn.setRequestMethod("GET");
    conn.setRequestProperty("Authorization", referenceToken);

    BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));

    String line;
    StringBuilder result = new StringBuilder();
    while((line = rd.readLine()) != null) {
      result.append(line);
    }
    rd.close();
    String encryptedJWT = result.toString();

    // Set up a JWT processor to parse the tokens and then check their signature
    // and validity time window (bounded by the "iat", "nbf" and "exp" claims)
    ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor();

    // The public RSA keys to validate the signatures can be sourced from the
    // OAuth 2.0 server's JWK set, published at a well-known URL. The RemoteJWKSet
    // object caches the retrieved keys to speed up subsequent look-ups and can
    // also gracefully handle key-rollover
    //JWKSource keySource = new RemoteJWKSet(opMetadata.getJWKSetURI().toURL());
    //In this example we will be using the shared secret key and no remote fetching of keys is necessary
    ImmutableSecret secret = new ImmutableSecret(secretKey.getBytes());

    // The expected JWS algorithm of the access tokens (agreed out-of-band)
    //JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
    JWSAlgorithm expectedJWSAlg = JWSAlgorithm.HS256;

    // Configure the JWT processor with a key selector to feed matching public
    // RSA keys sourced from the JWK set URL, or as in this example with the shared secret.
    //JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, keySource);
    JWSKeySelector jwsKeySelector = new JWSVerificationKeySelector(expectedJWSAlg, secret);
    jwtProcessor.setJWSKeySelector(jwsKeySelector);

    // The expected JWE algorithm and method
    JWEAlgorithm expectedJWEAlg = JWEAlgorithm.RSA1_5;
    EncryptionMethod expectedJWEEnc = EncryptionMethod.A128CBC_HS256;

    // The JWE key source
    String decodedKey = new String(Base64.getDecoder().decode(b64EncodedCert));
    JWK secretJWKKey = JWK.parse(decodedKey);

    JWKSet set = new JWKSet(secretJWKKey);
    JWKSource jweKeySource = new ImmutableJWKSet(set);

    // Configure a key selector to handle the decryption phase
    JWEKeySelector jweKeySelector = new JWEDecryptionKeySelector(expectedJWEAlg, expectedJWEEnc, jweKeySource);
    jwtProcessor.setJWEKeySelector(jweKeySelector);

    // Process the token
    SecurityContext ctx = null; // optional context parameter, not required here
    JWTClaimsSet claimsSet = jwtProcessor.process(encryptedJWT, ctx);

    // Print out the token claims set
    return claimsSet.toString();
  }


  public static void main(String[] args){

    // A client will connect to your endpoint with following header -> Authorization: Bearer <referencetoken>
    // This referencetoken is then used to do HTTP GET towards Smart Ansatt IDP url (without the Bearer prefix).
    // Production endpoint: https://idp.smartansatt.telenor.no    Development endpoint: https://smartworker-dev-azure-idp.pimdemo.no
    //
    // From the 'getUserInfo' method you will receive a Base64 encoded string of the JWT which you will need to decrypt and verify the signature
    // receivedJWTfromUserInfoEndpoint = "someRandomBase64Encodedstring.someRandomBase64Encodedstring.someRandomBase64Encodedstring.someRandomBase64Encodedstring.someRandomBase64Encodedstring"

    try {

      final String idpUrl = "https://idp.smartansatt.telenor.no";
      final String b64EncodedCert = "";
      final String referenceToken = "";
      final String clientSecret = "";
      String payload = ReferenceTokenSample.getUserInfo(idpUrl, referenceToken, b64EncodedCert, clientSecret);

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
