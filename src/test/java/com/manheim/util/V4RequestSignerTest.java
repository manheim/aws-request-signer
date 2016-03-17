package com.manheim.util;

import com.amazonaws.auth.AWSCredentialsProviderChain;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.internal.StaticCredentialsProvider;
import org.apache.http.Header;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.regex.Pattern;

import static com.manheim.util.V4RequestSigner.SESSION_TOKEN_HEADER;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * Test the V4 signing process. Example values are taken from: http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
 *
 * @author Eric Haynes
 */
public class V4RequestSignerTest {
   public static final String REGION_NAME = "us-east-1";
   public static final String SERVICE_NAME = "iam";
   public static final String AWS_ACCESS_KEY_ID = "AKIDEXAMPLE";
   public static final String AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
   public static final String TEST_ENDPOINT = "https://iam.amazonaws.com/";
   public static final String TEST_CONTENT_TYPE = "application/x-www-form-urlencoded; charset=utf-8";
   public static final String TEST_ACTION = "Action=ListUsers&Version=2010-05-08";
   private Date currentDate;
   private URI uri;
   private V4RequestSigner testObject;

   @Before
   public final void before() throws URISyntaxException {
      Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
      calendar.set(2011, 8, 9, 23, 36, 00);
      currentDate = calendar.getTime();
      uri = new URI(TEST_ENDPOINT);
      AWSCredentialsProviderChain awsCredentialsProvider = new AWSCredentialsProviderChain(
            new StaticCredentialsProvider(new BasicAWSCredentials(AWS_ACCESS_KEY_ID, AWS_SECRET_KEY)));
      testObject = new V4RequestSigner(awsCredentialsProvider, REGION_NAME, SERVICE_NAME, currentDate);
   }

   @Test
   public final void canonicalQueryStringEncodesKeys() {
      String queryString = createQueryString(
            "a-test-with-'quotes'", "value"
      );
      String expected = "a-test-with-%27quotes%27=value";
      StringBuilder builder = new StringBuilder();
      testObject.addCanonicalQueryString(queryString, builder);
      assertEquals(expected, builder.toString());
   }

   @Test
   public final void canonicalQueryStringEncodesValues() {
      String queryString = createQueryString(
            "test", "value-with-'quotes'"
      );
      String expected = "test=value-with-%27quotes%27";
      StringBuilder builder = new StringBuilder();
      testObject.addCanonicalQueryString(queryString, builder);
      assertEquals(expected, builder.toString());
   }

   @Test
   public final void canonicalQueryStringSortsByKey() {
      String queryString = createQueryString(
            "zzparam", "avalue",
            "\"doublequotes\"", "anothervalue",
            "'singlequotes'", "yetanothervalue",
            "aaparam", "zlastvalue"
      );
      String expected = "%22doublequotes%22=anothervalue&%27singlequotes%27=yetanothervalue&aaparam=zlastvalue&zzparam=avalue";
      StringBuilder builder = new StringBuilder();
      testObject.addCanonicalQueryString(queryString, builder);
      assertEquals(expected, builder.toString());
   }

   @Test
   public final void canonicalQueryStringDoesNotAddLeadingAmpersand() {
      String queryString = createQueryString(
            "test", "value"
      );
      String expected = "test=value";
      StringBuilder builder = new StringBuilder("stuff in front");
      testObject.addCanonicalQueryString(queryString, builder);
      assertEquals(expected, builder.toString().replace("stuff in front", ""));
   }

   @Test
   public final void canonicalQueryStringPercentEncodes() {
      String queryString = createQueryString(
            "a key with spaces", "a value with spaces"
      );
      String expected = "a%20key%20with%20spaces=a%20value%20with%20spaces";
      StringBuilder builder = new StringBuilder();
      testObject.addCanonicalQueryString(queryString, builder);
      assertEquals(expected, builder.toString());
   }

   @Test
   public final void sortedFormattedHeadersDowncasesNames() {
      Header[] headers = createHeaders(
            "Some-Header", "header value"
      );
      Map<String, String> expected = new LinkedHashMap<>();
      expected.put("some-header", "header value");

      assertEquals(expected, testObject.sortedFormattedHeaders(headers));
   }

   @Test
   public final void sortedFormattedHeadersSortsByName() {
      Header[] headers = createHeaders(
            "z-Header", "header z value",
            "a-Header", "header a value"
      );
      Map<String, String> expected = new LinkedHashMap<>();
      expected.put("a-header", "header a value");
      expected.put("z-header", "header z value");

      assertEquals(expected, testObject.sortedFormattedHeaders(headers));
   }

   @Test
   public final void canonicalHeadersFormatsHeaders() {
      SortedMap<String, String> headers = testObject.sortedFormattedHeaders(createHeaders(
            "z-Header", "header z value",
            "a-Header", "header a value"
      ));
      String expected = "a-header:header a value\nz-header:header z value\n";
      StringBuilder builder = testObject.addCanonicalHeaders(headers, new StringBuilder());
      assertEquals(expected, builder.toString());
   }

   @Test
   public final void signedHeadersFormatsHeaderNames() {
      SortedMap<String, String> headers = testObject.sortedFormattedHeaders(createHeaders(
            "z-Header", "header z value",
            "a-Header", "header a value"
      ));
      String expected = "a-header;z-header";
      StringBuilder builder = testObject.addSignedHeaders(headers, new StringBuilder());
      assertEquals(expected, builder.toString());
   }

   @Test
   public final void addHeadersAddsDateHostAndAuthKey() {
      Header[] headers = createHeaders(
            "Content-type", TEST_CONTENT_TYPE
      );

      HttpPost request = new HttpPost(uri);
      request.setHeaders(headers);
      StringBuilder builder = testObject.addCanonicalHeaders(request, new StringBuilder());

      String expected = "content-type:application/x-www-form-urlencoded; charset=utf-8\n" +
            "host:iam.amazonaws.com\n" +
            "x-amz-date:" + testObject.timestamp() + "\n" +
            "\n" +
            "content-type;host;x-amz-date";
      assertEquals(expected, builder.toString());
   }

   @Test
   public final void dateStampIsIso8601Formatted() {
      String datestamp = testObject.datestamp();
      Pattern expectedFormat = Pattern.compile("\\d{8}");
      assertTrue(expectedFormat.matcher(datestamp).matches());
   }

   @Test
   public final void timestampIsIso8601Formatted() {
      String timestamp = testObject.timestamp();
      Pattern expectedFormat = Pattern.compile("\\d{8}T\\d{6}Z");
      assertTrue(expectedFormat.matcher(timestamp).matches());
   }

   @Test
   public final void toHexStringFormatsByteArray() {
      byte[] bytes = { 31, 83, -6, -112, -49, -85, 81, -73, 60, 34, -85, 113, 107, -108, 37, 31, -4, 16, -20, -78 };
      String expected = "1f53fa90cfab51b73c22ab716b94251ffc10ecb2";

      assertEquals(expected, testObject.toHexString(bytes));
   }

   @Test
   public final void hashPayloadEncodesPayload() throws IOException {
      String payload = TEST_ACTION;
      String expected = "b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2";

      StringBuilder builder = testObject.addHashedPayload(new ByteArrayInputStream(payload.getBytes()),
            new StringBuilder());
      assertEquals(expected, builder.toString());
   }

   @Test
   public final void hashPayloadResetsPayloadInputStream() throws IOException {
      String payload = "this is a test";
      ByteArrayInputStream spy = spy(new ByteArrayInputStream(payload.getBytes()));
      testObject.addHashedPayload(spy, new StringBuilder());
      verify(spy).reset();
   }

   @Test
   public final void encodesRequest() {
      String expected = "POST\n" +
            "/\n" +
            "\n" +
            "content-type:application/x-www-form-urlencoded; charset=utf-8\n" +
            "host:iam.amazonaws.com\n" +
            "x-amz-date:" + testObject.timestamp() + "\n" +
            "\n" +
            "content-type;host;x-amz-date\n" +
            "b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2";

      HttpPost request = createTestRequest();

      assertEquals(expected, testObject.createCanonicalRequest(request));
   }

   @Test
   public final void calculatesSigningKey() {
      int[] expected = {152, 241, 216, 137, 254, 196, 244, 66, 26, 220, 82, 43, 171, 12, 225, 248, 46, 105, 41, 194,
            98, 237, 21, 229, 169, 76, 144, 239, 209, 227, 176, 231};
      byte[] signatureKey = testObject.getSignatureKey();
      assertEquals(expected.length, signatureKey.length);
      for (int i = 0; i < expected.length; i++) {
         assertEquals(expected[i], 0xff & signatureKey[i]);
      }
   }

   @Test
   public final void createsStringToSign() {
      String expected = "AWS4-HMAC-SHA256\n" +
            testObject.timestamp() + "\n" +
            "20110909/us-east-1/iam/aws4_request\n" +
            "3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2";

      HttpPost request = createTestRequest();

      String canonicalRequest = testObject.createCanonicalRequest(request);
      assertEquals(expected, testObject.createStringToSign(canonicalRequest));
   }

   @Test
   public final void createsSignature() {
      HttpPost request = createTestRequest();

      String expected = "ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c";

      String canonicalRequest = testObject.createCanonicalRequest(request);
      String stringToSign = testObject.createStringToSign(canonicalRequest);

      assertEquals(expected, testObject.createSignature(stringToSign));
   }

   @Test
   public final void addsAuthorizationHeader() {
      HttpPost request = createTestRequest();
      String expected = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c";

      testObject.signRequest(request);

      Header[] authorizations = request.getHeaders("Authorization");
      assertEquals(1, authorizations.length);
      assertEquals(expected, authorizations[0].getValue());
   }

   @Test
   public final void addsSessionTokenHeaderWhenSessionCredentialsAreProvided() {
      String sessionToken = "sessionToken";
      StaticCredentialsProvider credentialsProvider =
            new StaticCredentialsProvider(new BasicSessionCredentials("accessKey", "secretKey", sessionToken));
      testObject = new V4RequestSigner(credentialsProvider, REGION_NAME, SERVICE_NAME, currentDate);
      HttpPost request = createTestRequest();
      testObject.signRequest(request);
      Header[] tokenHeaders = request.getHeaders(SESSION_TOKEN_HEADER);
      assertEquals(1, tokenHeaders.length);
      assertEquals(SESSION_TOKEN_HEADER, tokenHeaders[0].getName());
      assertEquals(sessionToken, tokenHeaders[0].getValue());
   }

   @Test
   public final void emptyRequestPathIsSlash() throws UnsupportedEncodingException {
      HttpPost request = new HttpPost("https://iam.amazonaws.com");
      request.addHeader("Content-type", TEST_CONTENT_TYPE);
      request.setEntity(new StringEntity(TEST_ACTION));

      String canonicalRequest = testObject.createCanonicalRequest(request);
      assertEquals("/", canonicalRequest.split("\n")[1]);
   }

   private HttpPost createTestRequest() {
      try {
         HttpPost request = new HttpPost(TEST_ENDPOINT);
         request.addHeader("Content-type", TEST_CONTENT_TYPE);
         request.setEntity(new StringEntity(TEST_ACTION));
         return request;
      } catch (UnsupportedEncodingException e) {
         throw new RuntimeException(e);
      }
   }

   private static String createQueryString(String... keyValuePairs) {
      StringBuilder result = new StringBuilder();
      for (int i = 0; i < keyValuePairs.length; i += 2) {
         if (result.length() > 0) {
            result.append('&');
         }
         result.append(keyValuePairs[i]).append('=').append(keyValuePairs[i + 1]);
      }
      return result.toString();
   }

   private static Header[] createHeaders(String... headers) {
      Header[] result = new Header[headers.length / 2];
      for (int i = 0; i < result.length; i++) {
         result[i] = new BasicHeader(headers[2 * i], headers[2 * i + 1]);
      }
      return result;
   }
}