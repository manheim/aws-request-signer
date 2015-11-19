package com.manheim.util;

import com.amazonaws.auth.AWSCredentialsProviderChain;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Signs requests using the (at this time current) V4 request signing scheme.
 *
 * @see http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
 *
 * @author Eric Haynes
 */
class V4RequestSigner implements RequestSigner {
   public static final String ENCODING = "UTF8";
   public static final String ISO_8601_TIME_FORMAT = "yyyyMMdd'T'HHmmss'Z'";
   public static final String ISO_8601_DATE_FORMAT = "yyyyMMdd";
   public static final String PAYLOAD_HASHING_ALGORITHM = "SHA-256";
   public static final String SIGN_STRING_ALGORITHM_NAME = "AWS4-HMAC-SHA256";
   public static final String SIGNATURE_HASHING_ALGORITHM = "HmacSHA256";
   public static final String DATE_HEADER_NAME = "x-amz-date";
   public static final String HOST_HEADER_NAME = "host";
   public static final String AUTH_HEADER_NAME = "Authorization";
   public static final String AUTH_HEADER_FORMAT =
         SIGN_STRING_ALGORITHM_NAME + " Credential=%s/%s, SignedHeaders=%s, Signature=%s";

   private final String regionName;
   private final String serviceName;
   private final AWSCredentialsProviderChain awsCredentialsProvider;
   private final Date currentTime;

   public V4RequestSigner(AWSCredentialsProviderChain awsCredentialsProvider, String regionName, String serviceName) {
      this(awsCredentialsProvider, regionName, serviceName, null);
   }

   public V4RequestSigner(String regionName, String serviceName) {
      this(new DefaultAWSCredentialsProviderChain(), regionName, serviceName, null);
   }

   /**
    * Test constructor with overriden date
    */
   V4RequestSigner(AWSCredentialsProviderChain awsCredentialsProvider, String regionName, String serviceName, Date currentTime) {
      this.regionName = regionName;
      this.serviceName = serviceName;
      this.awsCredentialsProvider = awsCredentialsProvider;
      this.currentTime = currentTime;
   }

   @Override
   public void signRequest(HttpUriRequest request) {
      String canonicalRequest = createCanonicalRequest(request);
      String[] requestParts = canonicalRequest.split("\n");
      String signedHeaders = requestParts[requestParts.length - 2];
      String stringToSign = createStringToSign(canonicalRequest);
      String authScope = stringToSign.split("\n")[2];
      String signature = createSignature(stringToSign);

      String authHeader = String.format(AUTH_HEADER_FORMAT, awsCredentialsProvider.getCredentials().getAWSAccessKeyId(),
            authScope, signedHeaders, signature);

      request.addHeader(AUTH_HEADER_NAME, authHeader);
   }

   String createSignature(String stringToSign) {
      return toHexString(hmacSHA256(stringToSign, getSignatureKey()));
   }

   byte[] getSignatureKey() {
      byte[] secret = getBytes("AWS4" + awsCredentialsProvider.getCredentials().getAWSSecretKey());
      byte[] date = hmacSHA256(datestamp(), secret);
      byte[] retion = hmacSHA256(regionName, date);
      byte[] service = hmacSHA256(serviceName, retion);
      return hmacSHA256("aws4_request", service);
   }

   String createStringToSign(String canonicalRequest) {
      return SIGN_STRING_ALGORITHM_NAME + '\n' +
            timestamp() + '\n' +
            datestamp() + '/' + regionName + '/' + serviceName + "/aws4_request\n" +
            toHexString(sha256(new ByteArrayInputStream(getBytes(canonicalRequest))));
   }

   String createCanonicalRequest(HttpUriRequest request) {
      StringBuilder result = new StringBuilder();
      result.append(request.getMethod()).append('\n').append(request.getURI().getPath()).append('\n');
      String queryString = request.getURI().getQuery();
      queryString = queryString != null ? queryString : "";
      addCanonicalQueryString(queryString, result).append('\n');
      addCanonicalHeaders(request, result).append('\n');

      HttpEntity entity = null;
      try {
         if (request instanceof HttpEntityEnclosingRequestBase) {
            entity = ((HttpEntityEnclosingRequestBase) request).getEntity();
         } else {
            entity = new StringEntity("");
         }
         InputStream content = entity.getContent();
         addHashedPayload(content, result);
      } catch (IOException e) {
         throw new RuntimeException("Could not create hash for entity " + entity, e);
      }
      return result.toString();
   }

   StringBuilder addCanonicalQueryString(String queryString, StringBuilder builder) {
      SortedMap<String, String> encodedParams = new TreeMap<>();
      for (String queryParam : queryString.split("&")) {
         if (!queryParam.isEmpty()) {
            String[] parts = queryParam.split("=", 2);
            encodedParams.put(encodeQueryStringValue(parts[0]), encodeQueryStringValue(parts[1]));
         }
      }
      for (Map.Entry<String, String> entry : encodedParams.entrySet()) {
         if (builder.length() > 0) {
            builder.append('&');
         }
         builder.append(entry.getKey()).append('=').append(entry.getValue());
      }
      return builder;
   }

   StringBuilder addCanonicalHeaders(HttpUriRequest request, StringBuilder builder) {
      SortedMap<String, String> sortedHeaders = sortedFormattedHeaders(request.getAllHeaders());
      if (!sortedHeaders.containsKey(DATE_HEADER_NAME)) {
         String timestamp = timestamp();
         sortedHeaders.put(DATE_HEADER_NAME, timestamp);
         request.addHeader(DATE_HEADER_NAME, timestamp);
      }
      if (!sortedHeaders.containsKey(HOST_HEADER_NAME)) {
         sortedHeaders.put(HOST_HEADER_NAME, request.getURI().getHost());
         request.addHeader(HOST_HEADER_NAME, request.getURI().getHost());
      }

      addCanonicalHeaders(sortedHeaders, builder).append('\n');
      return addSignedHeaders(sortedHeaders, builder);
   }

   SortedMap<String, String> sortedFormattedHeaders(Header[] headers) {
      SortedMap<String, String> sortedHeaders = new TreeMap<>();
      for (Header header : headers) {
         sortedHeaders.put(header.getName().toLowerCase(), header.getValue().trim());
      }
      return sortedHeaders;
   }

   StringBuilder addCanonicalHeaders(SortedMap<String, String> sortedFormattedHeaders, StringBuilder builder) {
      for (Map.Entry<String, String> entry : sortedFormattedHeaders.entrySet()) {
         builder.append(entry.getKey()).append(':').append(entry.getValue()).append('\n');
      }
      return builder;
   }

   StringBuilder addSignedHeaders(SortedMap<String, String> sortedFormattedHeaders, StringBuilder builder) {
      int startingLength = builder.length();
      for (String headerName : sortedFormattedHeaders.keySet()) {
         if (builder.length() > startingLength) {
            builder.append(';');
         }
         builder.append(headerName);
      }
      return builder;
   }

   StringBuilder addHashedPayload(InputStream payload, StringBuilder builder) throws IOException {
      return builder.append(toHexString(sha256(payload)));
   }

   String datestamp() {
      Date date = currentTime != null ? currentTime : Calendar.getInstance().getTime();
      DateFormat dateFormat = new SimpleDateFormat(ISO_8601_DATE_FORMAT);
      dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
      return dateFormat.format(date);
   }

   String timestamp() {
      Date date = currentTime != null ? currentTime : Calendar.getInstance().getTime();
      DateFormat dateFormat = new SimpleDateFormat(ISO_8601_TIME_FORMAT);
      dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
      return dateFormat.format(date);
   }

   String toHexString(byte[] data) {
      char[] hexChars = "0123456789abcdef".toCharArray();
      char[] result = new char[data.length * 2];
      for (int i = 0; i < data.length; i++) {
         int v = data[i] & 0xFF;
         result[i * 2] = hexChars[v >>> 4];
         result[i * 2 + 1] = hexChars[v & 0x0F];
      }
      return new String(result);
   }

   byte[] sha256(InputStream inputStream) {
      try {
         try {
            MessageDigest messageDigest = MessageDigest.getInstance(PAYLOAD_HASHING_ALGORITHM);
            BufferedInputStream bufferedStream = new BufferedInputStream(inputStream);
            byte[] buffer = new byte[16384];
            int bytesRead;
            while ((bytesRead = bufferedStream.read(buffer, 0, buffer.length)) != -1) {
               messageDigest.update(buffer, 0, bytesRead);
            }
            return messageDigest.digest();
         } finally {
            if (inputStream.markSupported()) {
               inputStream.reset();
            }
         }
      } catch (NoSuchAlgorithmException | IOException e) {
         throw new RuntimeException(e);
      }
   }

   byte[] getBytes(String key) {
      try {
         return (key).getBytes(ENCODING);
      } catch (UnsupportedEncodingException e) {
         // Will never happen with "UTF8" hardcoded.
         throw new RuntimeException(e);
      }
   }

   /**
    * RFC 3986 URI encoding, with substitution of the empty string for null values
    */
   String encodeQueryStringValue(String s) {
      try {
         return URLEncoder.encode(s, ENCODING)
               .replace("+", "%20")
               .replace("*", "%2A")
               .replace("%7E", "~");
      } catch (UnsupportedEncodingException e) {
         // Will never happen with "UTF8" hardcoded.
         return null;
      }
   }

   byte[] hmacSHA256(String data, byte[] key) {
      try {
         Mac mac = Mac.getInstance(SIGNATURE_HASHING_ALGORITHM);
         mac.init(new SecretKeySpec(key, SIGNATURE_HASHING_ALGORITHM));
         return mac.doFinal(getBytes(data));
      } catch (NoSuchAlgorithmException | InvalidKeyException e) {
         throw new RuntimeException(e);
      }
   }
}
