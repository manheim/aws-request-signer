package com.manheim.util;

import org.apache.http.client.methods.HttpUriRequest;

/**
 * Utility for signing HTTP requests made to AWS services.
 *
 * @author Eric Haynes
 */
public interface RequestSigner {

   /**
    * Adds the following headers if not already present:
    * <ul>
    *    <li>host: the domain specified in the request</li>
    *    <li>x-amz-date: current timestamp</li>
    * </ul>
    *
    * Then signs the request by adding the 'Authorization' header. The specific signature is determined by
    * implementations of this interface.
    */
   void signRequest(HttpUriRequest request);
}
