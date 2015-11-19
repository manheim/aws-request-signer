# aws-request-signer
Utility for manually signing requests when using AWS APIs.

The `RequestSigner` interface, has a single public method:

    void signRequest(HttpUriRequest request);

This adds the required authentication information as a header called `Authorization` (Note that, per the AWS docs,
"Although the header is named Authorization, the signing information is actually used for authentication—establishing
who the request came from). In general, this is not required when using the AWS SDK, as specific client types will
handle the request signing automatically. This exists for calling services for which there is no SDK client. 

Source is located here: https://github.com/manheim/aws-request-signer
