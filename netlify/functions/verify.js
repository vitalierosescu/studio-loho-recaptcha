const fetch = require("node-fetch");

exports.handler = async function (event, context) {
  // Use environment variables for CORS origin and score threshold
  const mySiteUrl = process.env.MY_SITE_URL || "*"; // Fallback to '*' if not set
  const scoreThreshold = parseFloat(process.env.SCORE_THRESHOLD) || 0.5; // Default to 0.5 if not set

  // Define CORS headers for cross-origin requests
  const corsHeaders = {
    "Access-Control-Allow-Origin": mySiteUrl, // Use site url for better security
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Max-Age": "86400", // Cache preflight request for 86400 seconds
  };

  // Handle OPTIONS request for CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 204, // No content response for preflight
      headers: corsHeaders,
      body: "",
    };
  }

  // Restrict to POST requests only
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405, // Method not allowed
      headers: corsHeaders,
      body: "Method Not Allowed",
    };
  }

  try {
    // Parse the JSON body of the request
    const body = JSON.parse(event.body);
    const token = body.token; // Extract the ReCAPTCHA token

    // Check for the presence of the ReCAPTCHA token
    if (!token) {
      return {
        statusCode: 400, // Bad request
        headers: corsHeaders,
        body: "Token is required",
      };
    }

    const secretKey = process.env.RECAPTCHA_SECRET_KEY; // Retrieve secret key from environment variables

    // Perform ReCAPTCHA verification
    const verificationResponse = await fetch(
      "https://www.google.com/recaptcha/api/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `secret=${secretKey}&response=${token}`,
      },
    );

    // Check if ReCAPTCHA verification was successful
    if (!verificationResponse.ok) {
      throw new Error(
        `Error in ReCAPTCHA verification: ${verificationResponse.status}`,
      );
    }

    const verificationData = await verificationResponse.json();

    if (verificationData.success && verificationData.score >= scoreThreshold) {
      const formData = body.formData; // Extract form data from the request body
      const endpointUrl = process.env.ENDPOINT_URL; // Endpoint URL for forwarding the data

      // Convert formData object to URL-encoded string
      const formBody = new URLSearchParams(formData).toString();

      // Forward the form data to the specified endpoint
      const forwardResponse = await fetch(endpointUrl, {
        method: "POST",
        body: formBody,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      });

      // Check if data forwarding was successful
      if (!forwardResponse.ok) {
        throw new Error(`Error forwarding data: ${forwardResponse.status}`);
      }

      const forwardData = await forwardResponse.json();

      // Return the response from the endpoint
      return {
        statusCode: 200,
        headers: corsHeaders,
        body: JSON.stringify({
          formResponse: forwardData,
          threshold: scoreThreshold,
          details: verificationData,
        }),
      };
    } else {
      // Handle low-score submissions or verification failure
      return {
        statusCode: 400,
        headers: corsHeaders,
        body: JSON.stringify({
          error: "Low ReCAPTCHA score or verification failed",
          threshold: scoreThreshold,
          details: verificationData,
        }),
      };
    }
  } catch (error) {
    // Log and return server error
    console.error("Server Error:", error);
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({
        error: "Internal Server Error",
        message: error.message,
      }),
    };
  }
};
